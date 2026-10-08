begin;

-- A temporary Supabase Auth ban is not an entitlement revocation. Existing
-- grants remain persistent, but are hidden and cannot be reissued or replayed
-- while the canonical auth.users.banned_until is in the future.
do $preflight$
declare
  v_policy text;
begin
  if to_regprocedure(
    'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)'
  ) is null
    or to_regprocedure(
      'private.ordax_authenticated_entitlement_eligible_v1()'
    ) is not null
  then raise exception 'entitlement suspension: unexpected function baseline'; end if;

  select pg_catalog.lower(p.qual) into v_policy
    from pg_policies p
   where p.schemaname='public'
     and p.tablename='ordax_entitlement_grants'
     and p.policyname='ordax_entitlement_grants_select_subject'
     and p.cmd='SELECT';

  if v_policy is null
     or v_policy not like '%clock_timestamp%'
     or v_policy not like '%ordax_can_access_space%'
  then raise exception 'entitlement suspension: SELECT policy has drifted'; end if;
end;
$preflight$;

-- The database reads the authoritative Auth row on every entitlement
-- SELECT rather than trusting JWT claims that remain valid during suspension.
-- No arbitrary user ID can be passed to this function.
create function private.ordax_authenticated_entitlement_eligible_v1()
returns boolean
language sql
volatile
security definer
set search_path = ''
as $function$
  select exists (
    select 1
      from auth.users u
      join public.ordax_accounts a on a.user_id=u.id
     where u.id=(select auth.uid())
       and u.deleted_at is null
       and u.is_anonymous is false
       and u.confirmed_at is not null
       and (u.banned_until is null
         or u.banned_until<=pg_catalog.clock_timestamp())
  );
$function$;

revoke all on function private.ordax_authenticated_entitlement_eligible_v1()
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor,ordax_entitlement_default_executor;

-- Only authenticated queries through the existing RLS policy may use this
-- private helper. No private schema USAGE or Auth relation grant is added.
grant execute on function private.ordax_authenticated_entitlement_eligible_v1()
  to authenticated;

-- Preserve the same issuer and the same isolated NOLOGIN executor. Issuance,
-- including an idempotent success replay, is blocked throughout suspension.
create or replace function public.ordax_issue_account_default_entitlement_v2(
  p_subject_user_id uuid,
  p_entitlement_key text,
  p_policy_version integer
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_source_event_id text;
  v_event private.ordax_default_entitlement_events%rowtype;
  v_value jsonb;
  v_duration integer;
  v_now timestamptz;
  v_grant_id uuid;
begin
  if p_subject_user_id is null
     or p_entitlement_key is null
     or p_entitlement_key !~ '^[a-z][a-z0-9.-]{2,95}$'
     or p_policy_version is null
     or p_policy_version <= 0 then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','account_default_input_invalid');
  end if;

  -- The immutable one-time event identity is computed from canonical account
  -- identity and entitlement key, not supplied by the external caller.
  v_source_event_id :=
    'account_created:' || p_subject_user_id::text || ':' || p_entitlement_key;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ordax.default.event:' || v_source_event_id,0)
  );

  -- auth.users is authoritative for creation. The canonical Product account
  -- must have been bootstrapped from that same identity; deleted accounts
  -- cannot be granted new defaults.
  perform 1
    from auth.users u
    join public.ordax_accounts a on a.user_id=u.id
   where u.id=p_subject_user_id
     and u.deleted_at is null
     and u.is_anonymous is false
     and u.confirmed_at is not null
     and (u.banned_until is null or u.banned_until<=pg_catalog.clock_timestamp())
   for share of u,a;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','account_creation_not_verified');
  end if;

  select * into v_event
    from private.ordax_default_entitlement_events
   where source='product-default'
     and source_event_id=v_source_event_id;

  if found then
    if v_event.event_kind='issued'
       and v_event.subject_user_id=p_subject_user_id
       and v_event.entitlement_key=p_entitlement_key
       and v_event.policy_version=p_policy_version then
      -- An idempotent receipt is NOT proof that the entitlement remains
      -- effective. Expired, revoked or inconsistent grants must fail closed.
      v_now:=pg_catalog.clock_timestamp();
      if not exists (
        select 1
        from public.ordax_entitlement_grants g
        where g.grant_id=v_event.grant_id
          and g.user_id=p_subject_user_id
          and g.entitlement_key=p_entitlement_key
          and g.policy_version=p_policy_version
          and g.source='product-default'
          and g.source_event_id=v_source_event_id
          and g.valid_from<=v_now
          and (g.valid_until is null or g.valid_until>v_now)
          and not exists (
            select 1 from private.ordax_default_entitlement_events revoked
            where revoked.grant_id=g.grant_id
              and revoked.event_kind='revoked'
          )
      ) then
        return pg_catalog.jsonb_build_object(
          'ok',false,'changed',false,'replayed',true,
          'error','account_default_grant_inactive',
          'grant_id',v_event.grant_id);
      end if;

      return pg_catalog.jsonb_build_object(
        'ok',true,'changed',false,'replayed',true,
        'grant_id',v_event.grant_id);
    end if;
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','account_default_event_conflict');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      'ordax.default.subject:' || p_subject_user_id::text || ':' || p_entitlement_key,0)
  );

  select entitlement_value,duration_seconds
    into v_value,v_duration
    from private.ordax_default_entitlement_policies
   where entitlement_key=p_entitlement_key
     and policy_version=p_policy_version
     and state='active'
   for share;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','default_policy_not_active');
  end if;

  v_now:=pg_catalog.clock_timestamp();

  if exists(
    select 1 from public.ordax_entitlement_grants
     where user_id=p_subject_user_id
       and entitlement_key=p_entitlement_key
       and source='product-default'
       and valid_from<=v_now
       and (valid_until is null or valid_until>v_now)
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','default_entitlement_already_active');
  end if;

  insert into public.ordax_entitlement_grants(
    user_id,space_id,entitlement_key,entitlement_value,source,
    source_event_id,policy_version,valid_from,valid_until
  ) values (
    p_subject_user_id,null,p_entitlement_key,v_value,'product-default',
    v_source_event_id,p_policy_version,v_now,
    v_now+pg_catalog.make_interval(secs=>v_duration)
  ) returning grant_id into v_grant_id;

  insert into private.ordax_default_entitlement_events(
    source_event_id,event_kind,grant_id,subject_user_id,
    entitlement_key,policy_version
  ) values (
    v_source_event_id,'issued',v_grant_id,p_subject_user_id,
    p_entitlement_key,p_policy_version
  );

  return pg_catalog.jsonb_build_object(
    'ok',true,'changed',true,'replayed',false,'grant_id',v_grant_id);
end;
$function$;

alter policy ordax_entitlement_grants_select_subject
  on public.ordax_entitlement_grants
  using (
    (select private.ordax_authenticated_entitlement_eligible_v1())
    and valid_from<=pg_catalog.clock_timestamp()
    and (valid_until is null or valid_until>pg_catalog.clock_timestamp())
    and (
      user_id=(select auth.uid())
      or (space_id is not null and private.ordax_can_access_space(space_id))
    )
  );

do $postflight$
declare
  v_policy text;
  v_issuer text;
begin
  select pg_catalog.lower(p.qual) into v_policy
    from pg_policies p
   where p.schemaname='public'
     and p.tablename='ordax_entitlement_grants'
     and p.policyname='ordax_entitlement_grants_select_subject';

  select pg_catalog.lower(pg_get_functiondef(
    'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)'::regprocedure
  )) into v_issuer;

  if v_policy not like '%ordax_authenticated_entitlement_eligible_v1%'
     or v_policy not like '%clock_timestamp%'
     or v_policy not like '%auth.uid%'
     or v_policy not like '%ordax_can_access_space%'
     or v_issuer not like '%u.banned_until%'
     or v_issuer not like '%for share of u,a%'
  then raise exception 'entitlement suspension: issuer/RLS contract invalid'; end if;

  if not has_function_privilege(
        'authenticated','private.ordax_authenticated_entitlement_eligible_v1()','EXECUTE')
     or has_function_privilege(
        'anon','private.ordax_authenticated_entitlement_eligible_v1()','EXECUTE')
     or has_function_privilege(
        'service_role','private.ordax_authenticated_entitlement_eligible_v1()','EXECUTE')
     or has_schema_privilege('authenticated','private','USAGE')
     or has_table_privilege('authenticated','auth.users','SELECT')
     or has_table_privilege('authenticated','public.ordax_entitlement_grants','UPDATE')
     or has_function_privilege('authenticated',
        'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)',
        'EXECUTE')
     or not has_function_privilege('ordax_entitlement_default_executor',
        'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)',
        'EXECUTE')
  then raise exception 'entitlement suspension: unexpected permission'; end if;
end;
$postflight$;

commit;
