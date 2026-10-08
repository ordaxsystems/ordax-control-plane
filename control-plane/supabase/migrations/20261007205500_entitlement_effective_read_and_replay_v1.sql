begin;

-- Fail closed for a stale or revoked account-default receipt. An issued-event
-- record is immutable history, never an active entitlement by itself.
-- The existing Auth eligibility check and FOR SHARE serialization are kept.
do $preflight$
begin
  if to_regprocedure(
    'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)'
  ) is null
    or not exists (
      select 1 from pg_policies
      where schemaname='public'
        and tablename='ordax_entitlement_grants'
        and policyname='ordax_entitlement_grants_select_subject'
        and cmd='SELECT'
    )
  then raise exception 'entitlement effective-state: canonical contracts missing'; end if;
end;
$preflight$;

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

-- The authenticated Data API must expose only currently effective grants.
-- The private issuance/revocation journal retains historical evidence.
alter policy ordax_entitlement_grants_select_subject
  on public.ordax_entitlement_grants
  using (
    valid_from<=pg_catalog.statement_timestamp()
    and (valid_until is null or valid_until>pg_catalog.statement_timestamp())
    and (
      user_id=(select auth.uid())
      or (space_id is not null and private.ordax_can_access_space(space_id))
    )
  );

do $postflight$
declare
  v_fn text;
  v_policy text;
begin
  select pg_catalog.lower(pg_get_functiondef(
    'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)'::regprocedure
  )) into v_fn;

  if v_fn not like '%account_default_grant_inactive%'
    or v_fn not like '%for share of u,a%'
    or v_fn not like '%revoked.event_kind%'
  then raise exception 'entitlement effective-state: issuer regression'; end if;

  select pg_catalog.lower(p.qual) into v_policy
    from pg_policies p
    where p.schemaname='public'
      and p.tablename='ordax_entitlement_grants'
      and p.policyname='ordax_entitlement_grants_select_subject';

  if v_policy not like '%statement_timestamp%'
     or v_policy not like '%valid_from%'
     or v_policy not like '%valid_until%'
     or v_policy not like '%auth.uid%'
     or v_policy not like '%ordax_can_access_space%'
  then raise exception 'entitlement effective-state: read policy regression'; end if;

  if not has_function_privilege(
    'ordax_entitlement_default_executor',
    'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)',
    'EXECUTE')
    or has_function_privilege(
      'authenticated',
      'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)',
      'EXECUTE')
    or has_function_privilege(
      'service_role',
      'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)',
      'EXECUTE')
    or has_table_privilege(
      'authenticated','public.ordax_entitlement_grants','UPDATE')
  then raise exception 'entitlement effective-state: privilege regression'; end if;
end;
$postflight$;

commit;
