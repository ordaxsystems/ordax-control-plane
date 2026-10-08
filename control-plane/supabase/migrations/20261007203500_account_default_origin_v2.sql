begin;

-- Account-created is verified against the Auth and Product account SSOT.
-- Never accept an external source_event_id for this default issuer.
-- No real grants, policies or events exist in the canonical baseline.
do $preflight$
begin
  if exists (select 1 from public.ordax_entitlement_grants limit 1)
     or exists (select 1 from private.ordax_default_entitlement_events limit 1)
     or exists (select 1 from private.ordax_default_entitlement_policies limit 1) then
    raise exception 'account-default v2: requires unused default entitlement baseline';
  end if;

  if not exists (select 1 from pg_roles where rolname='ordax_entitlement_default_executor'
                  and not rolcanlogin and not rolinherit and not rolbypassrls)
    or to_regprocedure('public.ordax_issue_default_entitlement_v1(uuid,text,integer,text)') is null
    or to_regprocedure('public.ordax_revoke_default_entitlement_v1(uuid,text)') is null then
    raise exception 'account-default v2: expected v1 boundary missing';
  end if;
end;
$preflight$;

create function public.ordax_issue_account_default_entitlement_v2(
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

  select * into v_event
    from private.ordax_default_entitlement_events
   where source='product-default'
     and source_event_id=v_source_event_id;

  if found then
    if v_event.event_kind='issued'
       and v_event.subject_user_id=p_subject_user_id
       and v_event.entitlement_key=p_entitlement_key
       and v_event.policy_version=p_policy_version then
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

  -- auth.users is authoritative for creation. The canonical Product account
  -- must have been bootstrapped from that same identity; deleted accounts
  -- cannot be granted new defaults.
  perform 1
    from auth.users u
    join public.ordax_accounts a on a.user_id=u.id
   where u.id=p_subject_user_id
     and u.deleted_at is null
   for key share of u,a;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','account_creation_not_verified');
  end if;

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

revoke all on function
  public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor,ordax_entitlement_default_executor;

grant execute on function
  public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)
  to ordax_entitlement_default_executor;

-- Remove the v1 public database endpoints entirely. They accepted an
-- unverified caller-supplied source event and a generic revocation reason.
-- There are no issued grants/events to migrate. No compatibility RPC stays.
drop function public.ordax_issue_default_entitlement_v1(uuid,text,integer,text);
drop function public.ordax_revoke_default_entitlement_v1(uuid,text);

alter table private.ordax_default_entitlement_events
  drop constraint ordax_default_entitlement_events_event_kind_check;

alter table private.ordax_default_entitlement_events
  add constraint ordax_default_entitlement_events_event_kind_check
  check (event_kind='issued');

do $postflight$
declare
  v_bad_functions integer;
  v_bad_relations integer;
begin
  if to_regprocedure('public.ordax_issue_default_entitlement_v1(uuid,text,integer,text)') is not null
     or to_regprocedure('public.ordax_revoke_default_entitlement_v1(uuid,text)') is not null then
    raise exception 'account-default v2: old RPC still present';
  end if;

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
  then raise exception 'account-default v2: RPC boundary invalid'; end if;

  select count(*) into v_bad_functions
    from pg_proc f join pg_namespace n on n.oid=f.pronamespace
   where n.nspname='public'
     and has_function_privilege('ordax_entitlement_default_executor',f.oid,'EXECUTE')
     and f.oid <> 'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)'::regprocedure;
  if v_bad_functions<>0 then
    raise exception 'account-default v2: unexpected executor RPC';
  end if;

  select count(*) into v_bad_relations
    from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname in ('public','private')
     and c.relkind in ('r','p','v','m','f','S')
     and (
       (c.relkind='S' and (
         has_sequence_privilege('ordax_entitlement_default_executor',c.oid,'USAGE')
         or has_sequence_privilege('ordax_entitlement_default_executor',c.oid,'SELECT')
         or has_sequence_privilege('ordax_entitlement_default_executor',c.oid,'UPDATE')))
       or (c.relkind<>'S' and (
         has_table_privilege('ordax_entitlement_default_executor',c.oid,'SELECT')
         or has_table_privilege('ordax_entitlement_default_executor',c.oid,'INSERT')
         or has_table_privilege('ordax_entitlement_default_executor',c.oid,'UPDATE')
         or has_table_privilege('ordax_entitlement_default_executor',c.oid,'DELETE')))
     );
  if v_bad_relations<>0
     or has_schema_privilege('ordax_entitlement_default_executor','private','USAGE')
  then raise exception 'account-default v2: direct database authority survived'; end if;
end;
$postflight$;

commit;
