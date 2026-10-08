begin;

-- Fix the Auth soft-delete race and own the revocation event in Auth itself.
-- Product-default issuance must lock the Auth row with FOR SHARE rather than
-- FOR KEY SHARE: UPDATE deleted_at takes FOR NO KEY UPDATE.
do $preflight$
begin
  if to_regprocedure('public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)') is null
     or exists(select 1 from public.ordax_entitlement_grants limit 1)
     or exists(select 1 from private.ordax_default_entitlement_events limit 1)
     or exists(select 1 from private.ordax_default_entitlement_policies limit 1)
     or exists (
       select 1 from pg_trigger where tgrelid='auth.users'::regclass
         and tgname='ordax_auth_user_soft_delete_default_entitlements'
     )
  then raise exception 'Auth deletion revocation: unexpected baseline or trigger';
  end if;
end;
$preflight$;

-- The same single authoritative issuer. Only the row-lock semantics and
-- order of identity validation versus receipt replay change.
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

-- The receipt table stays an audit journal for issuance AND Auth soft-delete
-- revocations; no generic revoke RPC is restored.
alter table private.ordax_default_entitlement_events
  drop constraint ordax_default_entitlement_events_event_kind_check;
alter table private.ordax_default_entitlement_events
  add constraint ordax_default_entitlement_events_event_kind_check
  check(event_kind in ('issued','revoked'));

create function private.ordax_revoke_defaults_on_auth_soft_delete_v1()
returns trigger
language plpgsql
security definer
set search_path = ''
as $trigger$
declare
  v_now timestamptz;
begin
  if tg_op <> 'UPDATE'
    or old.deleted_at is not null
    or new.deleted_at is null
    or new.id is distinct from old.id then
    raise exception 'Auth deletion revocation: invalid trigger transition';
  end if;

  v_now:=pg_catalog.clock_timestamp();

  -- The function executes within the same Auth transaction. Its lock on the
  -- auth.users row serializes against the emitter's FOR SHARE check.
  with revoked as (
    update public.ordax_entitlement_grants g
       set valid_until=greatest(
         v_now, g.valid_from + interval '1 microsecond')
     where g.user_id=new.id
       and g.source='product-default'
       and (g.valid_until is null or g.valid_until>v_now)
    returning g.grant_id,g.entitlement_key,g.policy_version
  )
  insert into private.ordax_default_entitlement_events (
    source,source_event_id,event_kind,grant_id,
    subject_user_id,entitlement_key,policy_version
  )
  select 'product-default',
    'account_deleted:' || r.grant_id::text,
    'revoked',r.grant_id,new.id,r.entitlement_key,r.policy_version
  from revoked r;

  return new;
end;
$trigger$;

revoke all on function private.ordax_revoke_defaults_on_auth_soft_delete_v1()
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor,ordax_entitlement_default_executor;

create trigger ordax_auth_user_soft_delete_default_entitlements
after update of deleted_at on auth.users
for each row
when (old.deleted_at is null and new.deleted_at is not null)
execute function private.ordax_revoke_defaults_on_auth_soft_delete_v1();

do $postflight$
declare
  v_function text;
begin
  select pg_get_functiondef(
    'public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)'::regprocedure
  ) into v_function;
  if position('FOR SHARE OF u,a' in v_function)=0
     or position('FOR KEY SHARE OF u,a' in v_function)<>0
  then raise exception 'Auth deletion revocation: unsafe issuer lock'; end if;

  if not exists (
    select 1
    from pg_trigger t
    where t.tgname='ordax_auth_user_soft_delete_default_entitlements'
      and t.tgrelid='auth.users'::regclass and not t.tgisinternal
      and t.tgenabled='O'
  ) then raise exception 'Auth deletion revocation: trigger not enabled'; end if;

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
     or has_schema_privilege('ordax_entitlement_default_executor','private','USAGE')
     or has_function_privilege(
      'public',
      'private.ordax_revoke_defaults_on_auth_soft_delete_v1()',
      'EXECUTE')
  then raise exception 'Auth deletion revocation: privilege regression'; end if;

  if to_regprocedure('public.ordax_revoke_default_entitlement_v1(uuid,text)') is not null
  then raise exception 'Auth deletion revocation: generic revoke RPC returned'; end if;
end;
$postflight$;

commit;
