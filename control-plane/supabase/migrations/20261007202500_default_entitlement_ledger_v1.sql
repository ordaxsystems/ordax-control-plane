begin;

-- New canonical Product entitlements may only be issued from reviewed,
-- versioned policy. Billing/promotion/admin remain deliberately fail-closed.
do $preflight$
begin
  if exists (select 1 from public.ordax_entitlement_grants limit 1) then
    raise exception 'entitlement authority: existing grants require explicit provenance migration';
  end if;
  if exists (select 1 from pg_roles where rolname = 'ordax_entitlement_default_executor') then
    raise exception 'entitlement authority: executor role already exists';
  end if;
end;
$preflight$;

alter table public.ordax_entitlement_grants
  add column source_event_id text,
  add column policy_version integer;

alter table public.ordax_entitlement_grants
  add constraint ordax_entitlement_source_event_valid_check
  check (
    source_event_id is null or (
      char_length(source_event_id) between 8 and 160
      and source_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    )
  );

alter table public.ordax_entitlement_grants
  add constraint ordax_entitlement_default_provenance_check
  check (
    (source = 'product-default'
      and source_event_id is not null
      and policy_version > 0)
    or
    (source <> 'product-default'
      and source_event_id is null
      and policy_version is null)
  );

create unique index ordax_entitlements_source_event_uidx
  on public.ordax_entitlement_grants(source, source_event_id)
  where source_event_id is not null;

-- Catalog has deliberately no initial rows: an approved migration must publish
-- an exact default policy before the issuer can perform a real grant.
create table private.ordax_default_entitlement_policies (
  entitlement_key text not null
    check (entitlement_key ~ '^[a-z][a-z0-9.-]{2,95}$'),
  policy_version integer not null check (policy_version > 0),
  entitlement_value jsonb not null
    check (jsonb_typeof(entitlement_value) = 'object'
       and octet_length(entitlement_value::text) <= 8192),
  duration_seconds integer not null
    check (duration_seconds between 1 and 31536000),
  state text not null check (state in ('draft', 'active', 'retired')),
  created_at timestamptz not null default now(),
  primary key(entitlement_key, policy_version)
);

create table private.ordax_default_entitlement_events (
  event_id uuid primary key default gen_random_uuid(),
  source text not null default 'product-default'
    check (source = 'product-default'),
  source_event_id text not null
    check (char_length(source_event_id) between 8 and 160
      and source_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'),
  event_kind text not null check (event_kind in ('issued', 'revoked')),
  grant_id uuid not null
    references public.ordax_entitlement_grants(grant_id) on delete cascade,
  subject_user_id uuid not null
    references auth.users(id) on delete cascade,
  entitlement_key text not null,
  policy_version integer not null check (policy_version > 0),
  occurred_at timestamptz not null default now(),
  unique(source, source_event_id)
);
create index ordax_default_entitlement_events_grant_fk_idx
  on private.ordax_default_entitlement_events(grant_id);
create index ordax_default_entitlement_events_user_fk_idx
  on private.ordax_default_entitlement_events(subject_user_id);

alter table private.ordax_default_entitlement_policies enable row level security;
alter table private.ordax_default_entitlement_events enable row level security;

revoke all on table private.ordax_default_entitlement_policies,
  private.ordax_default_entitlement_events
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_memory_executor,
       ordax_profile_pack_executor;

create role ordax_entitlement_default_executor
  nosuperuser nocreatedb nocreaterole noinherit nologin noreplication nobypassrls;

revoke all on schema public from ordax_entitlement_default_executor;
revoke all on schema private from ordax_entitlement_default_executor;
grant usage on schema public to ordax_entitlement_default_executor;

create function public.ordax_issue_default_entitlement_v1(
  p_subject_user_id uuid,
  p_entitlement_key text,
  p_policy_version integer,
  p_source_event_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_event private.ordax_default_entitlement_events%rowtype;
  v_value jsonb;
  v_duration integer;
  v_grant_id uuid;
  v_now timestamptz;
begin
  if p_subject_user_id is null
    or p_entitlement_key is null
    or p_policy_version is null or p_policy_version < 1
    or p_source_event_id is null
    or char_length(p_source_event_id) not between 8 and 160
    or p_source_event_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$' then
    return jsonb_build_object('ok',false,'error','default_entitlement_input_invalid');
  end if;

  -- Locks serialize retries for the external event and overlapping default
  -- issuances of the same entitlement. A collision can only serialize work.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ordax.default.event:' || p_source_event_id, 0)
  );

  select * into v_event
  from private.ordax_default_entitlement_events
  where source='product-default' and source_event_id=p_source_event_id;

  if found then
    if v_event.event_kind='issued'
       and v_event.subject_user_id=p_subject_user_id
       and v_event.entitlement_key=p_entitlement_key
       and v_event.policy_version=p_policy_version then
      return jsonb_build_object('ok',true,'changed',false,'replayed',true,
        'grant_id',v_event.grant_id);
    end if;
    return jsonb_build_object('ok',false,'error','source_event_conflict');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      'ordax.default.subject:' || p_subject_user_id::text || ':' || p_entitlement_key, 0)
  );

  if not exists (select 1 from auth.users where id=p_subject_user_id) then
    return jsonb_build_object('ok',false,'error','entitlement_subject_not_found');
  end if;

  select entitlement_value,duration_seconds into v_value,v_duration
  from private.ordax_default_entitlement_policies
  where entitlement_key=p_entitlement_key
    and policy_version=p_policy_version
    and state='active'
  for share;
  if not found then
    return jsonb_build_object('ok',false,'error','default_policy_not_active');
  end if;

  v_now:=pg_catalog.clock_timestamp();

  if exists (
    select 1 from public.ordax_entitlement_grants
    where user_id=p_subject_user_id
      and entitlement_key=p_entitlement_key
      and source='product-default'
      and valid_from<=v_now
      and (valid_until is null or valid_until>v_now)
  ) then
    return jsonb_build_object('ok',false,'error','default_entitlement_already_active');
  end if;

  insert into public.ordax_entitlement_grants(
    user_id,space_id,entitlement_key,entitlement_value,
    source,source_event_id,policy_version,valid_from,valid_until
  ) values(
    p_subject_user_id,null,p_entitlement_key,v_value,
    'product-default',p_source_event_id,p_policy_version,
    v_now,v_now + pg_catalog.make_interval(secs => v_duration)
  ) returning grant_id into v_grant_id;

  insert into private.ordax_default_entitlement_events(
    source_event_id,event_kind,grant_id,subject_user_id,
    entitlement_key,policy_version
  ) values (
    p_source_event_id,'issued',v_grant_id,p_subject_user_id,
    p_entitlement_key,p_policy_version
  );

  return jsonb_build_object('ok',true,'changed',true,
    'replayed',false,'grant_id',v_grant_id);
end;
$function$;

create function public.ordax_revoke_default_entitlement_v1(
  p_grant_id uuid,
  p_source_event_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_event private.ordax_default_entitlement_events%rowtype;
  v_grant public.ordax_entitlement_grants%rowtype;
  v_now timestamptz;
  v_changed boolean;
begin
  if p_grant_id is null or p_source_event_id is null
     or char_length(p_source_event_id) not between 8 and 160
     or p_source_event_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$' then
    return jsonb_build_object('ok',false,'error','default_entitlement_input_invalid');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ordax.default.event:' || p_source_event_id, 0)
  );

  select * into v_event
  from private.ordax_default_entitlement_events
  where source='product-default' and source_event_id=p_source_event_id;

  if found then
    if v_event.event_kind='revoked' and v_event.grant_id=p_grant_id then
      return jsonb_build_object('ok',true,'changed',false,'replayed',true,
        'grant_id',p_grant_id);
    end if;
    return jsonb_build_object('ok',false,'error','source_event_conflict');
  end if;

  select * into v_grant
  from public.ordax_entitlement_grants
  where grant_id=p_grant_id and source='product-default'
  for update;

  if not found then
    return jsonb_build_object('ok',false,'error','default_entitlement_not_found');
  end if;

  v_now:=pg_catalog.clock_timestamp();
  v_changed:=(v_grant.valid_until is null or v_grant.valid_until>v_now);

  if v_changed then
    update public.ordax_entitlement_grants
       set valid_until=greatest(
         v_now, v_grant.valid_from + interval '1 microsecond')
     where grant_id=p_grant_id;
  end if;

  insert into private.ordax_default_entitlement_events(
    source_event_id,event_kind,grant_id,subject_user_id,
    entitlement_key,policy_version
  ) values (
    p_source_event_id,'revoked',p_grant_id,v_grant.user_id,
    v_grant.entitlement_key,v_grant.policy_version
  );

  return jsonb_build_object('ok',true,'changed',v_changed,
    'replayed',false,'grant_id',p_grant_id);
end;
$function$;

revoke all on function public.ordax_issue_default_entitlement_v1(uuid,text,integer,text)
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor,ordax_entitlement_default_executor;

revoke all on function public.ordax_revoke_default_entitlement_v1(uuid,text)
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor,ordax_entitlement_default_executor;

grant execute on function public.ordax_issue_default_entitlement_v1(uuid,text,integer,text)
  to ordax_entitlement_default_executor;
grant execute on function public.ordax_revoke_default_entitlement_v1(uuid,text)
  to ordax_entitlement_default_executor;

do $postflight$
declare
  v_bad_relations integer;
  v_bad_functions integer;
  v_bad_memberships integer;
begin
  if not exists (
    select 1 from pg_roles
    where rolname='ordax_entitlement_default_executor'
      and not rolcanlogin and not rolinherit and not rolbypassrls
      and not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication
  ) then raise exception 'default entitlement: executor role flags invalid'; end if;

  if not has_schema_privilege('ordax_entitlement_default_executor','public','USAGE')
     or has_schema_privilege('ordax_entitlement_default_executor','public','CREATE')
     or has_schema_privilege('ordax_entitlement_default_executor','private','USAGE')
  then raise exception 'default entitlement: executor schema privileges invalid'; end if;

  select count(*) into v_bad_relations
  from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where n.nspname in ('public','private')
    and c.relkind in ('r','p','v','m','f','S')
    and (
      (c.relkind='S' and (
        has_sequence_privilege('ordax_entitlement_default_executor',c.oid,'USAGE')
        or has_sequence_privilege('ordax_entitlement_default_executor',c.oid,'SELECT')
        or has_sequence_privilege('ordax_entitlement_default_executor',c.oid,'UPDATE')))
      or
      (c.relkind<>'S' and (
        has_table_privilege('ordax_entitlement_default_executor',c.oid,'SELECT')
        or has_table_privilege('ordax_entitlement_default_executor',c.oid,'INSERT')
        or has_table_privilege('ordax_entitlement_default_executor',c.oid,'UPDATE')
        or has_table_privilege('ordax_entitlement_default_executor',c.oid,'DELETE')))
    );
  if v_bad_relations<>0 then
    raise exception 'default entitlement: unexpected table/sequence access';
  end if;

  select count(*) into v_bad_functions
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public'
    and has_function_privilege('ordax_entitlement_default_executor',p.oid,'EXECUTE')
    and p.oid not in (
      'public.ordax_issue_default_entitlement_v1(uuid,text,integer,text)'::regprocedure,
      'public.ordax_revoke_default_entitlement_v1(uuid,text)'::regprocedure
    );
  if v_bad_functions<>0 then
    raise exception 'default entitlement: unexpected public function access';
  end if;

  select count(*) into v_bad_memberships
  from pg_auth_members am join pg_roles role on role.oid=am.roleid
  join pg_roles member on member.oid=am.member
  where (role.rolname='ordax_entitlement_default_executor'
    or member.rolname='ordax_entitlement_default_executor')
    and not (role.rolname='ordax_entitlement_default_executor'
       and member.rolname='postgres'
       and am.admin_option and not am.inherit_option and not am.set_option);
  if v_bad_memberships<>0 then
    raise exception 'default entitlement: unexpected executor membership';
  end if;
end;
$postflight$;

commit;
