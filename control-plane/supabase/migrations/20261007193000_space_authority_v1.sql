begin;

-- Space mutations are server-authoritative. The executor is a NOLOGIN capability
-- role with no direct table authority; it can invoke only reviewed RPCs.

do $role$
begin
  if exists (select 1 from pg_roles where rolname = 'ordax_space_executor') then
    raise exception 'space authority: ordax_space_executor already exists';
  end if;

  create role ordax_space_executor
    nosuperuser
    nocreatedb
    nocreaterole
    noinherit
    nologin
    noreplication
    nobypassrls;
end;
$role$;

revoke all on schema public from ordax_space_executor;
revoke all on schema private from ordax_space_executor;
grant usage on schema public to ordax_space_executor;

-- owner_user_id is the single owner SSOT. A membership row must never create a
-- second owner concept.
do $owner_guard$
begin
  if exists (
    select 1
    from public.ordax_space_members
    where role = 'owner'
  ) then
    raise exception 'space authority: legacy owner membership requires explicit migration';
  end if;
end;
$owner_guard$;

alter table public.ordax_space_members
  drop constraint ordax_space_members_role_check;

alter table public.ordax_space_members
  add constraint ordax_space_members_role_check
  check (role in ('admin', 'member', 'viewer'));

create function public.ordax_create_space_v1(
  p_actor_user_id uuid,
  p_name text,
  p_kind text,
  p_metadata jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_space_id uuid;
begin
  if p_actor_user_id is null
     or not exists (select 1 from auth.users u where u.id = p_actor_user_id) then
    return jsonb_build_object('ok', false, 'error', 'space_actor_not_found');
  end if;

  if p_name is null
     or char_length(btrim(p_name)) not between 1 and 120
     or p_name ~ '[[:cntrl:]]' then
    return jsonb_build_object('ok', false, 'error', 'space_name_invalid');
  end if;

  if p_kind not in ('personal', 'work', 'professional') then
    return jsonb_build_object('ok', false, 'error', 'space_kind_invalid');
  end if;

  if p_metadata is null
     or jsonb_typeof(p_metadata) <> 'object'
     or octet_length(p_metadata::text) > 65536 then
    return jsonb_build_object('ok', false, 'error', 'space_metadata_invalid');
  end if;

  insert into public.ordax_spaces(
    owner_user_id,
    name,
    kind,
    state,
    metadata
  ) values (
    p_actor_user_id,
    btrim(p_name),
    p_kind,
    'active',
    p_metadata
  )
  returning space_id into v_space_id;

  return jsonb_build_object(
    'ok', true,
    'space_id', v_space_id,
    'owner_user_id', p_actor_user_id,
    'state', 'active'
  );
end;
$function$;

create function public.ordax_update_space_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
  p_name text,
  p_state text,
  p_metadata jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok', false, 'error', 'space_identity_invalid');
  end if;

  if not exists (
    select 1 from public.ordax_spaces s where s.space_id = p_space_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'space_not_found');
  end if;

  if not private.ordax_subject_can_admin_space_v1(
    p_actor_user_id,
    p_space_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'space_admin_required');
  end if;

  if p_name is null
     or char_length(btrim(p_name)) not between 1 and 120
     or p_name ~ '[[:cntrl:]]' then
    return jsonb_build_object('ok', false, 'error', 'space_name_invalid');
  end if;

  if p_state not in ('active', 'archived') then
    return jsonb_build_object('ok', false, 'error', 'space_state_invalid');
  end if;

  if p_metadata is null
     or jsonb_typeof(p_metadata) <> 'object'
     or octet_length(p_metadata::text) > 65536 then
    return jsonb_build_object('ok', false, 'error', 'space_metadata_invalid');
  end if;

  update public.ordax_spaces
     set name = btrim(p_name),
         state = p_state,
         metadata = p_metadata
   where space_id = p_space_id;

  return jsonb_build_object(
    'ok', true,
    'space_id', p_space_id,
    'state', p_state
  );
end;
$function$;

create function public.ordax_set_space_member_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
  p_member_user_id uuid,
  p_role text,
  p_state text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_owner_user_id uuid;
begin
  if p_actor_user_id is null
     or p_space_id is null
     or p_member_user_id is null then
    return jsonb_build_object('ok', false, 'error', 'space_member_identity_invalid');
  end if;

  select s.owner_user_id
    into v_owner_user_id
    from public.ordax_spaces s
   where s.space_id = p_space_id;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'space_not_found');
  end if;

  if not private.ordax_subject_can_admin_space_v1(
    p_actor_user_id,
    p_space_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'space_admin_required');
  end if;

  if p_member_user_id = v_owner_user_id then
    return jsonb_build_object('ok', false, 'error', 'space_owner_membership_forbidden');
  end if;

  if not exists (
    select 1 from auth.users u where u.id = p_member_user_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'space_member_not_found');
  end if;

  if p_role not in ('admin', 'member', 'viewer') then
    return jsonb_build_object('ok', false, 'error', 'space_member_role_invalid');
  end if;

  if p_state not in ('active', 'suspended') then
    return jsonb_build_object('ok', false, 'error', 'space_member_state_invalid');
  end if;

  insert into public.ordax_space_members(
    space_id,
    user_id,
    role,
    state
  ) values (
    p_space_id,
    p_member_user_id,
    p_role,
    p_state
  )
  on conflict (space_id, user_id)
  do update
     set role = excluded.role,
         state = excluded.state;

  return jsonb_build_object(
    'ok', true,
    'space_id', p_space_id,
    'user_id', p_member_user_id,
    'role', p_role,
    'state', p_state
  );
end;
$function$;

create function public.ordax_remove_space_member_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
  p_member_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_owner_user_id uuid;
  v_removed boolean;
begin
  if p_actor_user_id is null
     or p_space_id is null
     or p_member_user_id is null then
    return jsonb_build_object('ok', false, 'error', 'space_member_identity_invalid');
  end if;

  select s.owner_user_id
    into v_owner_user_id
    from public.ordax_spaces s
   where s.space_id = p_space_id;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'space_not_found');
  end if;

  if not private.ordax_subject_can_admin_space_v1(
    p_actor_user_id,
    p_space_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'space_admin_required');
  end if;

  if p_member_user_id = v_owner_user_id then
    return jsonb_build_object('ok', false, 'error', 'space_owner_membership_forbidden');
  end if;

  delete from public.ordax_space_members
   where space_id = p_space_id
     and user_id = p_member_user_id;

  v_removed := found;

  return jsonb_build_object(
    'ok', true,
    'space_id', p_space_id,
    'user_id', p_member_user_id,
    'removed', v_removed
  );
end;
$function$;

revoke all on function public.ordax_create_space_v1(uuid, text, text, jsonb)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor;
revoke all on function public.ordax_update_space_v1(uuid, uuid, text, text, jsonb)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor;
revoke all on function public.ordax_set_space_member_v1(uuid, uuid, uuid, text, text)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor;
revoke all on function public.ordax_remove_space_member_v1(uuid, uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor;

grant execute on function public.ordax_create_space_v1(uuid, text, text, jsonb)
  to ordax_space_executor;
grant execute on function public.ordax_update_space_v1(uuid, uuid, text, text, jsonb)
  to ordax_space_executor;
grant execute on function public.ordax_set_space_member_v1(uuid, uuid, uuid, text, text)
  to ordax_space_executor;
grant execute on function public.ordax_remove_space_member_v1(uuid, uuid, uuid)
  to ordax_space_executor;

do $postflight$
declare
  r record;
  direct_relation_count integer;
  unexpected_exec_count integer;
  membership_count integer;
begin
  select rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolcanlogin,
         rolreplication, rolbypassrls
    into r
    from pg_roles
   where rolname = 'ordax_space_executor';

  if not found
     or r.rolsuper
     or r.rolcreatedb
     or r.rolcreaterole
     or r.rolinherit
     or r.rolcanlogin
     or r.rolreplication
     or r.rolbypassrls then
    raise exception 'space authority: executor role contract invalid';
  end if;

  if not has_schema_privilege('ordax_space_executor', 'public', 'USAGE')
     or has_schema_privilege('ordax_space_executor', 'public', 'CREATE')
     or has_schema_privilege('ordax_space_executor', 'private', 'USAGE') then
    raise exception 'space authority: executor schema boundary invalid';
  end if;

  select count(*) into direct_relation_count
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname in ('public', 'private')
    and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
    and (
      (c.relkind = 'S' and (
        has_sequence_privilege('ordax_space_executor', c.oid, 'USAGE')
        or has_sequence_privilege('ordax_space_executor', c.oid, 'SELECT')
        or has_sequence_privilege('ordax_space_executor', c.oid, 'UPDATE')
      ))
      or
      (c.relkind <> 'S' and (
        has_table_privilege('ordax_space_executor', c.oid, 'SELECT')
        or has_table_privilege('ordax_space_executor', c.oid, 'INSERT')
        or has_table_privilege('ordax_space_executor', c.oid, 'UPDATE')
        or has_table_privilege('ordax_space_executor', c.oid, 'DELETE')
      ))
    );

  if direct_relation_count <> 0 then
    raise exception 'space authority: executor has direct relation authority';
  end if;

  select count(*) into unexpected_exec_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and has_function_privilege('ordax_space_executor', p.oid, 'EXECUTE')
    and p.oid not in (
      'public.ordax_create_space_v1(uuid,text,text,jsonb)'::regprocedure,
      'public.ordax_update_space_v1(uuid,uuid,text,text,jsonb)'::regprocedure,
      'public.ordax_set_space_member_v1(uuid,uuid,uuid,text,text)'::regprocedure,
      'public.ordax_remove_space_member_v1(uuid,uuid,uuid)'::regprocedure
    );

  if unexpected_exec_count <> 0 then
    raise exception 'space authority: executor can execute unexpected public function';
  end if;

  select count(*) into membership_count
  from pg_auth_members am
  join pg_roles granted_role on granted_role.oid = am.roleid
  join pg_roles member_role on member_role.oid = am.member
  where granted_role.rolname = 'ordax_space_executor'
     or member_role.rolname = 'ordax_space_executor';

  select count(*) into membership_count
  from pg_auth_members am
  join pg_roles granted_role on granted_role.oid = am.roleid
  join pg_roles member_role on member_role.oid = am.member
  where (
      granted_role.rolname = 'ordax_space_executor'
      or member_role.rolname = 'ordax_space_executor'
    )
    and not (
      granted_role.rolname = 'ordax_space_executor'
      and member_role.rolname = 'postgres'
      and am.admin_option
      and not am.inherit_option
      and not am.set_option
    );

  if membership_count <> 0 then
    raise exception 'space authority: unexpected executor role membership';
  end if;

  if not exists (
    select 1
    from pg_auth_members am
    join pg_roles granted_role on granted_role.oid = am.roleid
    join pg_roles member_role on member_role.oid = am.member
    where granted_role.rolname = 'ordax_space_executor'
      and member_role.rolname = 'postgres'
      and am.admin_option
      and not am.inherit_option
      and not am.set_option
  ) then
    raise exception 'space authority: postgres administrative membership missing';
  end if;
end;
$postflight$;

commit;
