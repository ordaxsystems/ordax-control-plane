begin;

do $role$
begin
  if exists (select 1 from pg_roles where rolname = 'ordax_project_executor') then
    raise exception 'project authority: ordax_project_executor already exists';
  end if;

  create role ordax_project_executor
    nosuperuser
    nocreatedb
    nocreaterole
    noinherit
    nologin
    noreplication
    nobypassrls;
end;
$role$;

revoke all on schema public from ordax_project_executor;
revoke all on schema private from ordax_project_executor;
grant usage on schema public to ordax_project_executor;

create function public.ordax_create_project_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
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
  v_project_id uuid;
  v_space_state text;
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok', false, 'error', 'project_identity_invalid');
  end if;

  select s.state into v_space_state
  from public.ordax_spaces s
  where s.space_id = p_space_id;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'space_not_found');
  end if;

  if v_space_state <> 'active' then
    return jsonb_build_object('ok', false, 'error', 'space_inactive');
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
    return jsonb_build_object('ok', false, 'error', 'project_name_invalid');
  end if;

  if p_kind not in ('general', 'development', 'creative', 'legal', 'business', 'research') then
    return jsonb_build_object('ok', false, 'error', 'project_kind_invalid');
  end if;

  if p_metadata is null
     or jsonb_typeof(p_metadata) <> 'object'
     or octet_length(p_metadata::text) > 65536 then
    return jsonb_build_object('ok', false, 'error', 'project_metadata_invalid');
  end if;

  insert into public.ordax_projects(
    space_id,
    created_by_user_id,
    name,
    kind,
    state,
    metadata
  ) values (
    p_space_id,
    p_actor_user_id,
    btrim(p_name),
    p_kind,
    'active',
    p_metadata
  )
  returning project_id into v_project_id;

  return jsonb_build_object(
    'ok', true,
    'project_id', v_project_id,
    'space_id', p_space_id,
    'created_by_user_id', p_actor_user_id,
    'state', 'active'
  );
end;
$function$;

create function public.ordax_update_project_v1(
  p_actor_user_id uuid,
  p_project_id uuid,
  p_name text,
  p_state text,
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
  if p_actor_user_id is null or p_project_id is null then
    return jsonb_build_object('ok', false, 'error', 'project_identity_invalid');
  end if;

  select p.space_id into v_space_id
  from public.ordax_projects p
  where p.project_id = p_project_id;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'project_not_found');
  end if;

  if not private.ordax_subject_can_admin_space_v1(
    p_actor_user_id,
    v_space_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'space_admin_required');
  end if;

  if p_name is null
     or char_length(btrim(p_name)) not between 1 and 120
     or p_name ~ '[[:cntrl:]]' then
    return jsonb_build_object('ok', false, 'error', 'project_name_invalid');
  end if;

  if p_state not in ('active', 'archived') then
    return jsonb_build_object('ok', false, 'error', 'project_state_invalid');
  end if;

  if p_metadata is null
     or jsonb_typeof(p_metadata) <> 'object'
     or octet_length(p_metadata::text) > 65536 then
    return jsonb_build_object('ok', false, 'error', 'project_metadata_invalid');
  end if;

  update public.ordax_projects
     set name = btrim(p_name),
         state = p_state,
         metadata = p_metadata
   where project_id = p_project_id;

  return jsonb_build_object(
    'ok', true,
    'project_id', p_project_id,
    'space_id', v_space_id,
    'state', p_state
  );
end;
$function$;

revoke all on function public.ordax_create_project_v1(uuid, uuid, text, text, jsonb)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor, ordax_project_executor;
revoke all on function public.ordax_update_project_v1(uuid, uuid, text, text, jsonb)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor, ordax_project_executor;

grant execute on function public.ordax_create_project_v1(uuid, uuid, text, text, jsonb)
  to ordax_project_executor;
grant execute on function public.ordax_update_project_v1(uuid, uuid, text, text, jsonb)
  to ordax_project_executor;

do $postflight$
declare
  r record;
  direct_relation_count integer;
  unexpected_exec_count integer;
  unexpected_memberships integer;
begin
  select rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolcanlogin,
         rolreplication, rolbypassrls
    into r
    from pg_roles
   where rolname = 'ordax_project_executor';

  if not found
     or r.rolsuper
     or r.rolcreatedb
     or r.rolcreaterole
     or r.rolinherit
     or r.rolcanlogin
     or r.rolreplication
     or r.rolbypassrls then
    raise exception 'project authority: executor role contract invalid';
  end if;

  if not has_schema_privilege('ordax_project_executor', 'public', 'USAGE')
     or has_schema_privilege('ordax_project_executor', 'public', 'CREATE')
     or has_schema_privilege('ordax_project_executor', 'private', 'USAGE') then
    raise exception 'project authority: executor schema boundary invalid';
  end if;

  select count(*) into direct_relation_count
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname in ('public', 'private')
    and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
    and (
      (c.relkind = 'S' and (
        has_sequence_privilege('ordax_project_executor', c.oid, 'USAGE')
        or has_sequence_privilege('ordax_project_executor', c.oid, 'SELECT')
        or has_sequence_privilege('ordax_project_executor', c.oid, 'UPDATE')
      ))
      or
      (c.relkind <> 'S' and (
        has_table_privilege('ordax_project_executor', c.oid, 'SELECT')
        or has_table_privilege('ordax_project_executor', c.oid, 'INSERT')
        or has_table_privilege('ordax_project_executor', c.oid, 'UPDATE')
        or has_table_privilege('ordax_project_executor', c.oid, 'DELETE')
      ))
    );

  if direct_relation_count <> 0 then
    raise exception 'project authority: executor has direct relation authority';
  end if;

  select count(*) into unexpected_exec_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and has_function_privilege('ordax_project_executor', p.oid, 'EXECUTE')
    and p.oid not in (
      'public.ordax_create_project_v1(uuid,uuid,text,text,jsonb)'::regprocedure,
      'public.ordax_update_project_v1(uuid,uuid,text,text,jsonb)'::regprocedure
    );

  if unexpected_exec_count <> 0 then
    raise exception 'project authority: executor can execute unexpected public function';
  end if;

  select count(*) into unexpected_memberships
  from pg_auth_members am
  join pg_roles granted_role on granted_role.oid = am.roleid
  join pg_roles member_role on member_role.oid = am.member
  where (
      granted_role.rolname = 'ordax_project_executor'
      or member_role.rolname = 'ordax_project_executor'
    )
    and not (
      granted_role.rolname = 'ordax_project_executor'
      and member_role.rolname = 'postgres'
      and am.admin_option
      and not am.inherit_option
      and not am.set_option
    );

  if unexpected_memberships <> 0 then
    raise exception 'project authority: unexpected executor role membership';
  end if;

  if not exists (
    select 1
    from pg_auth_members am
    join pg_roles granted_role on granted_role.oid = am.roleid
    join pg_roles member_role on member_role.oid = am.member
    where granted_role.rolname = 'ordax_project_executor'
      and member_role.rolname = 'postgres'
      and am.admin_option
      and not am.inherit_option
      and not am.set_option
  ) then
    raise exception 'project authority: postgres administrative membership missing';
  end if;
end;
$postflight$;

commit;
