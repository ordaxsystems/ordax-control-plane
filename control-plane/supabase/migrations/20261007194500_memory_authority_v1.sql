begin;

do $preflight$
begin
  if exists (select 1 from public.ordax_memory_items limit 1) then
    raise exception 'memory authority: canonical table must be empty before scope normalization';
  end if;

  if exists (select 1 from pg_roles where rolname = 'ordax_memory_executor') then
    raise exception 'memory authority: ordax_memory_executor already exists';
  end if;
end;
$preflight$;

alter table public.ordax_memory_items
  drop column project_ref;

alter table public.ordax_memory_items
  add column project_id uuid;

alter table public.ordax_memory_items
  drop constraint if exists ordax_memory_items_scope_check;

alter table public.ordax_memory_items
  add constraint ordax_memory_items_scope_check
  check (scope in ('account', 'space', 'project'));

alter table public.ordax_memory_items
  add constraint ordax_memory_items_scope_identity_check
  check (
    (scope = 'account' and space_id is null and project_id is null)
    or
    (scope = 'space' and space_id is not null and project_id is null)
    or
    (scope = 'project' and space_id is not null and project_id is not null)
  );

alter table public.ordax_memory_items
  add constraint ordax_memory_items_project_space_fk
  foreign key (project_id, space_id)
  references public.ordax_projects(project_id, space_id)
  on delete cascade;

create index ordax_memory_items_project_scope_idx
  on public.ordax_memory_items(project_id, scope, state)
  where project_id is not null;

comment on column public.ordax_memory_items.project_id is
  'Canonical OrdaX Project identity for durable project-scoped memory. No local path or provider ref.';

create role ordax_memory_executor
  nosuperuser nocreatedb nocreaterole noinherit nologin noreplication nobypassrls;

revoke all on schema public from ordax_memory_executor;
revoke all on schema private from ordax_memory_executor;
grant usage on schema public to ordax_memory_executor;

create function public.ordax_create_memory_item_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_scope text,
  p_kind text,
  p_sensitivity text,
  p_content text,
  p_provenance text,
  p_source_timestamp timestamptz,
  p_confidence numeric
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_memory_id uuid;
begin
  if p_actor_user_id is null
     or not exists (select 1 from auth.users u where u.id = p_actor_user_id) then
    return jsonb_build_object('ok', false, 'error', 'memory_actor_not_found');
  end if;

  if p_scope not in ('account', 'space', 'project') then
    return jsonb_build_object('ok', false, 'error', 'memory_scope_invalid');
  end if;

  if p_scope = 'account' and (p_space_id is not null or p_project_id is not null) then
    return jsonb_build_object('ok', false, 'error', 'memory_account_scope_identity_invalid');
  end if;

  if p_scope = 'space' then
    if p_space_id is null or p_project_id is not null then
      return jsonb_build_object('ok', false, 'error', 'memory_space_scope_identity_invalid');
    end if;
    if not private.ordax_subject_can_access_space_v1(p_actor_user_id, p_space_id) then
      return jsonb_build_object('ok', false, 'error', 'memory_space_access_required');
    end if;
  end if;

  if p_scope = 'project' then
    if p_space_id is null or p_project_id is null then
      return jsonb_build_object('ok', false, 'error', 'memory_project_scope_identity_invalid');
    end if;
    if not exists (
      select 1 from public.ordax_projects p
      where p.project_id = p_project_id
        and p.space_id = p_space_id
        and p.state = 'active'
    ) then
      return jsonb_build_object('ok', false, 'error', 'memory_project_not_found');
    end if;
    if not private.ordax_subject_can_access_project_v1(p_actor_user_id, p_project_id) then
      return jsonb_build_object('ok', false, 'error', 'memory_project_access_required');
    end if;
  end if;

  if p_kind not in ('preference', 'fact', 'instruction', 'summary', 'artifact-reference') then
    return jsonb_build_object('ok', false, 'error', 'memory_kind_invalid');
  end if;

  if p_sensitivity not in ('normal', 'private', 'restricted') then
    return jsonb_build_object('ok', false, 'error', 'memory_sensitivity_invalid');
  end if;

  if p_content is null or char_length(p_content) not between 1 and 32768 then
    return jsonb_build_object('ok', false, 'error', 'memory_content_invalid');
  end if;

  if p_provenance is null or char_length(p_provenance) not between 1 and 1024 then
    return jsonb_build_object('ok', false, 'error', 'memory_provenance_invalid');
  end if;

  if p_source_timestamp is null then
    return jsonb_build_object('ok', false, 'error', 'memory_source_timestamp_invalid');
  end if;

  if p_confidence is not null and (p_confidence < 0 or p_confidence > 1) then
    return jsonb_build_object('ok', false, 'error', 'memory_confidence_invalid');
  end if;

  insert into public.ordax_memory_items(
    owner_user_id, space_id, project_id, scope, kind, sensitivity,
    content, provenance, source_timestamp, confidence, state
  ) values (
    p_actor_user_id, p_space_id, p_project_id, p_scope, p_kind, p_sensitivity,
    p_content, p_provenance, p_source_timestamp, p_confidence, 'active'
  )
  returning memory_id into v_memory_id;

  return jsonb_build_object('ok', true, 'memory_id', v_memory_id, 'scope', p_scope, 'state', 'active');
end;
$function$;

create function public.ordax_update_memory_item_v1(
  p_actor_user_id uuid,
  p_memory_id uuid,
  p_sensitivity text,
  p_content text,
  p_provenance text,
  p_source_timestamp timestamptz,
  p_confidence numeric,
  p_state text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_owner_user_id uuid;
  v_current_state text;
begin
  if p_actor_user_id is null or p_memory_id is null then
    return jsonb_build_object('ok', false, 'error', 'memory_identity_invalid');
  end if;

  select m.owner_user_id, m.state
    into v_owner_user_id, v_current_state
    from public.ordax_memory_items m
   where m.memory_id = p_memory_id;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'memory_not_found');
  end if;

  if v_owner_user_id <> p_actor_user_id then
    return jsonb_build_object('ok', false, 'error', 'memory_owner_required');
  end if;

  if v_current_state = 'deleted' then
    return jsonb_build_object('ok', false, 'error', 'memory_deleted');
  end if;

  if p_sensitivity not in ('normal', 'private', 'restricted') then
    return jsonb_build_object('ok', false, 'error', 'memory_sensitivity_invalid');
  end if;

  if p_content is null or char_length(p_content) not between 1 and 32768 then
    return jsonb_build_object('ok', false, 'error', 'memory_content_invalid');
  end if;

  if p_provenance is null or char_length(p_provenance) not between 1 and 1024 then
    return jsonb_build_object('ok', false, 'error', 'memory_provenance_invalid');
  end if;

  if p_source_timestamp is null then
    return jsonb_build_object('ok', false, 'error', 'memory_source_timestamp_invalid');
  end if;

  if p_confidence is not null and (p_confidence < 0 or p_confidence > 1) then
    return jsonb_build_object('ok', false, 'error', 'memory_confidence_invalid');
  end if;

  if p_state not in ('active', 'superseded', 'deleted') then
    return jsonb_build_object('ok', false, 'error', 'memory_state_invalid');
  end if;

  update public.ordax_memory_items
     set sensitivity = p_sensitivity,
         content = p_content,
         provenance = p_provenance,
         source_timestamp = p_source_timestamp,
         confidence = p_confidence,
         state = p_state
   where memory_id = p_memory_id;

  return jsonb_build_object('ok', true, 'memory_id', p_memory_id, 'state', p_state);
end;
$function$;

revoke all on function public.ordax_create_memory_item_v1(
  uuid, uuid, uuid, text, text, text, text, text, timestamptz, numeric
) from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_memory_executor;

revoke all on function public.ordax_update_memory_item_v1(
  uuid, uuid, text, text, text, timestamptz, numeric, text
) from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_memory_executor;

grant execute on function public.ordax_create_memory_item_v1(
  uuid, uuid, uuid, text, text, text, text, text, timestamptz, numeric
) to ordax_memory_executor;

grant execute on function public.ordax_update_memory_item_v1(
  uuid, uuid, text, text, text, timestamptz, numeric, text
) to ordax_memory_executor;

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
   where rolname = 'ordax_memory_executor';

  if not found
     or r.rolsuper or r.rolcreatedb or r.rolcreaterole
     or r.rolinherit or r.rolcanlogin or r.rolreplication or r.rolbypassrls then
    raise exception 'memory authority: executor role contract invalid';
  end if;

  if not has_schema_privilege('ordax_memory_executor', 'public', 'USAGE')
     or has_schema_privilege('ordax_memory_executor', 'public', 'CREATE')
     or has_schema_privilege('ordax_memory_executor', 'private', 'USAGE') then
    raise exception 'memory authority: executor schema boundary invalid';
  end if;

  select count(*) into direct_relation_count
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname in ('public', 'private')
    and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
    and (
      (c.relkind = 'S' and (
        has_sequence_privilege('ordax_memory_executor', c.oid, 'USAGE')
        or has_sequence_privilege('ordax_memory_executor', c.oid, 'SELECT')
        or has_sequence_privilege('ordax_memory_executor', c.oid, 'UPDATE')
      ))
      or
      (c.relkind <> 'S' and (
        has_table_privilege('ordax_memory_executor', c.oid, 'SELECT')
        or has_table_privilege('ordax_memory_executor', c.oid, 'INSERT')
        or has_table_privilege('ordax_memory_executor', c.oid, 'UPDATE')
        or has_table_privilege('ordax_memory_executor', c.oid, 'DELETE')
      ))
    );

  if direct_relation_count <> 0 then
    raise exception 'memory authority: executor has direct relation authority';
  end if;

  select count(*) into unexpected_exec_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and has_function_privilege('ordax_memory_executor', p.oid, 'EXECUTE')
    and p.oid not in (
      'public.ordax_create_memory_item_v1(uuid,uuid,uuid,text,text,text,text,text,timestamptz,numeric)'::regprocedure,
      'public.ordax_update_memory_item_v1(uuid,uuid,text,text,text,timestamptz,numeric,text)'::regprocedure
    );

  if unexpected_exec_count <> 0 then
    raise exception 'memory authority: executor can execute unexpected public function';
  end if;

  select count(*) into unexpected_memberships
  from pg_auth_members am
  join pg_roles granted_role on granted_role.oid = am.roleid
  join pg_roles member_role on member_role.oid = am.member
  where (
      granted_role.rolname = 'ordax_memory_executor'
      or member_role.rolname = 'ordax_memory_executor'
    )
    and not (
      granted_role.rolname = 'ordax_memory_executor'
      and member_role.rolname = 'postgres'
      and am.admin_option
      and not am.inherit_option
      and not am.set_option
    );

  if unexpected_memberships <> 0 then
    raise exception 'memory authority: unexpected executor role membership';
  end if;
end;
$postflight$;

commit;
