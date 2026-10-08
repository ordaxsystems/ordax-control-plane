begin;

-- Profile Pack definitions are source-controlled catalog data. This domain
-- changes only the Space selection, never the catalog or entitlements.
do $preflight$
begin
  if exists (select 1 from pg_roles where rolname='ordax_profile_pack_executor') then
    raise exception 'profile pack authority: executor already exists';
  end if;
  if exists (select 1 from public.ordax_space_profile_packs limit 1) then
    raise exception 'profile pack authority: review existing selections explicitly';
  end if;
end;
$preflight$;

create role ordax_profile_pack_executor
  nosuperuser nocreatedb nocreaterole noinherit nologin noreplication nobypassrls;

revoke all on schema public from ordax_profile_pack_executor;
revoke all on schema private from ordax_profile_pack_executor;
grant usage on schema public to ordax_profile_pack_executor;

-- Append-only event history, including deselection. This is not another
-- current-state table: ordax_space_profile_packs remains the assignment SSOT.
create table private.ordax_space_profile_pack_events (
  event_id uuid primary key default gen_random_uuid(),
  space_id uuid not null references public.ordax_spaces(space_id) on delete cascade,
  actor_user_id uuid references auth.users(id) on delete set null,
  operation text not null check (operation in ('selected', 'cleared')),
  previous_pack_slug text,
  previous_pack_version integer,
  selected_pack_slug text,
  selected_pack_version integer,
  occurred_at timestamptz not null default now(),
  check (
    (previous_pack_slug is null and previous_pack_version is null)
    or (previous_pack_slug is not null and previous_pack_version is not null)
  ),
  check (
    (selected_pack_slug is null and selected_pack_version is null)
    or (selected_pack_slug is not null and selected_pack_version is not null)
  ),
  check (
    (operation = 'selected' and selected_pack_slug is not null)
    or (operation = 'cleared' and selected_pack_slug is null)
  )
);
create index ordax_space_profile_pack_events_space_time_idx
  on private.ordax_space_profile_pack_events(space_id, occurred_at desc, event_id);
alter table private.ordax_space_profile_pack_events enable row level security;
revoke all on table private.ordax_space_profile_pack_events
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_memory_executor,
       ordax_profile_pack_executor;

create function public.ordax_select_space_profile_pack_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
  p_pack_slug text,
  p_pack_version integer
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_space_state text;
  v_previous_slug text;
  v_previous_version integer;
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok',false,'error','pack_identity_invalid');
  end if;

  -- Serializes concurrent selections and clear operations for this Space.
  select state into v_space_state
  from public.ordax_spaces
  where space_id=p_space_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'error','space_not_found');
  end if;
  if v_space_state <> 'active' then
    return jsonb_build_object('ok',false,'error','space_inactive');
  end if;
  if not private.ordax_subject_can_admin_space_v1(p_actor_user_id,p_space_id) then
    return jsonb_build_object('ok',false,'error','space_admin_required');
  end if;

  if p_pack_slug is null or p_pack_version is null or p_pack_version < 1 then
    return jsonb_build_object('ok',false,'error','pack_identity_invalid');
  end if;

  -- A catalog retirement must not race an assignment of the same version.
  perform 1 from public.ordax_profile_packs
  where slug=p_pack_slug and version=p_pack_version and state='active'
  for share;
  if not found then
    return jsonb_build_object('ok',false,'error','pack_not_active');
  end if;

  select pack_slug,pack_version
    into v_previous_slug,v_previous_version
    from public.ordax_space_profile_packs
   where space_id=p_space_id;

  if v_previous_slug = p_pack_slug and v_previous_version = p_pack_version then
    return jsonb_build_object('ok',true,'changed',false,'space_id',p_space_id,
      'pack_slug',p_pack_slug,'pack_version',p_pack_version);
  end if;

  -- No arbitrary configuration/secret blob is accepted by this MVP boundary.
  insert into public.ordax_space_profile_packs
    (space_id,pack_slug,pack_version,config,enabled_at,enabled_by)
  values (p_space_id,p_pack_slug,p_pack_version,'{}'::jsonb,now(),p_actor_user_id)
  on conflict (space_id) do update set
    pack_slug=excluded.pack_slug,
    pack_version=excluded.pack_version,
    config=excluded.config,
    enabled_at=excluded.enabled_at,
    enabled_by=excluded.enabled_by;

  insert into private.ordax_space_profile_pack_events
    (space_id,actor_user_id,operation,previous_pack_slug,
     previous_pack_version,selected_pack_slug,selected_pack_version)
  values (p_space_id,p_actor_user_id,'selected',v_previous_slug,
    v_previous_version,p_pack_slug,p_pack_version);

  return jsonb_build_object('ok',true,'changed',true,'space_id',p_space_id,
    'pack_slug',p_pack_slug,'pack_version',p_pack_version);
end;
$function$;

create function public.ordax_clear_space_profile_pack_v1(
  p_actor_user_id uuid,
  p_space_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_previous_slug text;
  v_previous_version integer;
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok',false,'error','pack_identity_invalid');
  end if;

  perform 1 from public.ordax_spaces
  where space_id=p_space_id
  for update;
  if not found then
    return jsonb_build_object('ok',false,'error','space_not_found');
  end if;
  if not private.ordax_subject_can_admin_space_v1(p_actor_user_id,p_space_id) then
    return jsonb_build_object('ok',false,'error','space_admin_required');
  end if;

  delete from public.ordax_space_profile_packs
   where space_id=p_space_id
  returning pack_slug,pack_version into v_previous_slug,v_previous_version;

  if not found then
    return jsonb_build_object('ok',true,'changed',false,'space_id',p_space_id);
  end if;

  insert into private.ordax_space_profile_pack_events
    (space_id,actor_user_id,operation,previous_pack_slug,previous_pack_version)
  values (p_space_id,p_actor_user_id,'cleared',v_previous_slug,v_previous_version);

  return jsonb_build_object('ok',true,'changed',true,'space_id',p_space_id);
end;
$function$;

revoke all on function public.ordax_select_space_profile_pack_v1(uuid,uuid,text,integer)
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor;
revoke all on function public.ordax_clear_space_profile_pack_v1(uuid,uuid)
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_memory_executor,
       ordax_profile_pack_executor;

grant execute on function public.ordax_select_space_profile_pack_v1(uuid,uuid,text,integer)
  to ordax_profile_pack_executor;
grant execute on function public.ordax_clear_space_profile_pack_v1(uuid,uuid)
  to ordax_profile_pack_executor;

do $postflight$
declare
  bad_relations integer;
  bad_functions integer;
  bad_memberships integer;
begin
  if not exists (
    select 1 from pg_roles
    where rolname='ordax_profile_pack_executor'
      and not rolcanlogin and not rolinherit and not rolbypassrls
      and not rolsuper and not rolcreatedb and not rolcreaterole
      and not rolreplication
  ) then
    raise exception 'profile pack authority: role flags invalid';
  end if;
  if not has_schema_privilege('ordax_profile_pack_executor','public','USAGE')
     or has_schema_privilege('ordax_profile_pack_executor','public','CREATE')
     or has_schema_privilege('ordax_profile_pack_executor','private','USAGE') then
    raise exception 'profile pack authority: schema access invalid';
  end if;

  select count(*) into bad_relations
    from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname in ('public','private')
     and c.relkind in ('r','p','v','m','f','S')
     and (
       (c.relkind='S' and (
         has_sequence_privilege('ordax_profile_pack_executor',c.oid,'USAGE')
         or has_sequence_privilege('ordax_profile_pack_executor',c.oid,'SELECT')
         or has_sequence_privilege('ordax_profile_pack_executor',c.oid,'UPDATE')
       ))
       or
       (c.relkind<>'S' and (
         has_table_privilege('ordax_profile_pack_executor',c.oid,'SELECT')
         or has_table_privilege('ordax_profile_pack_executor',c.oid,'INSERT')
         or has_table_privilege('ordax_profile_pack_executor',c.oid,'UPDATE')
         or has_table_privilege('ordax_profile_pack_executor',c.oid,'DELETE')
       ))
     );
  if bad_relations<>0 then
    raise exception 'profile pack authority: direct table or sequence access';
  end if;

  select count(*) into bad_functions
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
   where n.nspname='public'
     and has_function_privilege('ordax_profile_pack_executor',p.oid,'EXECUTE')
     and p.oid not in (
       'public.ordax_select_space_profile_pack_v1(uuid,uuid,text,integer)'::regprocedure,
       'public.ordax_clear_space_profile_pack_v1(uuid,uuid)'::regprocedure
     );
  if bad_functions<>0 then
    raise exception 'profile pack authority: unexpected RPC access';
  end if;

  select count(*) into bad_memberships
    from pg_auth_members m
    join pg_roles granted on granted.oid=m.roleid
    join pg_roles member on member.oid=m.member
   where (granted.rolname='ordax_profile_pack_executor'
       or member.rolname='ordax_profile_pack_executor')
     and not (
       granted.rolname='ordax_profile_pack_executor'
       and member.rolname='postgres'
       and m.admin_option and not m.inherit_option and not m.set_option
     );
  if bad_memberships<>0 then
    raise exception 'profile pack authority: unexpected role membership';
  end if;
end;
$postflight$;

commit;
