begin;

alter table public.ordax_remote_capability_grants
  add column if not exists grant_group_id uuid,
  add column if not exists profile_key text;

update public.ordax_remote_capability_grants
   set grant_group_id = coalesce(grant_group_id, extensions.gen_random_uuid()),
       profile_key = coalesce(profile_key, 'legacy')
 where grant_group_id is null or profile_key is null;

alter table public.ordax_remote_capability_grants
  alter column grant_group_id set default extensions.gen_random_uuid(),
  alter column grant_group_id set not null,
  alter column profile_key set default 'legacy',
  alter column profile_key set not null;

alter table public.ordax_remote_capability_grants
  drop constraint if exists ordax_remote_capability_grants_profile_key_check,
  add constraint ordax_remote_capability_grants_profile_key_check
    check (
      char_length(profile_key) between 2 and 80
      and profile_key ~ '^[a-z][a-z0-9._-]+$'
    );

create index if not exists ordax_remote_grants_group_state_idx
  on public.ordax_remote_capability_grants(grant_group_id, state);

create index if not exists ordax_remote_grants_owner_client_profile_idx
  on public.ordax_remote_capability_grants(
    owner_user_id, device_id, client_kind, client_id, profile_key, state
  );

create or replace function public.ordax_replace_remote_grant_group_v1(
  p_owner_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_client_kind text,
  p_client_id text,
  p_profile_key text,
  p_capabilities text[],
  p_access_modes text[],
  p_valid_until timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_group_id uuid := extensions.gen_random_uuid();
  v_count integer;
  v_index integer;
  v_binding public.ordax_device_project_bindings%rowtype;
begin
  if p_owner_user_id is null
     or p_device_id is null
     or p_client_kind not in ('ordax-web','ordax-mobile','product-mcp')
     or (
       p_client_id is not null
       and (
         char_length(p_client_id) not between 8 and 160
         or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
       )
     )
     or p_profile_key is null
     or char_length(p_profile_key) not between 2 and 80
     or p_profile_key !~ '^[a-z][a-z0-9._-]+$'
     or p_capabilities is null
     or cardinality(p_capabilities) not between 1 and 128
     or p_access_modes is null
     or cardinality(p_access_modes) <> cardinality(p_capabilities)
     or (
       p_valid_until is not null
       and p_valid_until <= v_now
     )
  then
    return jsonb_build_object('ok', false, 'error', 'remote_grant_invalid');
  end if;

  if exists (
    select 1 from unnest(p_capabilities) item
    where item is null
       or char_length(item) not between 2 and 120
       or item !~ '^[a-z][a-z0-9.-]+$'
  ) or exists (
    select 1 from unnest(p_access_modes) item
    where item is null or item not in ('read','write')
  ) then
    return jsonb_build_object('ok', false, 'error', 'remote_grant_invalid');
  end if;

  select count(distinct item)
    into v_count
    from unnest(p_capabilities) item;
  if v_count <> cardinality(p_capabilities) then
    return jsonb_build_object('ok', false, 'error', 'remote_grant_duplicate_capability');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(
      p_owner_user_id::text || '|' ||
      p_device_id::text || '|' ||
      p_client_kind || '|' ||
      coalesce(p_client_id, '') || '|' ||
      p_profile_key || '|' ||
      coalesce(p_project_id::text, '')
    )
  );

  if p_project_id is null then
    if p_space_id is not null then
      return jsonb_build_object('ok', false, 'error', 'device_grant_space_not_allowed');
    end if;

    if not exists (
      select 1
      from public.ordax_product_devices d
      where d.device_id = p_device_id
        and d.owner_user_id = p_owner_user_id
        and d.state = 'active'
    ) then
      return jsonb_build_object('ok', false, 'error', 'device_not_owned');
    end if;
  else
    if p_space_id is null then
      return jsonb_build_object('ok', false, 'error', 'project_grant_space_required');
    end if;

    if not exists (
      select 1
      from public.ordax_spaces s
      where s.space_id = p_space_id
        and s.state = 'active'
        and (
          s.owner_user_id = p_owner_user_id
          or exists (
            select 1
            from public.ordax_space_members m
            where m.space_id = s.space_id
              and m.user_id = p_owner_user_id
              and m.state = 'active'
              and m.role in ('owner','admin')
          )
        )
    ) then
      return jsonb_build_object('ok', false, 'error', 'space_admin_required');
    end if;

    if not exists (
      select 1
      from public.ordax_projects p
      where p.project_id = p_project_id
        and p.space_id = p_space_id
        and p.state = 'active'
    ) then
      return jsonb_build_object('ok', false, 'error', 'project_not_found');
    end if;

    if not exists (
      select 1
      from public.ordax_space_devices sd
      where sd.space_id = p_space_id
        and sd.device_id = p_device_id
        and sd.state = 'active'
        and sd.access_mode = 'execute'
    ) then
      return jsonb_build_object('ok', false, 'error', 'space_device_execute_required');
    end if;

    select b.*
      into v_binding
      from public.ordax_device_project_bindings b
     where b.project_id = p_project_id
       and b.device_id = p_device_id
       and b.state = 'active'
     for update;

    if not found then
      return jsonb_build_object('ok', false, 'error', 'project_device_binding_required');
    end if;

    if exists (
      select 1
      from unnest(p_capabilities) capability
      where not (capability = any(v_binding.allowed_capabilities))
    ) then
      return jsonb_build_object('ok', false, 'error', 'capability_not_bound_to_project');
    end if;
  end if;

  update public.ordax_remote_capability_grants
     set state = 'revoked',
         updated_at = v_now
   where owner_user_id = p_owner_user_id
     and device_id = p_device_id
     and client_kind = p_client_kind
     and client_id is not distinct from p_client_id
     and profile_key = p_profile_key
     and space_id is not distinct from p_space_id
     and project_id is not distinct from p_project_id
     and state = 'active';

  for v_index in 1..cardinality(p_capabilities) loop
    insert into public.ordax_remote_capability_grants(
      grant_id,
      grant_group_id,
      profile_key,
      owner_user_id,
      space_id,
      project_id,
      device_id,
      client_kind,
      client_id,
      capability,
      access_mode,
      state,
      approved_by_user_id,
      valid_until,
      scope_kind,
      created_at,
      updated_at
    ) values (
      extensions.gen_random_uuid(),
      v_group_id,
      p_profile_key,
      p_owner_user_id,
      p_space_id,
      p_project_id,
      p_device_id,
      p_client_kind,
      p_client_id,
      p_capabilities[v_index],
      p_access_modes[v_index],
      'active',
      p_owner_user_id,
      p_valid_until,
      case when p_project_id is null then 'device' else 'project' end,
      v_now,
      v_now
    );
  end loop;

  return jsonb_build_object(
    'ok', true,
    'grant_group_id', v_group_id,
    'capability_count', cardinality(p_capabilities),
    'scope_kind', case when p_project_id is null then 'device' else 'project' end
  );
end;
$$;

create or replace function public.ordax_revoke_remote_grant_group_v1(
  p_owner_user_id uuid,
  p_grant_group_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_count integer;
begin
  if p_owner_user_id is null or p_grant_group_id is null then
    return jsonb_build_object('ok', false, 'error', 'remote_grant_revoke_invalid');
  end if;

  update public.ordax_remote_capability_grants
     set state = 'revoked',
         updated_at = pg_catalog.clock_timestamp()
   where owner_user_id = p_owner_user_id
     and grant_group_id = p_grant_group_id
     and state = 'active';

  get diagnostics v_count = row_count;
  if v_count = 0 then
    return jsonb_build_object('ok', false, 'error', 'remote_grant_group_not_found');
  end if;

  return jsonb_build_object(
    'ok', true,
    'grant_group_id', p_grant_group_id,
    'revoked_capabilities', v_count
  );
end;
$$;

create or replace function public.ordax_list_product_targets_v1(
  p_owner_user_id uuid,
  p_client_kind text,
  p_client_id text
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  with active as (
    select
      g.grant_group_id,
      g.profile_key,
      g.device_id,
      g.space_id,
      g.project_id,
      g.capability,
      g.access_mode,
      g.valid_until
    from public.ordax_remote_capability_grants g
    join public.ordax_product_devices d
      on d.device_id = g.device_id
     and d.state = 'active'
    where g.owner_user_id = p_owner_user_id
      and g.client_kind = p_client_kind
      and g.client_id is not distinct from p_client_id
      and g.state = 'active'
      and (g.valid_until is null or g.valid_until > pg_catalog.clock_timestamp())
  ),
  grant_groups as (
    select
      a.device_id,
      a.grant_group_id,
      a.profile_key,
      a.space_id,
      a.project_id,
      max(a.valid_until) as valid_until,
      jsonb_agg(
        jsonb_build_object(
          'capability', a.capability,
          'access_mode', a.access_mode
        )
        order by a.capability
      ) as capabilities
    from active a
    group by
      a.device_id,
      a.grant_group_id,
      a.profile_key,
      a.space_id,
      a.project_id
  ),
  targets as (
    select
      d.device_id,
      d.display_name,
      d.device_kind,
      d.channel,
      coalesce(p.online, false) as online,
      p.last_seen_at,
      jsonb_agg(
        jsonb_build_object(
          'grant_group_id', gg.grant_group_id,
          'profile_key', gg.profile_key,
          'space_id', gg.space_id,
          'project_id', gg.project_id,
          'valid_until', gg.valid_until,
          'capabilities', gg.capabilities
        )
        order by gg.profile_key, gg.grant_group_id
      ) as grant_groups
    from grant_groups gg
    join public.ordax_product_devices d on d.device_id = gg.device_id
    left join public.ordax_device_presence p on p.device_id = d.device_id
    group by
      d.device_id,
      d.display_name,
      d.device_kind,
      d.channel,
      p.online,
      p.last_seen_at
  )
  select jsonb_build_object(
    'ok', true,
    'targets', coalesce(
      jsonb_agg(
        jsonb_build_object(
          'device_id', t.device_id,
          'device_name', t.display_name,
          'device_kind', t.device_kind,
          'channel', t.channel,
          'online', t.online,
          'last_seen_at', t.last_seen_at,
          'grant_groups', t.grant_groups
        )
        order by t.display_name, t.device_id
      ),
      '[]'::jsonb
    )
  )
  from targets t;
$$;

revoke all on function public.ordax_replace_remote_grant_group_v1(
  uuid, uuid, uuid, uuid, text, text, text, text[], text[], timestamptz
) from public, anon, authenticated;
revoke all on function public.ordax_revoke_remote_grant_group_v1(
  uuid, uuid
) from public, anon, authenticated;
revoke all on function public.ordax_list_product_targets_v1(
  uuid, text, text
) from public, anon, authenticated;

grant execute on function public.ordax_replace_remote_grant_group_v1(
  uuid, uuid, uuid, uuid, text, text, text, text[], text[], timestamptz
) to service_role;
grant execute on function public.ordax_revoke_remote_grant_group_v1(
  uuid, uuid
) to service_role;
grant execute on function public.ordax_list_product_targets_v1(
  uuid, text, text
) to service_role;

commit;
