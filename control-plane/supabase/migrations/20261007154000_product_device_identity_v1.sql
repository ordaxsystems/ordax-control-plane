begin;

-- Product-owned Computer Control must not require a synthetic Space or Project.
-- Project-scoped remote authority still requires both a real Space and Project.

alter table public.ordax_remote_capability_grants
  alter column space_id drop not null,
  drop constraint if exists ordax_remote_capability_grants_scope_shape_check;

alter table public.ordax_remote_capability_grants
  add constraint ordax_remote_capability_grants_scope_shape_check
  check (
    (
      scope_kind = 'device'
      and project_id is null
    )
    or
    (
      scope_kind = 'project'
      and project_id is not null
      and space_id is not null
    )
  );

alter table private.ordax_product_action_requests
  alter column space_id drop not null;

create table if not exists private.ordax_product_device_credentials (
  device_id uuid primary key
    references public.ordax_product_devices(device_id) on delete cascade,
  token_sha256 text not null unique
    check (token_sha256 ~ '^[0-9a-f]{64}$'),
  machine_binding_sha256 text not null unique
    check (machine_binding_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default timezone('utc', now()),
  last_enrolled_at timestamptz not null default timezone('utc', now()),
  enrollment_window_started_at timestamptz not null default timezone('utc', now()),
  enrollment_count integer not null default 1
    check (enrollment_count between 0 and 1000),
  revoked_at timestamptz
);

comment on table private.ordax_product_device_credentials is
  'Server-only Product device credential hashes. Raw device tokens are never persisted. This authority is separate from engineering credentials.';

alter table private.ordax_product_device_credentials enable row level security;
revoke all on table private.ordax_product_device_credentials
  from public, anon, authenticated, service_role;

create or replace function private.ordax_resolve_product_remote_grant_v1(
  p_owner_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_client_kind text,
  p_capability text,
  p_access_mode text
)
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select g.grant_id
  from public.ordax_remote_capability_grants g
  join public.ordax_product_devices d
    on d.device_id = g.device_id
   and d.state = 'active'
  left join public.ordax_space_devices sd
    on sd.space_id = g.space_id
   and sd.device_id = g.device_id
  left join public.ordax_projects p
    on p.project_id = g.project_id
   and p.space_id = g.space_id
  left join public.ordax_device_project_bindings b
    on b.project_id = g.project_id
   and b.device_id = g.device_id
  where g.owner_user_id = p_owner_user_id
    and g.device_id = p_device_id
    and g.client_kind = p_client_kind
    and g.capability = p_capability
    and g.access_mode = p_access_mode
    and g.state = 'active'
    and g.space_id is not distinct from p_space_id
    and (g.valid_until is null or g.valid_until > pg_catalog.clock_timestamp())
    and (
      (
        g.scope_kind = 'device'
        and g.project_id is null
        and p_project_id is null
        and d.owner_user_id = p_owner_user_id
      )
      or
      (
        g.scope_kind = 'project'
        and p_space_id is not null
        and g.project_id = p_project_id
        and p.project_id is not null
        and sd.state = 'active'
        and sd.access_mode = 'execute'
        and b.state = 'active'
        and p_capability = any(b.allowed_capabilities)
      )
    )
  order by g.valid_until desc nulls first, g.created_at desc
  limit 1;
$$;

create or replace function public.ordax_enqueue_product_action_v1(
  p_owner_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_client_kind text,
  p_capability text,
  p_access_mode text,
  p_payload jsonb,
  p_idempotency_key text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_grant_id uuid;
  v_payload_sha256 text;
  v_existing private.ordax_product_action_requests%rowtype;
  v_request_id uuid;
  v_effect_id uuid;
begin
  if p_owner_user_id is null
     or p_device_id is null
     or p_client_kind not in ('ordax-web','ordax-mobile','product-mcp')
     or p_access_mode not in ('read','write')
     or p_capability is null
     or char_length(p_capability) not between 2 and 120
     or p_capability !~ '^[a-z][a-z0-9.-]+$'
     or p_payload is null
     or jsonb_typeof(p_payload) <> 'object'
     or pg_catalog.octet_length(p_payload::text) > 131072
     or p_idempotency_key is null
     or char_length(p_idempotency_key) not between 8 and 128
     or p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
     or p_expires_at is null
     or p_expires_at <= v_now
     or p_expires_at > v_now + interval '24 hours'
  then
    return jsonb_build_object('ok', false, 'error', 'product_action_invalid');
  end if;

  v_payload_sha256 := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_payload::text, 'UTF8'), 'sha256'),
    'hex'
  );

  select *
    into v_existing
    from private.ordax_product_action_requests
   where owner_user_id = p_owner_user_id
     and idempotency_key = p_idempotency_key
   limit 1;

  if found then
    if v_existing.space_id is not distinct from p_space_id
       and v_existing.project_id is not distinct from p_project_id
       and v_existing.device_id = p_device_id
       and v_existing.client_kind = p_client_kind
       and v_existing.capability = p_capability
       and v_existing.access_mode = p_access_mode
       and v_existing.payload_sha256 = v_payload_sha256
    then
      return jsonb_build_object(
        'ok', true,
        'replayed', true,
        'request_id', v_existing.request_id,
        'effect_id', v_existing.effect_id,
        'status', v_existing.status
      );
    end if;

    insert into private.ordax_product_action_audit(
      request_id, owner_user_id, space_id, project_id, device_id, grant_id,
      client_kind, capability, access_mode, phase, decision, reason
    ) values (
      v_existing.request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id,
      v_existing.grant_id, p_client_kind, p_capability, p_access_mode,
      'decision', 'deny', 'idempotency_conflict'
    );

    return jsonb_build_object('ok', false, 'error', 'idempotency_conflict');
  end if;

  v_grant_id := private.ordax_resolve_product_remote_grant_v1(
    p_owner_user_id,
    p_space_id,
    p_project_id,
    p_device_id,
    p_client_kind,
    p_capability,
    p_access_mode
  );

  if v_grant_id is null then
    insert into private.ordax_product_action_audit(
      owner_user_id, space_id, project_id, device_id, client_kind,
      capability, access_mode, phase, decision, reason
    ) values (
      p_owner_user_id, p_space_id, p_project_id, p_device_id, p_client_kind,
      p_capability, p_access_mode, 'decision', 'deny', 'product_grant_not_resolved'
    );

    return jsonb_build_object('ok', false, 'error', 'product_grant_not_resolved');
  end if;

  v_request_id := extensions.gen_random_uuid();
  v_effect_id := extensions.gen_random_uuid();

  insert into private.ordax_product_action_requests(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, payload, payload_sha256,
    idempotency_key, effect_id, status, expires_at
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_capability, p_access_mode, p_payload, v_payload_sha256,
    p_idempotency_key, v_effect_id, 'queued', p_expires_at
  );

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, phase, decision, reason
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_capability, p_access_mode, 'decision', 'allow', 'grant_resolved'
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'request_id', v_request_id,
    'effect_id', v_effect_id,
    'status', 'queued'
  );
end;
$$;

create or replace function public.ordax_enroll_product_device_v1(
  p_owner_user_id uuid,
  p_device_name text,
  p_device_kind text,
  p_channel text,
  p_token_sha256 text,
  p_machine_binding_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_device public.ordax_product_devices%rowtype;
  v_credential private.ordax_product_device_credentials%rowtype;
  v_device_id uuid;
  v_same_window boolean;
  v_next_count integer;
begin
  if p_owner_user_id is null
     or p_device_name is null
     or char_length(btrim(p_device_name)) not between 1 and 120
     or p_device_name ~ '[[:cntrl:]]'
     or p_device_kind not in ('desktop','laptop','mobile','server','other')
     or p_channel not in ('stable','development')
     or p_token_sha256 is null
     or p_token_sha256 !~ '^[0-9a-f]{64}$'
     or p_machine_binding_sha256 is null
     or p_machine_binding_sha256 !~ '^[0-9a-f]{64}$'
  then
    return jsonb_build_object('ok', false, 'error', 'device_enrollment_invalid');
  end if;

  if not exists (select 1 from auth.users u where u.id = p_owner_user_id) then
    return jsonb_build_object('ok', false, 'error', 'device_owner_not_found');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_machine_binding_sha256)
  );

  select d.*, c.*
    into v_device, v_credential
    from private.ordax_product_device_credentials c
    join public.ordax_product_devices d on d.device_id = c.device_id
   where c.machine_binding_sha256 = p_machine_binding_sha256
   for update of c, d;

  if found then
    if v_device.owner_user_id <> p_owner_user_id then
      return jsonb_build_object('ok', false, 'error', 'device_owner_mismatch');
    end if;

    if exists (
      select 1
      from private.ordax_product_device_credentials other
      where other.token_sha256 = p_token_sha256
        and other.device_id <> v_device.device_id
    ) then
      return jsonb_build_object('ok', false, 'error', 'device_credential_conflict');
    end if;

    v_same_window := (
      v_credential.enrollment_window_started_at > v_now - interval '1 hour'
    );
    v_next_count := case
      when v_same_window then v_credential.enrollment_count + 1
      else 1
    end;

    if v_next_count > 10 then
      return jsonb_build_object('ok', false, 'error', 'enrollment_rate_limited');
    end if;

    update public.ordax_product_devices
       set display_name = btrim(p_device_name),
           device_kind = p_device_kind,
           channel = p_channel,
           state = 'active'
     where device_id = v_device.device_id;

    update private.ordax_product_device_credentials
       set token_sha256 = p_token_sha256,
           revoked_at = null,
           last_enrolled_at = v_now,
           enrollment_window_started_at = case
             when v_same_window then enrollment_window_started_at
             else v_now
           end,
           enrollment_count = v_next_count
     where device_id = v_device.device_id;

    return jsonb_build_object(
      'ok', true,
      'replayed', true,
      'protocol', 'cloudflare-v3',
      'device_id', v_device.device_id
    );
  end if;

  if exists (
    select 1
    from private.ordax_product_device_credentials c
    where c.token_sha256 = p_token_sha256
  ) then
    return jsonb_build_object('ok', false, 'error', 'device_credential_conflict');
  end if;

  v_device_id := extensions.gen_random_uuid();

  insert into public.ordax_product_devices(
    device_id, owner_user_id, device_public_id, display_name,
    device_kind, channel, state
  ) values (
    v_device_id, p_owner_user_id, v_device_id::text, btrim(p_device_name),
    p_device_kind, p_channel, 'active'
  );

  insert into private.ordax_product_device_credentials(
    device_id, token_sha256, machine_binding_sha256,
    created_at, last_enrolled_at, enrollment_window_started_at, enrollment_count
  ) values (
    v_device_id, p_token_sha256, p_machine_binding_sha256,
    v_now, v_now, v_now, 1
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'protocol', 'cloudflare-v3',
    'device_id', v_device_id
  );
end;
$$;

create or replace function public.ordax_identify_product_device_v1(
  p_token_sha256 text,
  p_machine_binding_sha256 text
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when d.device_id is null then
      jsonb_build_object('ok', false, 'error', 'device_token_invalid')
    else
      jsonb_build_object(
        'ok', true,
        'protocol', 'cloudflare-v3',
        'device_id', d.device_id
      )
    end
  from (select 1) seed
  left join lateral (
    select d.device_id
    from private.ordax_product_device_credentials c
    join public.ordax_product_devices d on d.device_id = c.device_id
    where c.token_sha256 = p_token_sha256
      and c.machine_binding_sha256 = p_machine_binding_sha256
      and c.revoked_at is null
      and d.state = 'active'
    limit 1
  ) d on true;
$$;

create or replace function public.ordax_authenticate_product_device_v1(
  p_device_id uuid,
  p_token_sha256 text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.ordax_product_device_credentials c
    join public.ordax_product_devices d on d.device_id = c.device_id
    where c.device_id = p_device_id
      and c.token_sha256 = p_token_sha256
      and c.revoked_at is null
      and d.state = 'active'
  );
$$;

create or replace function public.ordax_import_legacy_product_device_v1(
  p_device_id uuid,
  p_owner_user_id uuid,
  p_display_name text,
  p_device_kind text,
  p_channel text,
  p_token_sha256 text,
  p_machine_binding_sha256 text,
  p_last_seen_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_existing_owner uuid;
begin
  if p_device_id is null
     or p_owner_user_id is null
     or p_display_name is null
     or char_length(btrim(p_display_name)) not between 1 and 120
     or p_display_name ~ '[[:cntrl:]]'
     or p_device_kind not in ('desktop','laptop','mobile','server','other')
     or p_channel not in ('stable','development')
     or p_token_sha256 is null
     or p_token_sha256 !~ '^[0-9a-f]{64}$'
     or p_machine_binding_sha256 is null
     or p_machine_binding_sha256 !~ '^[0-9a-f]{64}$'
  then
    return jsonb_build_object('ok', false, 'error', 'legacy_device_invalid');
  end if;

  if not exists (select 1 from auth.users u where u.id = p_owner_user_id) then
    return jsonb_build_object('ok', false, 'error', 'device_owner_not_found');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_machine_binding_sha256)
  );

  select d.owner_user_id
    into v_existing_owner
    from public.ordax_product_devices d
   where d.device_id = p_device_id
   for update;

  if found and v_existing_owner <> p_owner_user_id then
    return jsonb_build_object('ok', false, 'error', 'device_owner_mismatch');
  end if;

  if exists (
    select 1
    from private.ordax_product_device_credentials c
    where (c.token_sha256 = p_token_sha256
           or c.machine_binding_sha256 = p_machine_binding_sha256)
      and c.device_id <> p_device_id
  ) then
    return jsonb_build_object('ok', false, 'error', 'device_credential_conflict');
  end if;

  insert into public.ordax_product_devices(
    device_id, owner_user_id, device_public_id, display_name,
    device_kind, channel, state, created_at, updated_at
  ) values (
    p_device_id, p_owner_user_id, p_device_id::text, btrim(p_display_name),
    p_device_kind, p_channel, 'active', v_now, v_now
  )
  on conflict (device_id) do update
    set display_name = excluded.display_name,
        device_kind = excluded.device_kind,
        channel = excluded.channel,
        state = 'active',
        updated_at = v_now
    where public.ordax_product_devices.owner_user_id = excluded.owner_user_id;

  insert into private.ordax_product_device_credentials(
    device_id, token_sha256, machine_binding_sha256,
    created_at, last_enrolled_at, enrollment_window_started_at,
    enrollment_count, revoked_at
  ) values (
    p_device_id, p_token_sha256, p_machine_binding_sha256,
    v_now, v_now, v_now, 1, null
  )
  on conflict (device_id) do update
    set token_sha256 = excluded.token_sha256,
        machine_binding_sha256 = excluded.machine_binding_sha256,
        last_enrolled_at = v_now,
        enrollment_window_started_at = v_now,
        enrollment_count = 1,
        revoked_at = null;

  if p_last_seen_at is not null then
    insert into public.ordax_device_presence(
      device_id, online, runtime_kind, last_seen_at, observed_at
    ) values (
      p_device_id, false, 'desktop-agent', p_last_seen_at, v_now
    )
    on conflict (device_id) do update
      set last_seen_at = excluded.last_seen_at,
          observed_at = v_now;
  end if;

  return jsonb_build_object(
    'ok', true,
    'protocol', 'cloudflare-v3',
    'device_id', p_device_id
  );
end;
$$;

revoke all on function public.ordax_enroll_product_device_v1(
  uuid, text, text, text, text, text
) from public, anon, authenticated;
revoke all on function public.ordax_identify_product_device_v1(
  text, text
) from public, anon, authenticated;
revoke all on function public.ordax_authenticate_product_device_v1(
  uuid, text
) from public, anon, authenticated;
revoke all on function public.ordax_import_legacy_product_device_v1(
  uuid, uuid, text, text, text, text, text, timestamptz
) from public, anon, authenticated;

grant execute on function public.ordax_enroll_product_device_v1(
  uuid, text, text, text, text, text
) to service_role;
grant execute on function public.ordax_identify_product_device_v1(
  text, text
) to service_role;
grant execute on function public.ordax_authenticate_product_device_v1(
  uuid, text
) to service_role;
grant execute on function public.ordax_import_legacy_product_device_v1(
  uuid, uuid, text, text, text, text, text, timestamptz
) to service_role;

commit;
