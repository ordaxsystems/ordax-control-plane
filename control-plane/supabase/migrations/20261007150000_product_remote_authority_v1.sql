begin;

-- Canonical product-remote persistence for ORDAX.
-- Cloudflare remains the edge/session transport; PostgreSQL is the durable source of truth.
-- This migration deliberately does NOT reuse the engineering ordax_develop_* queue.

alter table public.ordax_remote_capability_grants
  add column if not exists scope_kind text;

update public.ordax_remote_capability_grants
set scope_kind = 'project'
where scope_kind is null;

alter table public.ordax_remote_capability_grants
  alter column scope_kind set default 'project',
  alter column scope_kind set not null,
  drop constraint if exists ordax_remote_capability_grants_project_id_space_id_fkey,
  alter column project_id drop not null;

alter table public.ordax_remote_capability_grants
  add constraint ordax_remote_capability_grants_scope_kind_check
    check (scope_kind in ('device','project')),
  add constraint ordax_remote_capability_grants_scope_shape_check
    check (
      (scope_kind = 'device' and project_id is null)
      or
      (scope_kind = 'project' and project_id is not null)
    ),
  add constraint ordax_remote_capability_grants_project_id_space_id_fkey
    foreign key (project_id, space_id)
    references public.ordax_projects(project_id, space_id)
    on delete cascade;

comment on column public.ordax_remote_capability_grants.scope_kind is
  'Explicit remote authority scope. Device-scoped grants never require a synthetic project; project-scoped grants require a real project_id.';

create index if not exists ordax_remote_grants_device_scope_active_idx
  on public.ordax_remote_capability_grants
    (device_id, owner_user_id, client_kind, capability, access_mode, state)
  where scope_kind = 'device';

create index if not exists ordax_remote_grants_project_scope_active_idx
  on public.ordax_remote_capability_grants
    (project_id, device_id, owner_user_id, client_kind, capability, access_mode, state)
  where scope_kind = 'project';

create table if not exists private.ordax_product_action_requests (
  request_id uuid primary key default extensions.gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  space_id uuid not null references public.ordax_spaces(space_id) on delete cascade,
  project_id uuid references public.ordax_projects(project_id) on delete cascade,
  device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
  grant_id uuid references public.ordax_remote_capability_grants(grant_id) on delete set null,
  client_kind text not null
    check (client_kind in ('ordax-web','ordax-mobile','product-mcp')),
  capability text not null
    check (
      char_length(capability) between 2 and 120
      and capability ~ '^[a-z][a-z0-9.-]+$'
    ),
  access_mode text not null
    check (access_mode in ('read','write')),
  payload jsonb not null default '{}'::jsonb
    check (jsonb_typeof(payload) = 'object'),
  payload_sha256 text not null
    check (payload_sha256 ~ '^[0-9a-f]{64}$'),
  idempotency_key text not null
    check (
      char_length(idempotency_key) between 8 and 128
      and idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    ),
  effect_id uuid not null default extensions.gen_random_uuid(),
  status text not null default 'queued'
    check (status in ('queued','leased','running','succeeded','failed','cancelled')),
  attempt_id uuid,
  lease_id uuid,
  execution_epoch bigint not null default 0
    check (execution_epoch >= 0),
  agent_instance_id uuid,
  boot_id text
    check (boot_id is null or char_length(boot_id) between 8 and 160),
  lease_expires_at timestamptz,
  expires_at timestamptz not null,
  report_id uuid,
  result jsonb,
  result_sha256 text
    check (result_sha256 is null or result_sha256 ~ '^[0-9a-f]{64}$'),
  error_code text
    check (error_code is null or char_length(error_code) between 1 and 120),
  created_at timestamptz not null default timezone('utc', now()),
  started_at timestamptz,
  finished_at timestamptz,
  unique (owner_user_id, idempotency_key),
  unique (effect_id),
  unique (report_id),
  check (
    (project_id is null)
    or exists (
      select 1
      from public.ordax_projects p
      where p.project_id = project_id and p.space_id = space_id
    )
  )
);

comment on table private.ordax_product_action_requests is
  'Canonical Product MCP/Web/Mobile remote-action queue. Separate from engineering ordax_develop_jobs and never directly exposed to clients.';

create index if not exists ordax_product_action_device_status_created_idx
  on private.ordax_product_action_requests(device_id, status, created_at);

create index if not exists ordax_product_action_owner_status_created_idx
  on private.ordax_product_action_requests(owner_user_id, status, created_at desc);

create index if not exists ordax_product_action_lease_idx
  on private.ordax_product_action_requests(device_id, lease_expires_at)
  where status in ('leased','running');

create table if not exists private.ordax_product_action_events (
  event_id bigint generated always as identity primary key,
  request_id uuid not null
    references private.ordax_product_action_requests(request_id) on delete cascade,
  stage text not null check (char_length(stage) between 1 and 96),
  message text check (message is null or char_length(message) <= 512),
  progress_percent smallint check (progress_percent is null or progress_percent between 0 and 100),
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists ordax_product_action_events_request_idx
  on private.ordax_product_action_events(request_id, event_id);

create table if not exists private.ordax_product_action_audit (
  audit_id uuid primary key default extensions.gen_random_uuid(),
  request_id uuid,
  owner_user_id uuid,
  space_id uuid,
  project_id uuid,
  device_id uuid,
  grant_id uuid,
  client_kind text,
  capability text,
  access_mode text,
  phase text not null check (phase in ('decision','result')),
  decision text not null check (decision in ('allow','deny')),
  reason text not null check (char_length(reason) between 1 and 160),
  result_ok boolean,
  created_at timestamptz not null default timezone('utc', now())
);

comment on table private.ordax_product_action_audit is
  'Append-only remote authorization/result audit. UUID references are intentionally snapshots so audit evidence can outlive mutable product rows.';

create index if not exists ordax_product_action_audit_owner_created_idx
  on private.ordax_product_action_audit(owner_user_id, created_at desc);

create index if not exists ordax_product_action_audit_request_idx
  on private.ordax_product_action_audit(request_id, created_at);

revoke all on table private.ordax_product_action_requests
  from public, anon, authenticated, service_role;
revoke all on table private.ordax_product_action_events
  from public, anon, authenticated, service_role;
revoke all on table private.ordax_product_action_audit
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
  join public.ordax_space_devices sd
    on sd.space_id = g.space_id
   and sd.device_id = g.device_id
   and sd.state = 'active'
   and sd.access_mode = 'execute'
  left join public.ordax_projects p
    on p.project_id = g.project_id
   and p.space_id = g.space_id
   and p.state = 'active'
  left join public.ordax_device_project_bindings b
    on b.project_id = g.project_id
   and b.device_id = g.device_id
   and b.state = 'active'
  where g.owner_user_id = p_owner_user_id
    and g.space_id = p_space_id
    and g.device_id = p_device_id
    and g.client_kind = p_client_kind
    and g.capability = p_capability
    and g.access_mode = p_access_mode
    and g.state = 'active'
    and (g.valid_until is null or g.valid_until > pg_catalog.clock_timestamp())
    and (
      (
        g.scope_kind = 'device'
        and g.project_id is null
        and p_project_id is null
      )
      or
      (
        g.scope_kind = 'project'
        and g.project_id = p_project_id
        and p.project_id is not null
        and b.binding_id is not null
        and p_capability = any(b.allowed_capabilities)
      )
    )
  order by g.valid_until desc nulls first, g.created_at desc
  limit 1;
$$;

revoke all on function private.ordax_resolve_product_remote_grant_v1(
  uuid, uuid, uuid, uuid, text, text, text
) from public, anon, authenticated, service_role;

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
     or p_space_id is null
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
    if v_existing.space_id = p_space_id
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

create or replace function public.ordax_claim_product_action_v1(
  p_device_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_lease_seconds integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_job private.ordax_product_action_requests%rowtype;
  v_attempt_id uuid;
  v_lease_id uuid;
  v_lease_expires_at timestamptz;
begin
  if p_device_id is null
     or p_agent_instance_id is null
     or p_boot_id is null
     or char_length(p_boot_id) not between 8 and 160
     or p_lease_seconds not between 30 and 300
  then
    return jsonb_build_object('ok', false, 'error', 'claim_invalid');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_device_id::text));

  if exists (
    select 1
      from private.ordax_product_action_requests r
     where r.device_id = p_device_id
       and (
         r.status = 'running'
         or (r.status = 'leased' and r.lease_expires_at >= v_now)
       )
  ) then
    return jsonb_build_object('ok', true, 'job', null);
  end if;

  select *
    into v_job
    from private.ordax_product_action_requests r
   where r.device_id = p_device_id
     and r.expires_at > v_now
     and (
       r.status = 'queued'
       or (r.status = 'leased' and r.lease_expires_at < v_now)
     )
   order by r.created_at asc
   for update skip locked
   limit 1;

  if not found then
    return jsonb_build_object('ok', true, 'job', null);
  end if;

  v_attempt_id := extensions.gen_random_uuid();
  v_lease_id := extensions.gen_random_uuid();
  v_lease_expires_at := v_now + pg_catalog.make_interval(secs => p_lease_seconds);

  update private.ordax_product_action_requests
     set status = 'leased',
         attempt_id = v_attempt_id,
         lease_id = v_lease_id,
         execution_epoch = execution_epoch + 1,
         agent_instance_id = p_agent_instance_id,
         boot_id = p_boot_id,
         lease_expires_at = v_lease_expires_at
   where request_id = v_job.request_id
   returning * into v_job;

  return jsonb_build_object(
    'ok', true,
    'job', jsonb_build_object(
      'request_id', v_job.request_id,
      'device_id', v_job.device_id,
      'project_id', v_job.project_id,
      'capability', v_job.capability,
      'payload', v_job.payload,
      'payload_sha256', v_job.payload_sha256,
      'effect_id', v_job.effect_id,
      'attempt_id', v_job.attempt_id,
      'lease_id', v_job.lease_id,
      'execution_epoch', v_job.execution_epoch,
      'agent_instance_id', v_job.agent_instance_id,
      'boot_id', v_job.boot_id,
      'lease_expires_at', v_job.lease_expires_at
    )
  );
end;
$$;

create or replace function public.ordax_start_product_action_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  update private.ordax_product_action_requests
     set status = 'running',
         started_at = coalesce(started_at, pg_catalog.clock_timestamp())
   where request_id = p_request_id
     and device_id = p_device_id
     and effect_id = p_effect_id
     and attempt_id = p_attempt_id
     and lease_id = p_lease_id
     and execution_epoch = p_execution_epoch
     and agent_instance_id = p_agent_instance_id
     and boot_id = p_boot_id
     and status in ('leased','running')
     and report_id is null
     and lease_expires_at >= pg_catalog.clock_timestamp();

  return found;
end;
$$;

create or replace function public.ordax_renew_product_action_lease_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_lease_seconds integer default 120
)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_until timestamptz;
begin
  if p_lease_seconds not between 30 and 300 then
    return null;
  end if;

  v_until := pg_catalog.clock_timestamp() + pg_catalog.make_interval(secs => p_lease_seconds);

  update private.ordax_product_action_requests
     set lease_expires_at = v_until
   where request_id = p_request_id
     and device_id = p_device_id
     and effect_id = p_effect_id
     and attempt_id = p_attempt_id
     and lease_id = p_lease_id
     and execution_epoch = p_execution_epoch
     and agent_instance_id = p_agent_instance_id
     and boot_id = p_boot_id
     and status in ('leased','running')
     and report_id is null;

  if not found then
    return null;
  end if;
  return v_until;
end;
$$;

create or replace function public.ordax_progress_product_action_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_stage text,
  p_message text,
  p_progress_percent smallint
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_stage is null
     or char_length(p_stage) not between 1 and 96
     or (p_message is not null and char_length(p_message) > 512)
     or (p_progress_percent is not null and p_progress_percent not between 0 and 100)
  then
    return false;
  end if;

  if not exists (
    select 1
      from private.ordax_product_action_requests r
     where r.request_id = p_request_id
       and r.device_id = p_device_id
       and r.effect_id = p_effect_id
       and r.attempt_id = p_attempt_id
       and r.lease_id = p_lease_id
       and r.execution_epoch = p_execution_epoch
       and r.agent_instance_id = p_agent_instance_id
       and r.boot_id = p_boot_id
       and r.status in ('leased','running')
       and r.report_id is null
  ) then
    return false;
  end if;

  insert into private.ordax_product_action_events(
    request_id, stage, message, progress_percent
  ) values (
    p_request_id, p_stage, p_message, p_progress_percent
  );
  return true;
end;
$$;

create or replace function public.ordax_report_product_action_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_report_id uuid,
  p_status text,
  p_result jsonb,
  p_result_sha256 text,
  p_error_code text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row private.ordax_product_action_requests%rowtype;
  v_observed_sha256 text;
begin
  if p_status not in ('succeeded','failed','cancelled')
     or p_result is null
     or pg_catalog.octet_length(p_result::text) > 524288
     or p_result_sha256 is null
     or p_result_sha256 !~ '^[0-9a-f]{64}$'
     or (p_error_code is not null and char_length(p_error_code) > 120)
  then
    return jsonb_build_object('ok', false, 'error', 'report_invalid');
  end if;

  v_observed_sha256 := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_result::text, 'UTF8'), 'sha256'),
    'hex'
  );
  if v_observed_sha256 <> pg_catalog.lower(p_result_sha256) then
    return jsonb_build_object('ok', false, 'error', 'result_digest_mismatch');
  end if;

  select *
    into v_row
    from private.ordax_product_action_requests
   where request_id = p_request_id
     and device_id = p_device_id
   for update;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'product_action_not_found');
  end if;

  if v_row.status in ('succeeded','failed','cancelled') then
    if v_row.effect_id = p_effect_id
       and v_row.attempt_id = p_attempt_id
       and v_row.lease_id = p_lease_id
       and v_row.execution_epoch = p_execution_epoch
       and v_row.agent_instance_id = p_agent_instance_id
       and v_row.boot_id = p_boot_id
       and v_row.report_id = p_report_id
       and v_row.status = p_status
       and v_row.result_sha256 = pg_catalog.lower(p_result_sha256)
       and v_row.result = p_result
       and v_row.error_code is not distinct from p_error_code
    then
      return jsonb_build_object('ok', true, 'replayed', true, 'status', v_row.status);
    end if;
    return jsonb_build_object('ok', false, 'error', 'terminal_report_conflict');
  end if;

  if v_row.effect_id <> p_effect_id
     or v_row.attempt_id <> p_attempt_id
     or v_row.lease_id <> p_lease_id
     or v_row.execution_epoch <> p_execution_epoch
     or v_row.agent_instance_id <> p_agent_instance_id
     or v_row.boot_id <> p_boot_id
     or v_row.status not in ('leased','running')
     or v_row.report_id is not null
  then
    return jsonb_build_object('ok', false, 'error', 'lease_not_active');
  end if;

  update private.ordax_product_action_requests
     set status = p_status,
         report_id = p_report_id,
         result = p_result,
         result_sha256 = pg_catalog.lower(p_result_sha256),
         error_code = p_error_code,
         finished_at = v_now,
         lease_expires_at = null
   where request_id = p_request_id;

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, phase, decision, reason, result_ok
  ) values (
    v_row.request_id, v_row.owner_user_id, v_row.space_id, v_row.project_id,
    v_row.device_id, v_row.grant_id, v_row.client_kind, v_row.capability,
    v_row.access_mode, 'result', 'allow', 'terminal_report_committed',
    p_status = 'succeeded'
  );

  return jsonb_build_object('ok', true, 'replayed', false, 'status', p_status);
end;
$$;

create or replace function public.ordax_get_product_action_v1(
  p_owner_user_id uuid,
  p_request_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'ok', true,
    'request_id', r.request_id,
    'device_id', r.device_id,
    'project_id', r.project_id,
    'capability', r.capability,
    'status', r.status,
    'effect_id', r.effect_id,
    'result', r.result,
    'error_code', r.error_code,
    'created_at', r.created_at,
    'started_at', r.started_at,
    'finished_at', r.finished_at
  )
  from private.ordax_product_action_requests r
  where r.owner_user_id = p_owner_user_id
    and r.request_id = p_request_id;
$$;

create or replace function public.ordax_record_product_presence_v1(
  p_device_id uuid,
  p_online boolean,
  p_runtime_kind text,
  p_agent_version text,
  p_capability_digest text,
  p_force boolean default false
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_current public.ordax_device_presence%rowtype;
begin
  if p_device_id is null
     or p_online is null
     or (
       p_runtime_kind is not null
       and p_runtime_kind not in ('ordax-os','desktop-agent','mobile-client','other')
     )
     or (p_agent_version is not null and char_length(p_agent_version) not between 1 and 80)
     or (
       p_capability_digest is not null
       and p_capability_digest !~ '^[0-9a-f]{64}$'
     )
  then
    return false;
  end if;

  select *
    into v_current
    from public.ordax_device_presence
   where device_id = p_device_id
   for update;

  if not found then
    insert into public.ordax_device_presence(
      device_id, online, runtime_kind, agent_version, capability_digest,
      last_seen_at, observed_at
    ) values (
      p_device_id, p_online, p_runtime_kind, p_agent_version, p_capability_digest,
      case when p_online then v_now else null end,
      v_now
    );
    return true;
  end if;

  if not p_force
     and v_current.online = p_online
     and v_current.runtime_kind is not distinct from p_runtime_kind
     and v_current.agent_version is not distinct from p_agent_version
     and v_current.capability_digest is not distinct from p_capability_digest
     and v_current.observed_at > v_now - interval '5 minutes'
  then
    return false;
  end if;

  update public.ordax_device_presence
     set online = p_online,
         runtime_kind = p_runtime_kind,
         agent_version = p_agent_version,
         capability_digest = p_capability_digest,
         last_seen_at = case when p_online then v_now else last_seen_at end,
         observed_at = v_now
   where device_id = p_device_id;
  return true;
end;
$$;

revoke all on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, jsonb, text, timestamptz
) from public, anon, authenticated;
revoke all on function public.ordax_claim_product_action_v1(
  uuid, uuid, text, integer
) from public, anon, authenticated;
revoke all on function public.ordax_start_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text
) from public, anon, authenticated;
revoke all on function public.ordax_renew_product_action_lease_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, integer
) from public, anon, authenticated;
revoke all on function public.ordax_progress_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text, smallint
) from public, anon, authenticated;
revoke all on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) from public, anon, authenticated;
revoke all on function public.ordax_get_product_action_v1(
  uuid, uuid
) from public, anon, authenticated;
revoke all on function public.ordax_record_product_presence_v1(
  uuid, boolean, text, text, text, boolean
) from public, anon, authenticated;

grant execute on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, jsonb, text, timestamptz
) to service_role;
grant execute on function public.ordax_claim_product_action_v1(
  uuid, uuid, text, integer
) to service_role;
grant execute on function public.ordax_start_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text
) to service_role;
grant execute on function public.ordax_renew_product_action_lease_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, integer
) to service_role;
grant execute on function public.ordax_progress_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text, smallint
) to service_role;
grant execute on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) to service_role;
grant execute on function public.ordax_get_product_action_v1(
  uuid, uuid
) to service_role;
grant execute on function public.ordax_record_product_presence_v1(
  uuid, boolean, text, text, text, boolean
) to service_role;

commit;
