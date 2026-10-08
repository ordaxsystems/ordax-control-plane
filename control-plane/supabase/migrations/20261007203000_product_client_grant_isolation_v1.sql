-- Product RPC identity contract: exact per-client grants, actions and audit.
-- client_id MUST come from authenticated client credentials in the edge caller.
-- No request-body supplied client identity may authorize an action.
begin;

alter table private.ordax_product_action_requests add column client_id text;
alter table private.ordax_product_action_audit add column client_id text;

alter table private.ordax_product_action_requests
  add constraint ordax_product_action_requests_client_id_check
  check (client_id is null or (
    char_length(client_id) between 8 and 160
    and client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
  ));
alter table private.ordax_product_action_audit
  add constraint ordax_product_action_audit_client_id_check
  check (client_id is null or (
    char_length(client_id) between 8 and 160
    and client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
  ));

-- RESTRICT is implicit; fail atomically if any other owner depends on the
-- insecure signatures. Never use CASCADE to bypass dependency contracts.
revoke all on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, jsonb, text, timestamptz
) from public, anon, authenticated, service_role, ordax_edge_executor;
drop function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, jsonb, text, timestamptz
);
drop function private.ordax_resolve_product_remote_grant_v1(
  uuid, uuid, uuid, uuid, text, text, text
);

create or replace function private.ordax_resolve_product_remote_grant_v1(
  p_owner_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_client_kind text,
  p_client_id text,
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
    and g.client_id = p_client_id
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

revoke all on function private.ordax_resolve_product_remote_grant_v1(
  uuid, uuid, uuid, uuid, text, text, text, text
) from public, anon, authenticated, service_role, ordax_edge_executor;

create or replace function public.ordax_enqueue_product_action_v1(
  p_owner_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_client_kind text,
  p_client_id text,
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
     or p_client_id is null
     or char_length(p_client_id) not between 8 and 160
     or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
     or p_access_mode not in ('read','write')
     or p_capability is null
     or char_length(p_capability) not between 2 and 120
     or not private.ordax_product_capability_name_valid(p_capability)
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
       and v_existing.client_id = p_client_id
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
      client_kind, client_id, capability, access_mode, phase, decision, reason
    ) values (
      v_existing.request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id,
      v_existing.grant_id, p_client_kind, p_client_id, p_capability, p_access_mode,
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
    p_client_id,
    p_capability,
    p_access_mode
  );

  if v_grant_id is null then
    insert into private.ordax_product_action_audit(
      owner_user_id, space_id, project_id, device_id, client_kind,
      client_id, capability, access_mode, phase, decision, reason
    ) values (
      p_owner_user_id, p_space_id, p_project_id, p_device_id, p_client_kind,
      p_client_id, p_capability, p_access_mode, 'decision', 'deny', 'product_grant_not_resolved'
    );

    return jsonb_build_object('ok', false, 'error', 'product_grant_not_resolved');
  end if;

  v_request_id := extensions.gen_random_uuid();
  v_effect_id := extensions.gen_random_uuid();

  insert into private.ordax_product_action_requests(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, client_id, capability, access_mode, payload, payload_sha256,
    idempotency_key, effect_id, status, expires_at
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_client_id, p_capability, p_access_mode, p_payload, v_payload_sha256,
    p_idempotency_key, v_effect_id, 'queued', p_expires_at
  );

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, client_id, capability, access_mode, phase, decision, reason
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_client_id, p_capability, p_access_mode, 'decision', 'allow', 'grant_resolved'
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

revoke all on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, text, jsonb, text, timestamptz
) from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, text, jsonb, text, timestamptz
) to ordax_edge_executor;

commit;
