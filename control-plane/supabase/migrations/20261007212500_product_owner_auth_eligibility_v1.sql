begin;

-- Product ownership granted by a live, verified Supabase Auth account is
-- checked *inside* these three postgres-owned SECURITY DEFINER entrypoints,
-- before issuing any device/remote capability/action authority.
-- This reuses the canonical lock-bearing trusted actor eligibility helper
-- introduced in 20261007212000; it does not derive or authenticate the
-- service caller's identity from a supplied owner ID.
do $preflight$
declare
  v_bad integer;
begin
  if to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or has_function_privilege(
       'ordax_edge_executor','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
     or has_function_privilege(
       'authenticated','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  then
    raise exception 'product owner auth: canonical helper privilege contract changed';
  end if;

  -- Do not overwrite concurrent edits or assume all functions are as seen.
  with expected(signature,definition_md5) as (
    values
    ('public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamp with time zone)','9fe553136fc1a5967d92e4a8a0dcf708'),
    ('public.ordax_enroll_product_device_v1(uuid,text,text,text,text,text)','a2af5eef6f2bed54d032cacaf0300b5c'),
    ('public.ordax_replace_remote_grant_group_v1(uuid,uuid,uuid,uuid,text,text,text,text[],text[],timestamp with time zone)','24712d8fb09267b1964d8fc5c9389178')
  )
  select count(*) into v_bad
  from expected e
  left join pg_proc p on p.oid=to_regprocedure(e.signature)
  where p.oid is null
     or md5(pg_get_functiondef(p.oid))<>e.definition_md5
     or not p.prosecdef
     or not has_function_privilege('ordax_edge_executor',p.oid,'EXECUTE')
     or has_function_privilege('authenticated',p.oid,'EXECUTE')
     or has_function_privilege('service_role',p.oid,'EXECUTE');
  if v_bad<>0 then
    raise exception 'product owner auth: % RPCs drifted',v_bad;
  end if;
end;
$preflight$;

-- Protect the canonical ordax_enqueue_product_action_v1 RPC without changing its OID/EXECUTE ACL.
CREATE OR REPLACE FUNCTION public.ordax_enqueue_product_action_v1(p_owner_user_id uuid, p_space_id uuid, p_project_id uuid, p_device_id uuid, p_client_kind text, p_client_id text, p_capability text, p_access_mode text, p_payload jsonb, p_idempotency_key text, p_expires_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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

  -- The service is responsible for actor-to-caller proof. This DB guard
  -- confirms account eligibility and locks the Auth identity before the
  -- first replay, device enrollment or remote authority mutation.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','product_owner_auth_ineligible');
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
$function$
;

-- Protect the canonical ordax_enroll_product_device_v1 RPC without changing its OID/EXECUTE ACL.
CREATE OR REPLACE FUNCTION public.ordax_enroll_product_device_v1(p_owner_user_id uuid, p_device_name text, p_device_kind text, p_channel text, p_token_sha256 text, p_machine_binding_sha256 text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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

  -- The service is responsible for actor-to-caller proof. This DB guard
  -- confirms account eligibility and locks the Auth identity before the
  -- first replay, device enrollment or remote authority mutation.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','product_owner_auth_ineligible');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_machine_binding_sha256)
  );

  select d.*
    into v_device
    from private.ordax_product_device_credentials c
    join public.ordax_product_devices d on d.device_id = c.device_id
   where c.machine_binding_sha256 = p_machine_binding_sha256
   for update of d;

  if found then
    select c.*
      into v_credential
      from private.ordax_product_device_credentials c
     where c.device_id = v_device.device_id
     for update;

    if not found then
      return jsonb_build_object('ok', false, 'error', 'device_credential_missing');
    end if;

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
$function$
;

-- Protect the canonical ordax_replace_remote_grant_group_v1 RPC without changing its OID/EXECUTE ACL.
CREATE OR REPLACE FUNCTION public.ordax_replace_remote_grant_group_v1(p_owner_user_id uuid, p_space_id uuid, p_project_id uuid, p_device_id uuid, p_client_kind text, p_client_id text, p_profile_key text, p_capabilities text[], p_access_modes text[], p_valid_until timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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

  -- The service is responsible for actor-to-caller proof. This DB guard
  -- confirms account eligibility and locks the Auth identity before the
  -- first replay, device enrollment or remote authority mutation.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','product_owner_auth_ineligible');
  end if;

  if exists (
    select 1 from unnest(p_capabilities) item
    where not private.ordax_product_capability_name_valid(item)
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
$function$
;

do $postflight$
declare
  v_bad integer;
begin
  with expected(signature,definition_md5) as (
    values
    ('public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamp with time zone)','9fe553136fc1a5967d92e4a8a0dcf708'),
    ('public.ordax_enroll_product_device_v1(uuid,text,text,text,text,text)','a2af5eef6f2bed54d032cacaf0300b5c'),
    ('public.ordax_replace_remote_grant_group_v1(uuid,uuid,uuid,uuid,text,text,text,text[],text[],timestamp with time zone)','24712d8fb09267b1964d8fc5c9389178')
  )
  select count(*) into v_bad
  from expected e
  left join pg_proc p on p.oid=to_regprocedure(e.signature)
  where p.oid is null
    or not p.prosecdef
    or p.provolatile<>'v'
    or pg_get_functiondef(p.oid) not like '%ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)%'
    or pg_get_functiondef(p.oid) not like '%product_owner_auth_ineligible%'
    or not has_function_privilege('ordax_edge_executor',p.oid,'EXECUTE')
    or has_function_privilege('authenticated',p.oid,'EXECUTE')
    or has_function_privilege('service_role',p.oid,'EXECUTE');

  if v_bad<>0 then
    raise exception 'product owner auth: % RPC guards/privileges invalid',v_bad;
  end if;

  if has_function_privilege(
      'ordax_edge_executor','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
    or has_schema_privilege('ordax_edge_executor','private','USAGE')
    or has_table_privilege('ordax_edge_executor','auth.users','SELECT')
    or has_table_privilege('authenticated','auth.users','SELECT')
  then
    raise exception 'product owner auth: leaked private Auth authority';
  end if;
end;
$postflight$;

commit;
