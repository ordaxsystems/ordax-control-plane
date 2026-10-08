begin;

-- The ten privileged actor RPCs are service-only; the service authenticates
-- the caller. PostgreSQL nevertheless must reject actors whose canonical
-- Auth account is no longer eligible, even if services retry stale jobs.
-- Distinct from RLS's JWT-session checker: this function validates a trusted
-- actor ID, never purports to authenticate a network request.
do $preflight$
declare
  v_bad integer;
begin
  if to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is not null
  then raise exception 'trusted actor: unexpected existing helper'; end if;

  with expected(signature,definition_md5) as (
    values
    ('public.ordax_clear_space_profile_pack_v1(uuid,uuid)','4326a2501d3cd9e5b370021a15af0058'),
    ('public.ordax_create_memory_item_v1(uuid,uuid,uuid,text,text,text,text,text,timestamp with time zone,numeric)','3ec103f54693a286c5370da4e9b1a998'),
    ('public.ordax_create_project_v1(uuid,uuid,text,text,jsonb)','98ef55653be126da9b5675ddcb62a4b1'),
    ('public.ordax_create_space_v1(uuid,text,text,jsonb)','6e3e05f9417cd33f32efec0c0ebcbdbb'),
    ('public.ordax_remove_space_member_v1(uuid,uuid,uuid)','0434012425fa41c253c2daf66efb6f23'),
    ('public.ordax_select_space_profile_pack_v1(uuid,uuid,text,integer)','07453d2901f686c5c3d24f48e7bf6c1c'),
    ('public.ordax_set_space_member_v1(uuid,uuid,uuid,text,text)','d6b53ab91aa35d50078b162a33df47ec'),
    ('public.ordax_update_memory_item_v1(uuid,uuid,text,text,text,timestamp with time zone,numeric,text)','2ecf3d61e45834209732b17f9fdb78a6'),
    ('public.ordax_update_project_v1(uuid,uuid,text,text,jsonb)','f6cee368e7918ee7e03b21d5747ba2c6'),
    ('public.ordax_update_space_v1(uuid,uuid,text,text,jsonb)','6488f332740ef35b0fa432dc976913c0')
  )
  select count(*) into v_bad
  from expected e
  left join pg_proc p on p.oid=to_regprocedure(e.signature)
  where p.oid is null or md5(pg_get_functiondef(p.oid))<>e.definition_md5
    or not p.prosecdef;
  if v_bad<>0 then raise exception 'trusted actor: % RPC definitions have drifted',v_bad; end if;

  if (select count(*) from auth.users)<>0
    or not exists(select 1 from pg_roles where rolname='ordax_space_executor'
      and not rolcanlogin and not rolbypassrls)
  then raise exception 'trusted actor: baseline or role mismatch'; end if;
end;
$preflight$;

-- Only postgres-owned SECURITY DEFINER RPCs can invoke this. Its row locks
-- serialize against Auth account-status updates within the same transaction.
create function private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id uuid)
returns boolean
language plpgsql
volatile
security invoker
set search_path = ''
as $function$
begin
  if p_actor_user_id is null then
    return false;
  end if;

  perform 1
  from auth.users u
  join public.ordax_accounts a on a.user_id=u.id
  where u.id=p_actor_user_id
    and u.deleted_at is null
    and u.is_anonymous is false
    and u.confirmed_at is not null
    and (u.banned_until is null
       or u.banned_until<=pg_catalog.clock_timestamp())
  for share of u,a;

  return found;
end;
$function$;

revoke all on function private.ordax_trusted_actor_auth_eligible_v1(uuid)
from public, anon, authenticated, service_role,
     ordax_edge_executor, ordax_space_executor,
     ordax_project_executor, ordax_memory_executor,
     ordax_profile_pack_executor, ordax_entitlement_default_executor;

-- Auth status gate for ordax_clear_space_profile_pack_v1(uuid,uuid)
CREATE OR REPLACE FUNCTION public.ordax_clear_space_profile_pack_v1(p_actor_user_id uuid, p_space_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_previous_slug text;
  v_previous_version integer;
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok',false,'error','pack_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_create_memory_item_v1(uuid,uuid,uuid,text,text,text,text,text,timestamp with time zone,numeric)
CREATE OR REPLACE FUNCTION public.ordax_create_memory_item_v1(p_actor_user_id uuid, p_space_id uuid, p_project_id uuid, p_scope text, p_kind text, p_sensitivity text, p_content text, p_provenance text, p_source_timestamp timestamp with time zone, p_confidence numeric)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_memory_id uuid;
begin
  if p_actor_user_id is null
     or not exists (select 1 from auth.users u where u.id = p_actor_user_id) then
    return jsonb_build_object('ok', false, 'error', 'memory_actor_not_found');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_create_project_v1(uuid,uuid,text,text,jsonb)
CREATE OR REPLACE FUNCTION public.ordax_create_project_v1(p_actor_user_id uuid, p_space_id uuid, p_name text, p_kind text, p_metadata jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_project_id uuid;
  v_space_state text;
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok', false, 'error', 'project_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_create_space_v1(uuid,text,text,jsonb)
CREATE OR REPLACE FUNCTION public.ordax_create_space_v1(p_actor_user_id uuid, p_name text, p_kind text, p_metadata jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_space_id uuid;
begin
  if p_actor_user_id is null
     or not exists (select 1 from auth.users u where u.id = p_actor_user_id) then
    return jsonb_build_object('ok', false, 'error', 'space_actor_not_found');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_remove_space_member_v1(uuid,uuid,uuid)
CREATE OR REPLACE FUNCTION public.ordax_remove_space_member_v1(p_actor_user_id uuid, p_space_id uuid, p_member_user_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_owner_user_id uuid;
  v_removed boolean;
begin
  if p_actor_user_id is null
     or p_space_id is null
     or p_member_user_id is null then
    return jsonb_build_object('ok', false, 'error', 'space_member_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_select_space_profile_pack_v1(uuid,uuid,text,integer)
CREATE OR REPLACE FUNCTION public.ordax_select_space_profile_pack_v1(p_actor_user_id uuid, p_space_id uuid, p_pack_slug text, p_pack_version integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_space_state text;
  v_previous_slug text;
  v_previous_version integer;
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok',false,'error','pack_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_set_space_member_v1(uuid,uuid,uuid,text,text)
CREATE OR REPLACE FUNCTION public.ordax_set_space_member_v1(p_actor_user_id uuid, p_space_id uuid, p_member_user_id uuid, p_role text, p_state text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_owner_user_id uuid;
begin
  if p_actor_user_id is null
     or p_space_id is null
     or p_member_user_id is null then
    return jsonb_build_object('ok', false, 'error', 'space_member_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_update_memory_item_v1(uuid,uuid,text,text,text,timestamp with time zone,numeric,text)
CREATE OR REPLACE FUNCTION public.ordax_update_memory_item_v1(p_actor_user_id uuid, p_memory_id uuid, p_sensitivity text, p_content text, p_provenance text, p_source_timestamp timestamp with time zone, p_confidence numeric, p_state text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_owner_user_id uuid;
  v_current_state text;
begin
  if p_actor_user_id is null or p_memory_id is null then
    return jsonb_build_object('ok', false, 'error', 'memory_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_update_project_v1(uuid,uuid,text,text,jsonb)
CREATE OR REPLACE FUNCTION public.ordax_update_project_v1(p_actor_user_id uuid, p_project_id uuid, p_name text, p_state text, p_metadata jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_space_id uuid;
begin
  if p_actor_user_id is null or p_project_id is null then
    return jsonb_build_object('ok', false, 'error', 'project_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

-- Auth status gate for ordax_update_space_v1(uuid,uuid,text,text,jsonb)
CREATE OR REPLACE FUNCTION public.ordax_update_space_v1(p_actor_user_id uuid, p_space_id uuid, p_name text, p_state text, p_metadata jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  if p_actor_user_id is null or p_space_id is null then
    return jsonb_build_object('ok', false, 'error', 'space_identity_invalid');
  end if;
  -- Re-check the canonical Auth subject and lock its row against concurrent
  -- Auth ban/delete/eligibility transitions throughout this RPC transaction.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','trusted_actor_auth_ineligible');
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
$function$
;

do $postflight$
declare
  v_bad integer;
begin
  with expected(signature,definition_md5) as (
    values
    ('public.ordax_clear_space_profile_pack_v1(uuid,uuid)','4326a2501d3cd9e5b370021a15af0058'),
    ('public.ordax_create_memory_item_v1(uuid,uuid,uuid,text,text,text,text,text,timestamp with time zone,numeric)','3ec103f54693a286c5370da4e9b1a998'),
    ('public.ordax_create_project_v1(uuid,uuid,text,text,jsonb)','98ef55653be126da9b5675ddcb62a4b1'),
    ('public.ordax_create_space_v1(uuid,text,text,jsonb)','6e3e05f9417cd33f32efec0c0ebcbdbb'),
    ('public.ordax_remove_space_member_v1(uuid,uuid,uuid)','0434012425fa41c253c2daf66efb6f23'),
    ('public.ordax_select_space_profile_pack_v1(uuid,uuid,text,integer)','07453d2901f686c5c3d24f48e7bf6c1c'),
    ('public.ordax_set_space_member_v1(uuid,uuid,uuid,text,text)','d6b53ab91aa35d50078b162a33df47ec'),
    ('public.ordax_update_memory_item_v1(uuid,uuid,text,text,text,timestamp with time zone,numeric,text)','2ecf3d61e45834209732b17f9fdb78a6'),
    ('public.ordax_update_project_v1(uuid,uuid,text,text,jsonb)','f6cee368e7918ee7e03b21d5747ba2c6'),
    ('public.ordax_update_space_v1(uuid,uuid,text,text,jsonb)','6488f332740ef35b0fa432dc976913c0')
  )
  select count(*) into v_bad
  from expected e
  join pg_proc p on p.oid=to_regprocedure(e.signature)
  where pg_get_functiondef(p.oid) not like '%trusted_actor_auth_ineligible%'
    or pg_get_functiondef(p.oid) not like '%ordax_trusted_actor_auth_eligible_v1%'
    or not p.prosecdef
    or p.provolatile<>'v';
  if v_bad<>0 then raise exception 'trusted actor: % RPCs not updated',v_bad; end if;

  if not exists(
    select 1 from pg_proc p where
    p.oid='private.ordax_trusted_actor_auth_eligible_v1(uuid)'::regprocedure
    and not p.prosecdef and p.provolatile='v'
    and pg_get_userbyid(p.proowner)='postgres'
  ) or has_function_privilege(
      'authenticated','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
    or has_function_privilege(
      'anon','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
    or has_function_privilege(
      'ordax_space_executor','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
    or has_schema_privilege('authenticated','private','USAGE')
    or has_table_privilege('authenticated','auth.users','SELECT')
  then raise exception 'trusted actor: helper owner/ACL violation'; end if;
end;
$postflight$;

commit;
