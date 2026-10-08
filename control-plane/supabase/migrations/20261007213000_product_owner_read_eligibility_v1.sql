begin;

-- A valid scoped owner/request ID is not evidence of a *currently eligible*
-- Auth account. Deny sensitive Product target/action-result reads for banned,
-- soft-deleted, anonymous or unconfirmed owners. No new permission is minted.
-- Reuse the existing private, lock-bearing trusted owner status check.
do $preflight$
declare
  v_bad integer;
begin
  if to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or has_function_privilege(
         'authenticated','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
     or has_function_privilege(
         'ordax_edge_executor','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  then raise exception 'product owner read: canonical helper/ACL unavailable'; end if;

  with expected(signature,md5) as (values
    ('public.ordax_get_product_action_v1(uuid,text,text,uuid)','5c661f113787e5796fa3f185bc9dfc93'),
    ('public.ordax_list_product_targets_v1(uuid,text,text)','2fa6a6a140a150780676ac5a891f792a')
  )
  select count(*) into v_bad from expected e
  left join pg_proc p on p.oid=to_regprocedure(e.signature)
  where p.oid is null
    or md5(pg_get_functiondef(p.oid))<>e.md5
    or not p.prosecdef
    or p.provolatile<>'s'
    or pg_get_userbyid(p.proowner)<>'postgres'
    or not has_function_privilege('ordax_edge_executor',p.oid,'EXECUTE')
    or has_function_privilege('authenticated',p.oid,'EXECUTE')
    or has_function_privilege('service_role',p.oid,'EXECUTE');
  if v_bad<>0
  then raise exception 'product owner read: % RPC signatures/baselines drifted',v_bad; end if;
end;
$preflight$;

-- Security-definer function OIDs and caller ACLs remain unchanged.
-- VOLATILE is required because the shared helper locks the Auth row.
CREATE OR REPLACE FUNCTION public.ordax_get_product_action_v1(p_owner_user_id uuid, p_client_kind text, p_client_id text, p_request_id uuid)
 RETURNS jsonb
 LANGUAGE sql
 VOLATILE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select case
    -- Auth is owned by Supabase; the Worker must separately authenticate
    -- and bind this service-supplied owner ID to the verified caller.
    when not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
      then pg_catalog.jsonb_build_object(
        'ok',false,'error','product_owner_auth_ineligible')
    else (
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
        where p_owner_user_id is not null
          and p_request_id is not null
          and p_client_kind in ('ordax-web','ordax-mobile','product-mcp')
          and p_client_id is not null
          and char_length(p_client_id) between 8 and 160
          and p_client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
          and r.owner_user_id = p_owner_user_id
          and r.client_kind = p_client_kind
          and r.client_id = p_client_id
          and r.request_id = p_request_id
    )
  end;
$function$
;

CREATE OR REPLACE FUNCTION public.ordax_list_product_targets_v1(p_owner_user_id uuid, p_client_kind text, p_client_id text)
 RETURNS jsonb
 LANGUAGE sql
 VOLATILE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select case
    -- Auth is owned by Supabase; the Worker must separately authenticate
    -- and bind this service-supplied owner ID to the verified caller.
    when not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
      then pg_catalog.jsonb_build_object(
        'ok',false,'error','product_owner_auth_ineligible')
    else (
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
            and (g.valid_until is null or g.valid_until > pg_catalog.statement_timestamp())
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
        from targets t
    )
  end;
$function$
;

do $postflight$
declare
  v_bad integer;
begin
  with expected(signature,md5) as (values
    ('public.ordax_get_product_action_v1(uuid,text,text,uuid)','5c661f113787e5796fa3f185bc9dfc93'),
    ('public.ordax_list_product_targets_v1(uuid,text,text)','2fa6a6a140a150780676ac5a891f792a')
  )
  select count(*) into v_bad from expected e
  left join pg_proc p on p.oid=to_regprocedure(e.signature)
  where p.oid is null
    or not p.prosecdef
    or p.provolatile<>'v'
    or pg_get_userbyid(p.proowner)<>'postgres'
    or pg_get_functiondef(p.oid) not like '%ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)%'
    or pg_get_functiondef(p.oid) not like '%product_owner_auth_ineligible%'
    or not has_function_privilege('ordax_edge_executor',p.oid,'EXECUTE')
    or has_function_privilege('authenticated',p.oid,'EXECUTE')
    or has_function_privilege('service_role',p.oid,'EXECUTE');
  if v_bad<>0
  then raise exception 'product owner read: % RPC postflight contract failures',v_bad; end if;

  if has_schema_privilege('ordax_edge_executor','private','USAGE')
    or has_table_privilege('ordax_edge_executor','auth.users','SELECT')
    or has_table_privilege('authenticated','auth.users','SELECT')
    or has_function_privilege(
        'service_role','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  then raise exception 'product owner read: privilege escalation'; end if;
end;
$postflight$;

commit;
