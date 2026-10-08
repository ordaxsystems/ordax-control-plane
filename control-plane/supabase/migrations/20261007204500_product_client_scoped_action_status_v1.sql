-- Match action-status reads to the exact Product OAuth client identity.
-- The entrypoint must derive client_id from a verified JWT; this SQL
-- enforces per-client read isolation as a second authority boundary.
-- Do not preserve the identity-less overload or make a D1 fallback.
begin;

revoke all on function public.ordax_get_product_action_v1(uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

-- Restrict rather than CASCADE: fail atomically on unexpected dependencies.
drop function public.ordax_get_product_action_v1(uuid, uuid);

create function public.ordax_get_product_action_v1(
  p_owner_user_id uuid,
  p_client_kind text,
  p_client_id text,
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
  where p_owner_user_id is not null
    and p_request_id is not null
    and p_client_kind in ('ordax-web','ordax-mobile','product-mcp')
    and p_client_id is not null
    and char_length(p_client_id) between 8 and 160
    and p_client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    and r.owner_user_id = p_owner_user_id
    and r.client_kind = p_client_kind
    and r.client_id = p_client_id
    and r.request_id = p_request_id;
$$;

revoke all on function public.ordax_get_product_action_v1(uuid, text, text, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

grant execute on function public.ordax_get_product_action_v1(uuid, text, text, uuid)
  to ordax_edge_executor;

commit;
