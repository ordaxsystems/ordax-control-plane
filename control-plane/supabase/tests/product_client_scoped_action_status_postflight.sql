-- Read-only postflight for the exact client-scoped Product status RPC.
-- Run after the versioned migration; no fixture rows or persistent changes.
do $postflight$
declare
  v_old regprocedure := pg_catalog.to_regprocedure(
    'public.ordax_get_product_action_v1(uuid,uuid)'
  );
  v_new regprocedure := pg_catalog.to_regprocedure(
    'public.ordax_get_product_action_v1(uuid,text,text,uuid)'
  );
  v_definition text;
begin
  if v_old is not null or v_new is null then
    raise exception 'product_status_client_signature_mismatch';
  end if;

  if not pg_catalog.has_function_privilege(
       'ordax_edge_executor', v_new::oid, 'EXECUTE'
     )
     or pg_catalog.has_function_privilege(
       'authenticated', v_new::oid, 'EXECUTE'
     )
     or pg_catalog.has_function_privilege(
       'anon', v_new::oid, 'EXECUTE'
     )
     or pg_catalog.has_function_privilege(
       'service_role', v_new::oid, 'EXECUTE'
     ) then
    raise exception 'product_status_client_acl_mismatch';
  end if;

  v_definition := pg_catalog.pg_get_functiondef(v_new::oid);
  if pg_catalog.strpos(v_definition, 'r.owner_user_id = p_owner_user_id') = 0
     or pg_catalog.strpos(v_definition, 'r.client_kind = p_client_kind') = 0
     or pg_catalog.strpos(v_definition, 'r.client_id = p_client_id') = 0
     or pg_catalog.strpos(v_definition, 'r.request_id = p_request_id') = 0
     or pg_catalog.strpos(v_definition, 'p_client_id is not null') = 0
  then
    raise exception 'product_status_client_predicate_missing';
  end if;
end;
$postflight$;
