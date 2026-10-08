-- Read-only postflight for 20261007202500_product_client_grant_isolation_v1.
-- Run only AFTER this migration has been applied and the ledger version recorded.
-- This script does not create test grants, mutate permissions or write rows.
do $postflight$
declare
  v_old_rpc regprocedure;
  v_new_rpc regprocedure;
  v_old_resolver regprocedure;
  v_new_resolver regprocedure;
begin
  v_old_rpc := pg_catalog.to_regprocedure(
    'public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,jsonb,text,timestamptz)'
  );
  v_new_rpc := pg_catalog.to_regprocedure(
    'public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamptz)'
  );
  v_old_resolver := pg_catalog.to_regprocedure(
    'private.ordax_resolve_product_remote_grant_v1(uuid,uuid,uuid,uuid,text,text,text)'
  );
  v_new_resolver := pg_catalog.to_regprocedure(
    'private.ordax_resolve_product_remote_grant_v1(uuid,uuid,uuid,uuid,text,text,text,text)'
  );

  if v_old_rpc is not null or v_old_resolver is not null
     or v_new_rpc is null or v_new_resolver is null then
    raise exception 'product_client_contract_signature_mismatch';
  end if;

  if not pg_catalog.has_function_privilege(
      'ordax_edge_executor', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'authenticated', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'anon', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'service_role', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'ordax_edge_executor', v_new_resolver::oid, 'EXECUTE'
    )
  then
    raise exception 'product_client_contract_acl_mismatch';
  end if;

  if pg_catalog.position(
       'and g.client_id = p_client_id' in
       pg_catalog.pg_get_functiondef(v_new_resolver::oid)
     ) = 0
     or pg_catalog.position(
       'v_existing.client_id = p_client_id' in
       pg_catalog.pg_get_functiondef(v_new_rpc::oid)
     ) = 0 then
    raise exception 'product_client_contract_missing_client_match';
  end if;

  if not exists (
    select 1 from information_schema.columns
    where table_schema='private' and table_name='ordax_product_action_requests'
      and column_name='client_id'
  ) or not exists (
    select 1 from information_schema.columns
    where table_schema='private' and table_name='ordax_product_action_audit'
      and column_name='client_id'
  ) then
    raise exception 'product_client_contract_missing_client_audit';
  end if;
end;
$postflight$;
