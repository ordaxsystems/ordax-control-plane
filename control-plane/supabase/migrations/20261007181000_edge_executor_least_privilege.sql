begin;

do $role$
begin
  if not exists (select 1 from pg_roles where rolname = 'ordax_edge_executor') then
    create role ordax_edge_executor nologin;
  end if;
end;
$role$;

revoke all on schema private from ordax_edge_executor;
revoke all on all tables in schema public from ordax_edge_executor;
revoke all on all tables in schema private from ordax_edge_executor;
revoke all on all sequences in schema public from ordax_edge_executor;
revoke all on all sequences in schema private from ordax_edge_executor;
revoke all on all functions in schema public from ordax_edge_executor;
revoke all on all functions in schema private from ordax_edge_executor;

grant usage on schema public to ordax_edge_executor;

revoke execute on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, jsonb, text, timestamptz
) from service_role;
revoke execute on function public.ordax_claim_product_action_v1(
  uuid, uuid, text, integer
) from service_role;
revoke execute on function public.ordax_start_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text
) from service_role;
revoke execute on function public.ordax_renew_product_action_lease_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, integer
) from service_role;
revoke execute on function public.ordax_progress_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text, smallint
) from service_role;
revoke execute on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) from service_role;
revoke execute on function public.ordax_get_product_action_v1(uuid, uuid)
  from service_role;
revoke execute on function public.ordax_record_product_presence_v1(
  uuid, boolean, text, text, text, boolean
) from service_role;
revoke execute on function public.ordax_enroll_product_device_v1(
  uuid, text, text, text, text, text
) from service_role;
revoke execute on function public.ordax_identify_product_device_v1(text, text)
  from service_role;
revoke execute on function public.ordax_authenticate_product_device_v1(uuid, text)
  from service_role;
revoke execute on function public.ordax_import_legacy_product_device_v1(
  uuid, uuid, text, text, text, text, text, timestamptz
) from service_role;

grant execute on function public.ordax_enqueue_product_action_v1(
  uuid, uuid, uuid, uuid, text, text, text, jsonb, text, timestamptz
) to ordax_edge_executor;
grant execute on function public.ordax_claim_product_action_v1(
  uuid, uuid, text, integer
) to ordax_edge_executor;
grant execute on function public.ordax_start_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text
) to ordax_edge_executor;
grant execute on function public.ordax_renew_product_action_lease_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, integer
) to ordax_edge_executor;
grant execute on function public.ordax_progress_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text, smallint
) to ordax_edge_executor;
grant execute on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) to ordax_edge_executor;
grant execute on function public.ordax_get_product_action_v1(uuid, uuid)
  to ordax_edge_executor;
grant execute on function public.ordax_record_product_presence_v1(
  uuid, boolean, text, text, text, boolean
) to ordax_edge_executor;
grant execute on function public.ordax_enroll_product_device_v1(
  uuid, text, text, text, text, text
) to ordax_edge_executor;
grant execute on function public.ordax_identify_product_device_v1(text, text)
  to ordax_edge_executor;
grant execute on function public.ordax_authenticate_product_device_v1(uuid, text)
  to ordax_edge_executor;

commit;
