begin;

-- The generic Supabase service_role is not an authority for ORDAX remote
-- devices, presence, bindings or capability grants. These relations are
-- mutated only through reviewed SECURITY DEFINER RPCs exposed to the dedicated
-- NOLOGIN ordax_edge_executor role.

revoke all on table public.ordax_product_devices from service_role;
revoke all on table public.ordax_device_presence from service_role;
revoke all on table public.ordax_space_devices from service_role;
revoke all on table public.ordax_device_project_bindings from service_role;
revoke all on table public.ordax_remote_capability_grants from service_role;

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

commit;
