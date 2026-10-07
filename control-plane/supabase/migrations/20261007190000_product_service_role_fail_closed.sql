begin;

-- The generic Supabase service_role is not an application authority for the
-- canonical ORDAX product database. Every server-side mutation path must use a
-- reviewed dedicated executor/RPC boundary instead of bypassing RLS with broad
-- direct table DML.

revoke all on table public.ordax_accounts from service_role;
revoke all on table public.ordax_spaces from service_role;
revoke all on table public.ordax_space_members from service_role;
revoke all on table public.ordax_entitlement_grants from service_role;
revoke all on table public.ordax_profile_packs from service_role;
revoke all on table public.ordax_space_profile_packs from service_role;
revoke all on table public.ordax_memory_items from service_role;
revoke all on table public.ordax_memory_embeddings from service_role;
revoke all on table public.ordax_project_connections from service_role;
revoke all on table public.ordax_projects from service_role;
revoke all on table public.ordax_product_devices from service_role;
revoke all on table public.ordax_device_presence from service_role;
revoke all on table public.ordax_space_devices from service_role;
revoke all on table public.ordax_device_project_bindings from service_role;
revoke all on table public.ordax_remote_capability_grants from service_role;

commit;
