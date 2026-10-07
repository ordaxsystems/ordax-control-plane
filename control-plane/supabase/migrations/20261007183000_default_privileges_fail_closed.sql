begin;

-- Future objects owned by postgres must start deny-by-default.
-- Migrations that intentionally expose an object must grant the exact privilege
-- to the exact role in the same source-controlled migration.

alter default privileges for role postgres in schema public
  revoke all on tables from anon, authenticated, service_role;

alter default privileges for role postgres in schema public
  revoke all on sequences from anon, authenticated, service_role;

alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated, service_role, ordax_edge_executor;

-- The private schema is not exposed, but keep its object defaults fail-closed as
-- defense in depth. This prevents a future schema-USAGE change from accidentally
-- turning PostgreSQL's default PUBLIC function EXECUTE into an API boundary.

alter default privileges for role postgres in schema private
  revoke all on tables from public, anon, authenticated, service_role, ordax_edge_executor;

alter default privileges for role postgres in schema private
  revoke all on sequences from public, anon, authenticated, service_role, ordax_edge_executor;

alter default privileges for role postgres in schema private
  revoke execute on functions from public, anon, authenticated, service_role, ordax_edge_executor;

commit;
