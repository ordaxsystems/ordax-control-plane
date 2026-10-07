begin;

-- PostgreSQL grants EXECUTE on newly created functions to PUBLIC by default.
-- A schema-scoped default-privilege revoke cannot remove that global default.
-- Remove it once for objects created by postgres; every intended caller must
-- then receive an explicit EXECUTE grant in the owning migration.

alter default privileges for role postgres
  revoke execute on functions from public;

commit;
