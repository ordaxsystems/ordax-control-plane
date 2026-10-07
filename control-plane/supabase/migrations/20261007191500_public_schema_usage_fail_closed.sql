begin;

-- Custom PostgreSQL roles inherit privileges granted to PUBLIC. Keep the
-- exposed schema opt-in so future domain executors do not acquire Data API
-- surface merely by existing.
do $preflight$
begin
  if not has_schema_privilege('anon', 'public', 'USAGE')
     or not has_schema_privilege('authenticated', 'public', 'USAGE')
     or not has_schema_privilege('service_role', 'public', 'USAGE')
     or not has_schema_privilege('postgres', 'public', 'USAGE')
     or not has_schema_privilege('ordax_edge_executor', 'public', 'USAGE') then
    raise exception 'public schema hardening: required explicit role usage missing';
  end if;
end;
$preflight$;

revoke usage, create on schema public from public;

do $postflight$
declare
  public_usage_grants integer;
begin
  select count(*) into public_usage_grants
  from pg_namespace n,
       lateral aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) acl
  where n.nspname = 'public'
    and acl.grantee = 0
    and acl.privilege_type in ('USAGE', 'CREATE');

  if public_usage_grants <> 0 then
    raise exception 'public schema hardening: PUBLIC schema privilege survived';
  end if;

  if not has_schema_privilege('anon', 'public', 'USAGE')
     or not has_schema_privilege('authenticated', 'public', 'USAGE')
     or not has_schema_privilege('service_role', 'public', 'USAGE')
     or not has_schema_privilege('postgres', 'public', 'USAGE')
     or not has_schema_privilege('ordax_edge_executor', 'public', 'USAGE') then
    raise exception 'public schema hardening: required role access regressed';
  end if;

  if has_schema_privilege('ordax_edge_executor', 'private', 'USAGE') then
    raise exception 'public schema hardening: edge executor leaked private usage';
  end if;
end;
$postflight$;

commit;
