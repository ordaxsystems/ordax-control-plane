begin;

do $role$
begin
  if exists (select 1 from pg_roles where rolname = 'ordax_edge_runtime') then
    revoke ordax_edge_executor from ordax_edge_runtime;
    revoke connect on database postgres from ordax_edge_runtime;
    drop role ordax_edge_runtime;
  end if;
end;
$role$;

commit;
