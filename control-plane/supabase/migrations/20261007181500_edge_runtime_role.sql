begin;

do $role$
begin
  if not exists (select 1 from pg_roles where rolname = 'ordax_edge_runtime') then
    create role ordax_edge_runtime
      login
      inherit
      nosuperuser
      nocreatedb
      nocreaterole
      noreplication
      nobypassrls;
  end if;
end;
$role$;

grant ordax_edge_executor to ordax_edge_runtime;
grant connect on database postgres to ordax_edge_runtime;

alter role ordax_edge_runtime set search_path = '';
alter role ordax_edge_runtime set statement_timeout = '10s';
alter role ordax_edge_runtime set lock_timeout = '3s';
alter role ordax_edge_runtime set idle_in_transaction_session_timeout = '10s';

commit;
