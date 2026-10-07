begin;

-- Repository connections remain read-only at the Product surface. This migration
-- tightens stored metadata to the already-versioned explicit-repository contract
-- without creating any mutation RPC.

do $preflight$
begin
  if exists (
    select 1
    from public.ordax_project_connections c
    where c.provider = 'github'
      and (
        c.installation_id is null
        or c.installation_id <= 0
        or c.repository_id is null
        or c.repository_id <= 0
        or c.repository_full_name is null
        or char_length(c.repository_full_name) not between 3 and 200
        or c.repository_full_name !~ '^[^[:space:]/]+/[^[:space:]/]+$'
      )
  ) then
    raise exception 'project connection contract: invalid GitHub selection exists';
  end if;

  if exists (
    select 1
    from public.ordax_project_connections c
    where c.default_branch is not null
      and char_length(c.default_branch) not between 1 and 255
  ) then
    raise exception 'project connection contract: invalid default branch exists';
  end if;

  if exists (
    select 1
    from public.ordax_project_connections c
    where c.provider = 'github'
    group by c.project_id, c.repository_id
    having count(*) > 1
  ) then
    raise exception 'project connection contract: duplicate repository selection exists';
  end if;
end;
$preflight$;

alter table public.ordax_project_connections
  drop constraint ordax_project_connections_check;

alter table public.ordax_project_connections
  add constraint ordax_project_connections_github_selection_check
  check (
    provider <> 'github'
    or (
      installation_id is not null
      and installation_id > 0
      and repository_id is not null
      and repository_id > 0
      and repository_full_name is not null
      and char_length(repository_full_name) between 3 and 200
      and repository_full_name ~ '^[^[:space:]/]+/[^[:space:]/]+$'
    )
  );

alter table public.ordax_project_connections
  add constraint ordax_project_connections_default_branch_check
  check (
    default_branch is null
    or char_length(default_branch) between 1 and 255
  );

create unique index ordax_project_connections_project_github_repository_uidx
  on public.ordax_project_connections(project_id, repository_id)
  where provider = 'github';

do $postflight$
begin
  if has_table_privilege('authenticated', 'public.ordax_project_connections', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_project_connections', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_project_connections', 'DELETE')
     or has_table_privilege('service_role', 'public.ordax_project_connections', 'INSERT')
     or has_table_privilege('service_role', 'public.ordax_project_connections', 'UPDATE')
     or has_table_privilege('service_role', 'public.ordax_project_connections', 'DELETE')
     or has_table_privilege('ordax_edge_executor', 'public.ordax_project_connections', 'INSERT')
     or has_table_privilege('ordax_edge_executor', 'public.ordax_project_connections', 'UPDATE')
     or has_table_privilege('ordax_edge_executor', 'public.ordax_project_connections', 'DELETE')
     or has_table_privilege('ordax_project_executor', 'public.ordax_project_connections', 'INSERT')
     or has_table_privilege('ordax_project_executor', 'public.ordax_project_connections', 'UPDATE')
     or has_table_privilege('ordax_project_executor', 'public.ordax_project_connections', 'DELETE') then
    raise exception 'project connection contract: mutation authority unexpectedly present';
  end if;
end;
$postflight$;

commit;
