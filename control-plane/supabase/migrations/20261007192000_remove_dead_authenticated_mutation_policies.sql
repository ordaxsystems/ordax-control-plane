begin;

-- These mutation policies became unreachable when authenticated DML was revoked
-- by the server-authoritative foundation. Remove them so a future table GRANT
-- cannot silently resurrect direct client mutation.

do $preflight$
begin
  if has_table_privilege('authenticated', 'public.ordax_spaces', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_spaces', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_spaces', 'DELETE')
     or has_table_privilege('authenticated', 'public.ordax_space_members', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_space_members', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_space_members', 'DELETE')
     or has_table_privilege('authenticated', 'public.ordax_memory_items', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_memory_items', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_memory_items', 'DELETE') then
    raise exception 'client mutation policy cleanup: authenticated DML privilege unexpectedly present';
  end if;
end;
$preflight$;

drop policy if exists ordax_spaces_insert_own on public.ordax_spaces;
drop policy if exists ordax_spaces_update_admin on public.ordax_spaces;
drop policy if exists ordax_spaces_delete_owner on public.ordax_spaces;

drop policy if exists ordax_space_members_insert_admin on public.ordax_space_members;
drop policy if exists ordax_space_members_update_admin on public.ordax_space_members;
drop policy if exists ordax_space_members_delete_admin on public.ordax_space_members;

drop policy if exists ordax_memory_items_insert_own on public.ordax_memory_items;
drop policy if exists ordax_memory_items_update_own on public.ordax_memory_items;
drop policy if exists ordax_memory_items_delete_own on public.ordax_memory_items;

do $postflight$
declare
  remaining integer;
begin
  select count(*) into remaining
  from pg_policies
  where schemaname = 'public'
    and tablename in ('ordax_spaces', 'ordax_space_members', 'ordax_memory_items')
    and cmd in ('INSERT', 'UPDATE', 'DELETE');

  if remaining <> 0 then
    raise exception 'client mutation policy cleanup: stale mutation policy survived';
  end if;

  if has_table_privilege('authenticated', 'public.ordax_spaces', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_spaces', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_spaces', 'DELETE')
     or has_table_privilege('authenticated', 'public.ordax_space_members', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_space_members', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_space_members', 'DELETE')
     or has_table_privilege('authenticated', 'public.ordax_memory_items', 'INSERT')
     or has_table_privilege('authenticated', 'public.ordax_memory_items', 'UPDATE')
     or has_table_privilege('authenticated', 'public.ordax_memory_items', 'DELETE') then
    raise exception 'client mutation policy cleanup: DML authority regressed';
  end if;
end;
$postflight$;

commit;
