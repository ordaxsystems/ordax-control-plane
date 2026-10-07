begin;

do $policy$
declare
  v_table text;
  v_policy text;
begin
  foreach v_table in array array[
    'ordax_product_action_requests',
    'ordax_product_action_events',
    'ordax_product_action_audit',
    'ordax_product_device_credentials'
  ]
  loop
    v_policy := v_table || '_deny_direct_access';

    if not exists (
      select 1
      from pg_policies
      where schemaname = 'private'
        and tablename = v_table
        and policyname = v_policy
    ) then
      execute format(
        'create policy %I on private.%I as restrictive for all to public using (false) with check (false)',
        v_policy,
        v_table
      );
    end if;
  end loop;
end;
$policy$;

commit;
