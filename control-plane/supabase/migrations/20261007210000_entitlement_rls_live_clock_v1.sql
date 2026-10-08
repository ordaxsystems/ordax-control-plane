begin;

-- Use the same real clock as the canonical grant issuer and revoker.
-- statement_timestamp() can precede valid_from when multiple statements
-- are submitted as one command; that incorrectly hides a fresh grant.
do $preflight$
declare
  v_policy text;
begin
  select pg_catalog.lower(p.qual) into v_policy
    from pg_policies p
   where p.schemaname='public'
     and p.tablename='ordax_entitlement_grants'
     and p.policyname='ordax_entitlement_grants_select_subject'
     and p.cmd='SELECT';

  if v_policy is null
     or v_policy not like '%statement_timestamp%'
  then
    raise exception 'entitlement live-clock: expected time-bound SELECT policy missing';
  end if;
end;
$preflight$;

alter policy ordax_entitlement_grants_select_subject
  on public.ordax_entitlement_grants
  using (
    valid_from<=pg_catalog.clock_timestamp()
    and (valid_until is null or valid_until>pg_catalog.clock_timestamp())
    and (
      user_id=(select auth.uid())
      or (space_id is not null and private.ordax_can_access_space(space_id))
    )
  );

do $postflight$
declare
  v_policy text;
begin
  select pg_catalog.lower(p.qual) into v_policy
    from pg_policies p
   where p.schemaname='public'
     and p.tablename='ordax_entitlement_grants'
     and p.policyname='ordax_entitlement_grants_select_subject'
     and p.cmd='SELECT';

  if v_policy not like '%clock_timestamp%'
    or v_policy like '%statement_timestamp%'
    or v_policy not like '%valid_from%'
    or v_policy not like '%valid_until%'
    or v_policy not like '%auth.uid%'
    or v_policy not like '%ordax_can_access_space%'
    or not has_table_privilege(
      'authenticated','public.ordax_entitlement_grants','SELECT')
    or has_table_privilege(
      'authenticated','public.ordax_entitlement_grants','UPDATE')
  then
    raise exception 'entitlement live-clock: policy or ACL regression';
  end if;
end;
$postflight$;

commit;
