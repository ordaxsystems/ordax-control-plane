begin;

-- The live Supabase Auth session/eligibility check already exists in the
-- entitlement-only helper. Rename the same OID, preserving owner and ACL;
-- make it the single PostgreSQL SSOT for private authenticated reads.
-- Never copy the session state, create a new helper, or widen table grants.
do $preflight$
declare
  v_expected_count integer;
  v_bad_count integer;
begin
  if to_regprocedure('private.ordax_authenticated_subject_eligible_v1()') is not null
     or to_regprocedure('private.ordax_authenticated_entitlement_eligible_v1()') is null
  then raise exception 'subject session RLS: unexpected helper version'; end if;

  if not exists (
    select 1 from pg_proc p
    where p.oid='private.ordax_authenticated_entitlement_eligible_v1()'::regprocedure
      and p.prosecdef and p.provolatile='v' and p.pronargs=0
      and pg_get_userbyid(p.proowner)='postgres'
  )
  or not has_function_privilege(
      'authenticated',
      'private.ordax_authenticated_entitlement_eligible_v1()','EXECUTE')
  or has_function_privilege(
      'anon',
      'private.ordax_authenticated_entitlement_eligible_v1()','EXECUTE')
  or has_schema_privilege('authenticated','private','USAGE')
  then raise exception 'subject session RLS: helper ownership or ACL drift'; end if;

  -- Pin all 14 subject-bound policies and their ORIGINAL definitions.
  -- Abort rather than silently overwriting another chat's policy changes.
  with expected(tablename,policyname,cmd,qual,with_check) as (
    values
    ('ordax_accounts','ordax_accounts_select_own','SELECT','(( SELECT auth.uid() AS uid) = user_id)',null),
    ('ordax_accounts','ordax_accounts_update_own','UPDATE','(( SELECT auth.uid() AS uid) = user_id)','(( SELECT auth.uid() AS uid) = user_id)'),
    ('ordax_device_presence','ordax_device_presence_select_authorized','SELECT','private.ordax_can_access_product_device(device_id)',null),
    ('ordax_device_project_bindings','ordax_device_project_bindings_select_project','SELECT','private.ordax_can_access_project(project_id)',null),
    ('ordax_memory_embeddings','ordax_memory_embeddings_select_authorized','SELECT','(EXISTS ( SELECT 1
   FROM ordax_memory_items m
  WHERE ((m.memory_id = ordax_memory_embeddings.memory_id) AND ((m.owner_user_id = ( SELECT auth.uid() AS uid)) OR ((m.space_id IS NOT NULL) AND private.ordax_can_access_space(m.space_id))))))',null),
    ('ordax_memory_items','ordax_memory_items_select_authorized','SELECT','((owner_user_id = ( SELECT auth.uid() AS uid)) OR ((space_id IS NOT NULL) AND private.ordax_can_access_space(space_id)))',null),
    ('ordax_product_devices','ordax_product_devices_select_authorized','SELECT','private.ordax_can_access_product_device(device_id)',null),
    ('ordax_project_connections','ordax_project_connections_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_projects','ordax_projects_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_remote_capability_grants','ordax_remote_capability_grants_select_admin','SELECT','((owner_user_id = ( SELECT auth.uid() AS uid)) OR private.ordax_can_admin_space(space_id))',null),
    ('ordax_space_devices','ordax_space_devices_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_space_members','ordax_space_members_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_space_profile_packs','ordax_space_profile_packs_select_member','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_spaces','ordax_spaces_select_member','SELECT','private.ordax_can_access_space(space_id)',null)
  )
  select count(*) into v_expected_count from expected;
  if v_expected_count<>14
  then raise exception 'subject session RLS: expected policy count changed'; end if;

  with expected(tablename,policyname,cmd,qual,with_check) as (
    values
    ('ordax_accounts','ordax_accounts_select_own','SELECT','(( SELECT auth.uid() AS uid) = user_id)',null),
    ('ordax_accounts','ordax_accounts_update_own','UPDATE','(( SELECT auth.uid() AS uid) = user_id)','(( SELECT auth.uid() AS uid) = user_id)'),
    ('ordax_device_presence','ordax_device_presence_select_authorized','SELECT','private.ordax_can_access_product_device(device_id)',null),
    ('ordax_device_project_bindings','ordax_device_project_bindings_select_project','SELECT','private.ordax_can_access_project(project_id)',null),
    ('ordax_memory_embeddings','ordax_memory_embeddings_select_authorized','SELECT','(EXISTS ( SELECT 1
   FROM ordax_memory_items m
  WHERE ((m.memory_id = ordax_memory_embeddings.memory_id) AND ((m.owner_user_id = ( SELECT auth.uid() AS uid)) OR ((m.space_id IS NOT NULL) AND private.ordax_can_access_space(m.space_id))))))',null),
    ('ordax_memory_items','ordax_memory_items_select_authorized','SELECT','((owner_user_id = ( SELECT auth.uid() AS uid)) OR ((space_id IS NOT NULL) AND private.ordax_can_access_space(space_id)))',null),
    ('ordax_product_devices','ordax_product_devices_select_authorized','SELECT','private.ordax_can_access_product_device(device_id)',null),
    ('ordax_project_connections','ordax_project_connections_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_projects','ordax_projects_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_remote_capability_grants','ordax_remote_capability_grants_select_admin','SELECT','((owner_user_id = ( SELECT auth.uid() AS uid)) OR private.ordax_can_admin_space(space_id))',null),
    ('ordax_space_devices','ordax_space_devices_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_space_members','ordax_space_members_select_space','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_space_profile_packs','ordax_space_profile_packs_select_member','SELECT','private.ordax_can_access_space(space_id)',null),
    ('ordax_spaces','ordax_spaces_select_member','SELECT','private.ordax_can_access_space(space_id)',null)
  )
  select count(*) into v_bad_count
    from expected e
    left join pg_policies p on p.schemaname='public'
      and p.tablename=e.tablename
      and p.policyname=e.policyname
   where p.policyname is null
      or p.cmd is distinct from e.cmd
      or p.roles::text is distinct from '{authenticated}'
      or p.qual is distinct from e.qual
      or p.with_check is distinct from e.with_check;
  if v_bad_count<>0
  then raise exception 'subject session RLS: baseline policy mismatch %',v_bad_count; end if;

  if (select count(*) from pg_policies where schemaname='public')<>16
    or not exists(
      select 1 from pg_policies
      where schemaname='public' and tablename='ordax_profile_packs'
      and policyname='ordax_profile_packs_select_active'
      and cmd='SELECT' and qual='(state = ''active''::text)'
    )
    or not exists(
      select 1 from pg_policies
      where schemaname='public' and tablename='ordax_entitlement_grants'
      and policyname='ordax_entitlement_grants_select_subject'
      and qual like '%ordax_authenticated_entitlement_eligible_v1%'
    )
  then raise exception 'subject session RLS: catalog policy drift'; end if;
end;
$preflight$;

alter function private.ordax_authenticated_entitlement_eligible_v1()
  rename to ordax_authenticated_subject_eligible_v1;

-- Keep all original subject/space/device/project/memory predicates exactly.
-- The entitlement policy binds function OID; PostgreSQL updates its
-- textual name automatically when the function is renamed.
alter policy ordax_accounts_select_own
  on public.ordax_accounts
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and ((( SELECT auth.uid() AS uid) = user_id))
  );

alter policy ordax_accounts_update_own
  on public.ordax_accounts
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and ((( SELECT auth.uid() AS uid) = user_id))
  )
  with check (
    (select private.ordax_authenticated_subject_eligible_v1())
    and ((( SELECT auth.uid() AS uid) = user_id))
  );

alter policy ordax_device_presence_select_authorized
  on public.ordax_device_presence
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_product_device(device_id))
  );

alter policy ordax_device_project_bindings_select_project
  on public.ordax_device_project_bindings
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_project(project_id))
  );

alter policy ordax_memory_embeddings_select_authorized
  on public.ordax_memory_embeddings
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and ((EXISTS ( SELECT 1
   FROM ordax_memory_items m
  WHERE ((m.memory_id = ordax_memory_embeddings.memory_id) AND ((m.owner_user_id = ( SELECT auth.uid() AS uid)) OR ((m.space_id IS NOT NULL) AND private.ordax_can_access_space(m.space_id)))))))
  );

alter policy ordax_memory_items_select_authorized
  on public.ordax_memory_items
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (((owner_user_id = ( SELECT auth.uid() AS uid)) OR ((space_id IS NOT NULL) AND private.ordax_can_access_space(space_id))))
  );

alter policy ordax_product_devices_select_authorized
  on public.ordax_product_devices
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_product_device(device_id))
  );

alter policy ordax_project_connections_select_space
  on public.ordax_project_connections
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_space(space_id))
  );

alter policy ordax_projects_select_space
  on public.ordax_projects
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_space(space_id))
  );

alter policy ordax_remote_capability_grants_select_admin
  on public.ordax_remote_capability_grants
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (((owner_user_id = ( SELECT auth.uid() AS uid)) OR private.ordax_can_admin_space(space_id)))
  );

alter policy ordax_space_devices_select_space
  on public.ordax_space_devices
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_space(space_id))
  );

alter policy ordax_space_members_select_space
  on public.ordax_space_members
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_space(space_id))
  );

alter policy ordax_space_profile_packs_select_member
  on public.ordax_space_profile_packs
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_space(space_id))
  );

alter policy ordax_spaces_select_member
  on public.ordax_spaces
  using (
    (select private.ordax_authenticated_subject_eligible_v1())
    and (private.ordax_can_access_space(space_id))
  );

do $postflight$
declare
  v_unprotected integer;
  v_guarded integer;
  v_def text;
begin
  if to_regprocedure('private.ordax_authenticated_entitlement_eligible_v1()') is not null
     or to_regprocedure('private.ordax_authenticated_subject_eligible_v1()') is null
  then raise exception 'subject session RLS: duplicate/legacy helper'; end if;

  select pg_catalog.lower(pg_get_functiondef(
    'private.ordax_authenticated_subject_eligible_v1()'::regprocedure
  )) into v_def;
  if v_def not like '%auth.sessions%'
    or v_def not like '%auth.uid%'
    or v_def not like '%session_id%'
    or v_def not like '%banned_until%'
    or v_def not like '%not_after%'
  then raise exception 'subject session RLS: live session authority lost'; end if;

  select count(*) into v_unprotected from pg_policies
   where schemaname='public'
     and tablename<>'ordax_profile_packs'
     and (qual not like '%ordax_authenticated_subject_eligible_v1%'
       or (cmd='UPDATE' and with_check not like '%ordax_authenticated_subject_eligible_v1%'));
  select count(*) into v_guarded from pg_policies
   where schemaname='public'
     and qual like '%ordax_authenticated_subject_eligible_v1%';

  if v_unprotected<>0 or v_guarded<>15
  then raise exception 'subject session RLS: missing guard % / %',v_unprotected,v_guarded; end if;

  if not has_function_privilege(
       'authenticated',
       'private.ordax_authenticated_subject_eligible_v1()','EXECUTE')
    or has_function_privilege(
       'anon',
       'private.ordax_authenticated_subject_eligible_v1()','EXECUTE')
    or has_function_privilege(
       'service_role',
       'private.ordax_authenticated_subject_eligible_v1()','EXECUTE')
    or has_schema_privilege('authenticated','private','USAGE')
    or has_table_privilege('authenticated','auth.sessions','SELECT')
    or has_table_privilege('authenticated','auth.users','SELECT')
    or has_table_privilege('authenticated','public.ordax_accounts','UPDATE')
    or has_table_privilege('authenticated','public.ordax_projects','UPDATE')
  then raise exception 'subject session RLS: unexpected privilege expansion'; end if;
end;
$postflight$;

commit;
