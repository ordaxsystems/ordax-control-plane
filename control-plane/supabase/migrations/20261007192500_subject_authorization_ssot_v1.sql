begin;

-- Central subject-aware authorization is the SSOT for server-side Product
-- executors. Existing auth.uid()-bound helpers remain as thin RLS wrappers.

do $preflight$
declare
  bad_count integer;
begin
  if to_regprocedure('private.ordax_subject_can_access_space_v1(uuid,uuid)') is not null
     or to_regprocedure('private.ordax_subject_can_admin_space_v1(uuid,uuid)') is not null
     or to_regprocedure('private.ordax_subject_can_access_project_v1(uuid,uuid)') is not null
     or to_regprocedure('private.ordax_subject_can_access_product_device_v1(uuid,uuid)') is not null then
    raise exception 'subject authorization SSOT: helper already exists';
  end if;

  select count(*) into bad_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'private'
    and p.proname in (
      'ordax_can_access_space',
      'ordax_can_admin_space',
      'ordax_can_access_project',
      'ordax_can_access_product_device'
    )
    and (
      pg_get_userbyid(p.proowner) <> 'postgres'
      or not p.prosecdef
      or not ('search_path=""' = any(coalesce(p.proconfig, '{}'::text[])))
    );

  if bad_count <> 0 then
    raise exception 'subject authorization SSOT: existing wrapper security contract drifted';
  end if;
end;
$preflight$;

create function private.ordax_subject_can_access_space_v1(
  target_user_id uuid,
  target_space_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select target_user_id is not null
     and target_space_id is not null
     and (
       exists (
         select 1
         from public.ordax_spaces s
         where s.space_id = target_space_id
           and s.owner_user_id = target_user_id
       )
       or exists (
         select 1
         from public.ordax_space_members m
         where m.space_id = target_space_id
           and m.user_id = target_user_id
           and m.state = 'active'
       )
     );
$function$;

create function private.ordax_subject_can_admin_space_v1(
  target_user_id uuid,
  target_space_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select target_user_id is not null
     and target_space_id is not null
     and (
       exists (
         select 1
         from public.ordax_spaces s
         where s.space_id = target_space_id
           and s.owner_user_id = target_user_id
       )
       or exists (
         select 1
         from public.ordax_space_members m
         where m.space_id = target_space_id
           and m.user_id = target_user_id
           and m.state = 'active'
           and m.role in ('owner', 'admin')
       )
     );
$function$;

create function private.ordax_subject_can_access_project_v1(
  target_user_id uuid,
  target_project_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select target_user_id is not null
     and target_project_id is not null
     and exists (
       select 1
       from public.ordax_projects p
       where p.project_id = target_project_id
         and private.ordax_subject_can_access_space_v1(
           target_user_id,
           p.space_id
         )
     );
$function$;

create function private.ordax_subject_can_access_product_device_v1(
  target_user_id uuid,
  target_device_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select target_user_id is not null
     and target_device_id is not null
     and (
       exists (
         select 1
         from public.ordax_product_devices d
         where d.device_id = target_device_id
           and d.owner_user_id = target_user_id
           and d.state = 'active'
       )
       or exists (
         select 1
         from public.ordax_space_devices sd
         where sd.device_id = target_device_id
           and sd.state = 'active'
           and private.ordax_subject_can_access_space_v1(
             target_user_id,
             sd.space_id
           )
       )
     );
$function$;

revoke all on function private.ordax_subject_can_access_space_v1(uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function private.ordax_subject_can_admin_space_v1(uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function private.ordax_subject_can_access_project_v1(uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function private.ordax_subject_can_access_product_device_v1(uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

create or replace function private.ordax_can_access_space(target_space_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select private.ordax_subject_can_access_space_v1(
    (select auth.uid()),
    target_space_id
  );
$function$;

create or replace function private.ordax_can_admin_space(target_space_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select private.ordax_subject_can_admin_space_v1(
    (select auth.uid()),
    target_space_id
  );
$function$;

create or replace function private.ordax_can_access_project(target_project_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select private.ordax_subject_can_access_project_v1(
    (select auth.uid()),
    target_project_id
  );
$function$;

create or replace function private.ordax_can_access_product_device(target_device_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select private.ordax_subject_can_access_product_device_v1(
    (select auth.uid()),
    target_device_id
  );
$function$;

revoke all on function private.ordax_can_access_space(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function private.ordax_can_admin_space(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function private.ordax_can_access_project(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function private.ordax_can_access_product_device(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

grant execute on function private.ordax_can_access_space(uuid) to authenticated;
grant execute on function private.ordax_can_admin_space(uuid) to authenticated;
grant execute on function private.ordax_can_access_project(uuid) to authenticated;
grant execute on function private.ordax_can_access_product_device(uuid) to authenticated;

do $postflight$
declare
  leaked_count integer;
  wrapper_count integer;
begin
  select count(*) into leaked_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'private'
    and p.proname in (
      'ordax_subject_can_access_space_v1',
      'ordax_subject_can_admin_space_v1',
      'ordax_subject_can_access_project_v1',
      'ordax_subject_can_access_product_device_v1'
    )
    and (
      has_function_privilege('anon', p.oid, 'EXECUTE')
      or has_function_privilege('authenticated', p.oid, 'EXECUTE')
      or has_function_privilege('service_role', p.oid, 'EXECUTE')
      or has_function_privilege('ordax_edge_executor', p.oid, 'EXECUTE')
    );

  if leaked_count <> 0 then
    raise exception 'subject authorization SSOT: subject helper leaked';
  end if;

  select count(*) into wrapper_count
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'private'
    and p.proname in (
      'ordax_can_access_space',
      'ordax_can_admin_space',
      'ordax_can_access_project',
      'ordax_can_access_product_device'
    )
    and has_function_privilege('authenticated', p.oid, 'EXECUTE')
    and not has_function_privilege('anon', p.oid, 'EXECUTE')
    and not has_function_privilege('service_role', p.oid, 'EXECUTE')
    and not has_function_privilege('ordax_edge_executor', p.oid, 'EXECUTE');

  if wrapper_count <> 4 then
    raise exception 'subject authorization SSOT: RLS wrapper ACL mismatch';
  end if;
end;
$postflight$;

commit;
