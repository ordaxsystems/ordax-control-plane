begin;

-- Signed Supabase JWT access tokens can survive logout until expiration.
-- Entitlement SELECT is sensitive: require the token's live session_id to
-- match the canonical auth.sessions row belonging to auth.uid().
-- Do not grant direct access to auth.sessions and do not create a second
-- session SSOT.
do $preflight$
declare
  v_previous text;
begin
  if to_regprocedure(
    'private.ordax_authenticated_entitlement_eligible_v1()'
  ) is null then
    raise exception 'entitlement session authority: canonical helper missing';
  end if;

  select pg_catalog.lower(pg_get_functiondef(
    'private.ordax_authenticated_entitlement_eligible_v1()'::regprocedure
  )) into v_previous;

  if v_previous not like '%auth.users%'
     or v_previous not like '%ordax_accounts%'
     or v_previous not like '%banned_until%'
     or v_previous like '%auth.sessions%'
  then
    raise exception 'entitlement session authority: helper baseline drifted';
  end if;

  if not has_function_privilege(
      'authenticated',
      'private.ordax_authenticated_entitlement_eligible_v1()',
      'EXECUTE')
    or has_schema_privilege('authenticated','private','USAGE')
    or has_table_privilege('authenticated','auth.sessions','SELECT')
  then
    raise exception 'entitlement session authority: permission baseline drifted';
  end if;
end;
$preflight$;

create or replace function private.ordax_authenticated_entitlement_eligible_v1()
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $function$
declare
  v_subject_user_id uuid;
  v_claims jsonb;
  v_session_text text;
  v_session_id uuid;
begin
  v_subject_user_id:=auth.uid();
  if v_subject_user_id is null then
    return false;
  end if;

  -- These claims are supplied by Supabase/PostgREST after JWT verification;
  -- a raw user_id or a caller-selected session_id is never accepted.
  v_claims:=auth.jwt();
  if v_claims is null
     or pg_catalog.jsonb_typeof(v_claims)<>'object'
     or pg_catalog.jsonb_typeof(v_claims->'session_id')<>'string' then
    return false;
  end if;

  v_session_text:=v_claims->>'session_id';
  if v_session_text is null
     or v_session_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    return false;
  end if;
  v_session_id:=v_session_text::uuid;

  return exists (
    select 1
      from auth.sessions s
      join auth.users u on u.id=s.user_id
      join public.ordax_accounts a on a.user_id=u.id
     where s.id=v_session_id
       and s.user_id=v_subject_user_id
       and u.deleted_at is null
       and u.is_anonymous is false
       and u.confirmed_at is not null
       and (u.banned_until is null
         or u.banned_until<=pg_catalog.clock_timestamp())
       and (s.not_after is null
         or s.not_after>pg_catalog.clock_timestamp())
  );
end;
$function$;

-- CREATE OR REPLACE retains the original function OID and permissions;
-- assert exclusive authenticated EXECUTE and no relationship grants.
do $postflight$
declare
  v_policy text;
  v_definition text;
begin
  select pg_catalog.lower(p.qual) into v_policy
  from pg_policies p
  where p.schemaname='public'
    and p.tablename='ordax_entitlement_grants'
    and p.policyname='ordax_entitlement_grants_select_subject';

  select pg_catalog.lower(pg_get_functiondef(
    'private.ordax_authenticated_entitlement_eligible_v1()'::regprocedure
  )) into v_definition;

  if v_policy is null
     or v_policy not like '%ordax_authenticated_entitlement_eligible_v1%'
     or v_policy not like '%clock_timestamp%'
     or v_policy not like '%auth.uid%'
     or v_policy not like '%ordax_can_access_space%'
     or v_definition not like '%auth.sessions%'
     or v_definition not like '%session_id%'
     or v_definition not like '%s.user_id = v_subject_user_id%'
     or v_definition not like '%not_after%'
     or v_definition not like '%banned_until%'
  then
    raise exception 'entitlement session authority: policy or function regression';
  end if;

  if not has_function_privilege(
       'authenticated',
       'private.ordax_authenticated_entitlement_eligible_v1()',
       'EXECUTE')
     or has_function_privilege(
       'anon',
       'private.ordax_authenticated_entitlement_eligible_v1()',
       'EXECUTE')
     or has_function_privilege(
       'service_role',
       'private.ordax_authenticated_entitlement_eligible_v1()',
       'EXECUTE')
     or has_schema_privilege('authenticated','private','USAGE')
     or has_table_privilege('authenticated','auth.sessions','SELECT')
     or has_table_privilege('authenticated','auth.users','SELECT')
     or has_table_privilege(
       'authenticated','public.ordax_entitlement_grants','UPDATE')
  then
    raise exception 'entitlement session authority: unexpected ACL expansion';
  end if;

  if not exists (
    select 1 from pg_proc p
    where p.oid='private.ordax_authenticated_entitlement_eligible_v1()'::regprocedure
      and p.prosecdef
      and p.provolatile='v'
      and p.pronargs=0
      and pg_get_userbyid(p.proowner)='postgres'
  ) then
    raise exception 'entitlement session authority: function ownership/volatility changed';
  end if;
end;
$postflight$;

commit;
