begin;

-- Supabase Auth eligibility is the only revocation authority here.
-- Replaces the narrowly scoped deletion trigger with the complete set of
-- trust-loss transitions already enforced by the canonical v2 issuer.
do $preflight$
begin
  if to_regprocedure('public.ordax_issue_account_default_entitlement_v2(uuid,text,integer)') is null
     or to_regprocedure('private.ordax_revoke_defaults_on_auth_soft_delete_v1()') is null
     or exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
       where n.nspname='private' and p.proname='ordax_revoke_defaults_on_auth_ineligible_v2')
     or not exists (
       select 1 from pg_trigger
       where tgrelid='auth.users'::regclass
       and tgname='ordax_auth_user_soft_delete_default_entitlements'
       and not tgisinternal and tgenabled='O'
     )
  then
    raise exception 'Auth eligibility v2: expected previous boundary missing or replacement exists';
  end if;
end;
$preflight$;

create function private.ordax_revoke_defaults_on_auth_ineligible_v2()
returns trigger
language plpgsql
security definer
set search_path = ''
as $trigger$
declare
  v_now timestamptz;
  v_origin text;
begin
  if tg_op <> 'UPDATE' or old.id is distinct from new.id then
    raise exception 'Auth eligibility v2: invalid trigger invocation';
  end if;

  if old.deleted_at is null and new.deleted_at is not null then
    v_origin := 'account_deleted:';
  elsif old.is_anonymous is false and new.is_anonymous is true
     or (old.confirmed_at is not null and new.confirmed_at is null) then
    v_origin := 'account_ineligible:';
  else
    raise exception 'Auth eligibility v2: unexpected transition';
  end if;

  v_now:=pg_catalog.clock_timestamp();

  -- The trigger and issuer are serialized by the auth.users row lock.
  -- Emit the receipt in the very same Auth transaction as the trust loss.
  with revoked as (
    update public.ordax_entitlement_grants g
       set valid_until=greatest(
         v_now, g.valid_from + interval '1 microsecond')
     where g.user_id=new.id
       and g.source='product-default'
       and g.valid_from<=v_now
       and (g.valid_until is null or g.valid_until>v_now)
    returning g.grant_id,g.entitlement_key,g.policy_version
  )
  insert into private.ordax_default_entitlement_events(
    source,source_event_id,event_kind,grant_id,
    subject_user_id,entitlement_key,policy_version
  )
  select 'product-default',
    v_origin || r.grant_id::text,
    'revoked',r.grant_id,new.id,r.entitlement_key,r.policy_version
  from revoked r;

  return new;
end;
$trigger$;

revoke all on function private.ordax_revoke_defaults_on_auth_ineligible_v2()
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_memory_executor,
       ordax_profile_pack_executor, ordax_entitlement_default_executor;

drop trigger ordax_auth_user_soft_delete_default_entitlements on auth.users;

-- No second active trigger or legacy entry point remains.
drop function private.ordax_revoke_defaults_on_auth_soft_delete_v1();

-- No UPDATE OF list: confirmed_at is a stored generated column and changes
-- when its underlying email/phone confirmation fields are updated.
create trigger ordax_auth_user_ineligible_default_entitlements
after update on auth.users
for each row
when (
  (old.deleted_at is null and new.deleted_at is not null)
  or (old.is_anonymous is false and new.is_anonymous is true)
  or (old.confirmed_at is not null and new.confirmed_at is null)
)
execute function private.ordax_revoke_defaults_on_auth_ineligible_v2();

do $postflight$
declare
  v_def text;
begin
  select pg_get_triggerdef(t.oid) into v_def
  from pg_trigger t
  where t.tgrelid='auth.users'::regclass
    and t.tgname='ordax_auth_user_ineligible_default_entitlements'
    and not t.tgisinternal and t.tgenabled='O';

  if v_def is null
     or v_def not like '%AFTER UPDATE ON auth.users%'
     or v_def not like '%old.confirmed_at%'
     or v_def not like '%new.is_anonymous%'
     or v_def not like '%new.deleted_at%'
  then raise exception 'Auth eligibility v2: trigger contract invalid'; end if;

  if to_regprocedure('private.ordax_revoke_defaults_on_auth_soft_delete_v1()') is not null
     or exists(select 1 from pg_trigger where
       tgrelid='auth.users'::regclass
       and tgname='ordax_auth_user_soft_delete_default_entitlements')
     or has_function_privilege('authenticated',
       'private.ordax_revoke_defaults_on_auth_ineligible_v2()','EXECUTE')
     or has_function_privilege('service_role',
       'private.ordax_revoke_defaults_on_auth_ineligible_v2()','EXECUTE')
     or has_schema_privilege('ordax_entitlement_default_executor','private','USAGE')
     or to_regprocedure('public.ordax_revoke_default_entitlement_v1(uuid,text)') is not null
  then raise exception 'Auth eligibility v2: stale authority or privilege regression'; end if;
end;
$postflight$;

commit;
