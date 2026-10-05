-- Run against the development control plane. All fixture mutations roll back.
begin;
do $$
declare a jsonb; b jsonb;
begin
  a := public.ordax_setup_device_v1('999999999',repeat('c',64),'setup-regression',repeat('d',64));
  b := public.ordax_setup_device_v1('999999999',repeat('c',64),'setup-regression',repeat('d',64));
  if a->>'device_id' <> b->>'device_id' or b->>'reused' <> 'true' then
    raise exception 'idempotency_failed';
  end if;
  begin
    perform public.ordax_setup_device_v1('999999998',repeat('c',64),'attacker',repeat('e',64));
    raise exception 'owner_check_failed';
  exception when others then
    if sqlerrm <> 'device_owner_mismatch' then raise; end if;
  end;
  update public.ordax_device_credentials set revoked_at=now() where token_sha256=repeat('d',64);
  begin
    perform public.ordax_setup_device_v1('999999999',repeat('c',64),'setup-regression',repeat('d',64));
    raise exception 'replay_check_failed';
  exception when others then
    if sqlerrm <> 'token_replay_rejected' then raise; end if;
  end;
  if has_function_privilege('anon','public.ordax_setup_device_v1(text,text,text,text)','EXECUTE')
     or has_function_privilege('authenticated','public.ordax_setup_device_v1(text,text,text,text)','EXECUTE')
  then raise exception 'privilege_leak'; end if;
end $$;
rollback;
