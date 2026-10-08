begin;

-- Repair uncovered FK lookups discovered after Profile Pack authority was
-- applied. The Memory FK predates this branch; its existing partial index does
-- not cover the composite (project_id,space_id) reference.
do $preflight$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid='public.ordax_memory_items'::regclass
      and conname='ordax_memory_items_project_space_fk' and contype='f'
  ) or not exists (
    select 1 from pg_constraint
    where conrelid='private.ordax_space_profile_pack_events'::regclass
      and conname='ordax_space_profile_pack_events_actor_user_id_fkey'
      and contype='f'
  ) then
    raise exception 'FK index hardening: expected canonical FK missing';
  end if;
end;
$preflight$;

create index ordax_memory_items_project_space_fk_idx
  on public.ordax_memory_items(project_id,space_id);

create index ordax_space_profile_pack_events_actor_fk_idx
  on private.ordax_space_profile_pack_events(actor_user_id);

do $postflight$
begin
  if (
    select count(*) from pg_index i
    join pg_class idx on idx.oid=i.indexrelid
    where idx.oid in (
      'public.ordax_memory_items_project_space_fk_idx'::regclass,
      'private.ordax_space_profile_pack_events_actor_fk_idx'::regclass
    )
    and i.indisvalid and i.indisready and i.indislive
  ) <> 2 then
    raise exception 'FK index hardening: an index is not valid/ready/live';
  end if;
end;
$postflight$;

commit;
