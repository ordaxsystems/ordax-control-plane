begin;

-- Follow-up hardening from Supabase's post-DDL advisors.
-- Cover every Product action foreign key used by cascades/joins and keep the
-- private queue inaccessible even if the private schema is exposed by mistake.

create index if not exists ordax_product_action_project_space_idx
  on private.ordax_product_action_requests(project_id, space_id);

create index if not exists ordax_product_action_space_idx
  on private.ordax_product_action_requests(space_id);

create index if not exists ordax_product_action_grant_idx
  on private.ordax_product_action_requests(grant_id);

alter table private.ordax_product_action_requests enable row level security;
alter table private.ordax_product_action_events enable row level security;
alter table private.ordax_product_action_audit enable row level security;

commit;
