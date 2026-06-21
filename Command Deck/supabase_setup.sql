-- ============================================================================
-- CommandDeck — Supabase Security + Driver Capture Loop
-- ----------------------------------------------------------------------------
-- Paste this whole file into Supabase → SQL Editor → Run.
-- It is IDEMPOTENT: safe to run more than once.
--
-- WHAT THIS DOES
--   1. Turns on Row Level Security (RLS) for every table.
--   2. Gives your logged-in dispatcher account full access to everything.
--   3. Locks the public (anon) key down so it can ONLY:
--        - submit a web quote request   (insert into quote_requests)
--        - load + respond to a quote     (via RPC, by secret accept_id)
--        - load a shipment for tracking  (via RPC, by secret tracking_id)
--        - load + update a load as driver (via RPC, by secret driver_token)
--      The anon key can NO LONGER read or dump your customer tables directly.
--   4. Adds the driver capture loop: new columns + a POD photo bucket + the
--      RPC the driver page uses to update status and attach proof of delivery.
--
-- DESIGN NOTE — why RPCs instead of direct table writes:
--   Your accept/track/driver pages all run with the public anon key, which is
--   visible in page source. If the anon key could UPDATE tables directly, a
--   single unfiltered request could mass-edit every row. Instead, all public
--   writes go through SECURITY DEFINER functions that check the secret token
--   server-side, so a caller can only touch the one row whose token they hold.
-- ============================================================================


-- ============================================================================
-- SECTION 1 — Driver-loop schema additions (load_tracking)
-- ============================================================================
alter table public.load_tracking add column if not exists driver_token text;
alter table public.load_tracking add column if not exists driver_note  text;
alter table public.load_tracking add column if not exists pod_urls     jsonb default '[]'::jsonb;
alter table public.load_tracking add column if not exists delivered_at timestamptz;

-- The dispatcher caches the driver token on the quote so the link survives a reload.
alter table public.quotes add column if not exists driver_token text;

-- Fast + unique lookups by the driver's secret token.
create unique index if not exists load_tracking_driver_token_idx
  on public.load_tracking (driver_token)
  where driver_token is not null;


-- ============================================================================
-- SECTION 2 — Enable RLS on every table
-- (With RLS on and no anon policy, the anon key is denied by default.)
-- ============================================================================
alter table public.quotes            enable row level security;
alter table public.quote_requests    enable row level security;
alter table public.quote_acceptance  enable row level security;
alter table public.load_tracking     enable row level security;
alter table public.leads             enable row level security;
alter table public.jobs              enable row level security;
alter table public.expenses          enable row level security;


-- ============================================================================
-- SECTION 3 — Dispatcher (authenticated) gets full access to everything
-- ============================================================================
do $$
declare t text;
begin
  foreach t in array array[
    'quotes','quote_requests','quote_acceptance','load_tracking','leads','jobs','expenses'
  ]
  loop
    execute format('drop policy if exists "auth full %1$s" on public.%1$I;', t);
    execute format(
      'create policy "auth full %1$s" on public.%1$I
         for all to authenticated using (true) with check (true);', t);
  end loop;
end $$;


-- ============================================================================
-- SECTION 4 — The ONLY direct anon privilege: submit a web quote request
-- (Everything else for anon goes through the RPCs in Section 5.)
-- ============================================================================
drop policy if exists "anon insert quote_requests" on public.quote_requests;
create policy "anon insert quote_requests" on public.quote_requests
  for insert to anon with check (true);


-- ============================================================================
-- SECTION 5 — Public RPCs (SECURITY DEFINER, token-gated)
-- These bypass RLS internally but only ever act on the single row whose
-- secret id/token the caller supplies.
-- ============================================================================

-- 5a. Customer loads their quote to approve/decline (by secret accept_id).
create or replace function public.get_acceptance(p_accept_id text)
returns jsonb
language sql
security definer
set search_path = public, pg_temp
as $$
  select to_jsonb(t) from (
    select accept_id, quote_num, company, contact, pickup, delivery,
           load_type, weight, pickup_date, total, status, responded_at
    from public.quote_acceptance
    where accept_id = p_accept_id
    limit 1
  ) t;
$$;

-- 5b. Customer submits Accept / Decline (only valid while still Pending).
create or replace function public.respond_to_quote(p_accept_id text, p_decision text)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare r jsonb;
begin
  if p_decision not in ('Accepted','Declined') then
    raise exception 'invalid decision';
  end if;

  update public.quote_acceptance
     set status = p_decision, responded_at = now()
   where accept_id = p_accept_id
     and status = 'Pending';

  select to_jsonb(t) into r from (
    select accept_id, status, responded_at
    from public.quote_acceptance
    where accept_id = p_accept_id
  ) t;

  if r is null then raise exception 'not found'; end if;
  return r;
end;
$$;

-- 5c. Customer loads live tracking (by secret tracking_id). No driver_token leaks.
create or replace function public.get_tracking(p_tracking_id text)
returns jsonb
language sql
security definer
set search_path = public, pg_temp
as $$
  select to_jsonb(t) from (
    select tracking_id, quote_num, company, pickup, delivery, load_type, weight,
           status, pickup_confirmed_at, delivered_at, driver_note, pod_urls
    from public.load_tracking
    where tracking_id = p_tracking_id
    limit 1
  ) t;
$$;

-- 5d. Driver loads their assigned load (by secret driver_token).
create or replace function public.get_driver_load(p_token text)
returns jsonb
language sql
security definer
set search_path = public, pg_temp
as $$
  select to_jsonb(t) from (
    select tracking_id, quote_num, company, pickup, delivery, load_type, weight,
           status, pickup_confirmed_at, delivered_at, driver_note, pod_urls
    from public.load_tracking
    where driver_token = p_token
    limit 1
  ) t;
$$;

-- 5e. Driver updates status + note, and appends POD photo URLs.
create or replace function public.driver_update_load(
  p_token    text,
  p_status   text,
  p_note     text  default null,
  p_pod_urls jsonb default '[]'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare r jsonb;
begin
  if p_status not in ('Picked Up','In Transit','Delivered') then
    raise exception 'invalid status';
  end if;

  update public.load_tracking lt set
    status              = p_status,
    driver_note         = coalesce(nullif(p_note, ''), lt.driver_note),
    pod_urls            = coalesce(lt.pod_urls, '[]'::jsonb) || coalesce(p_pod_urls, '[]'::jsonb),
    pickup_confirmed_at = case when p_status = 'Picked Up' and lt.pickup_confirmed_at is null
                               then now() else lt.pickup_confirmed_at end,
    delivered_at        = case when p_status = 'Delivered' then now() else lt.delivered_at end,
    updated_at          = now()
  where lt.driver_token = p_token;

  if not found then raise exception 'invalid token'; end if;

  select to_jsonb(t) into r from (
    select tracking_id, status, pickup, delivery, load_type, weight, quote_num,
           company, driver_note, pod_urls, pickup_confirmed_at, delivered_at
    from public.load_tracking
    where driver_token = p_token
  ) t;
  return r;
end;
$$;

-- Lock down + expose the RPCs to the public roles.
do $$
declare fn text;
begin
  foreach fn in array array[
    'public.get_acceptance(text)',
    'public.respond_to_quote(text, text)',
    'public.get_tracking(text)',
    'public.get_driver_load(text)',
    'public.driver_update_load(text, text, text, jsonb)'
  ]
  loop
    execute format('revoke all on function %s from public;', fn);
    execute format('grant execute on function %s to anon, authenticated;', fn);
  end loop;
end $$;


-- ============================================================================
-- SECTION 6 — POD (proof-of-delivery) photo storage
-- Public-read bucket so the photo is viewable from the customer tracking page
-- by its URL; the path includes the secret token so URLs aren't guessable.
-- Anyone (a driver, no login) may UPLOAD; nobody anon may delete/overwrite.
-- ============================================================================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('pod', 'pod', true, 10485760, array['image/jpeg','image/png','image/webp','application/pdf'])
on conflict (id) do update
  set public = true,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "pod public upload"  on storage.objects;
drop policy if exists "pod dispatcher all" on storage.objects;

-- Drivers (anon) may upload only.
create policy "pod public upload" on storage.objects
  for insert to anon
  with check (bucket_id = 'pod');

-- Dispatcher may manage everything in the bucket.
create policy "pod dispatcher all" on storage.objects
  for all to authenticated
  using (bucket_id = 'pod')
  with check (bucket_id = 'pod');


-- ============================================================================
-- SECTION 7 — Verify (optional). Run these to confirm the lockdown took.
-- ============================================================================
-- Every table should show rowsecurity = true:
--   select relname, relrowsecurity from pg_class
--   where relname in ('quotes','quote_requests','quote_acceptance',
--                     'load_tracking','leads','jobs','expenses');
--
-- The 5 RPCs should be listed:
--   select proname from pg_proc
--   where proname in ('get_acceptance','respond_to_quote','get_tracking',
--                     'get_driver_load','driver_update_load');
-- ============================================================================
