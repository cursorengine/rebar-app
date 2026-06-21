-- ============================================================================
-- CommandDeck — Multi-Tenancy + Profiles + Branding  (migration 2)
-- ----------------------------------------------------------------------------
-- RUN THIS *AFTER* supabase_setup.sql, in Supabase → SQL Editor.
-- Idempotent: safe to run more than once.
--
-- WHY: until now every logged-in user could see every row (policies were
-- `using(true)`). This scopes all core data to its owner via a user_id column,
-- so a second account no longer sees the first account's quotes/loads/etc.
--
-- It also adds a `profiles` table (the carrier's own name/logo/phone) and makes
-- the customer-facing RPCs return that branding, so accept/track/driver pages
-- show the CARRIER's brand instead of the hardcoded product name.
--
-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ ONE THING YOU MUST EDIT: put your main account's user id below.          │
-- │ Find it in Supabase → Authentication → Users → copy the "UID" of your    │
-- │ primary account, and paste it between the quotes on the next line.       │
-- └─────────────────────────────────────────────────────────────────────────┘
-- ============================================================================

-- ---------------------------------------------------------------------------
-- SECTION 1 — Add an owner column to every core table.
-- New rows auto-fill user_id from the logged-in user (default auth.uid()).
-- ---------------------------------------------------------------------------
alter table public.quotes           add column if not exists user_id uuid default auth.uid();
alter table public.quote_acceptance add column if not exists user_id uuid default auth.uid();
alter table public.load_tracking    add column if not exists user_id uuid default auth.uid();
alter table public.leads            add column if not exists user_id uuid default auth.uid();
alter table public.jobs             add column if not exists user_id uuid default auth.uid();
alter table public.expenses         add column if not exists user_id uuid default auth.uid();
-- quote_requests come from the public web form (no logged-in user), so its
-- user_id stays nullable with NO default — see Section 4 for how it's scoped.
alter table public.quote_requests   add column if not exists user_id uuid;


-- ---------------------------------------------------------------------------
-- SECTION 2 — Backfill existing rows to you.
-- Auto-detects your account: if you have exactly ONE user it uses that one,
-- so you normally do NOT have to edit anything. If you have multiple accounts,
-- paste the correct UID between the quotes in `override` below
-- (Supabase > Authentication > Users > copy UID). Leaving it blank = auto.
-- ---------------------------------------------------------------------------
do $$
declare
  override text := '066700df-2d92-4f66-a9f9-e1394445e15e';   -- primary account (owns existing data)
  owner_uid uuid;
  n_users   int;
begin
  if length(trim(override)) > 0 then
    owner_uid := trim(override)::uuid;
  else
    select count(*) into n_users from auth.users;
    if n_users = 0 then
      raise exception 'No users exist yet — create/sign in to your account first, then re-run.';
    elsif n_users > 1 then
      raise exception 'Multiple accounts found — paste the correct UID into `override` (Supabase > Authentication > Users).';
    end if;
    select id into owner_uid from auth.users limit 1;
  end if;

  update public.quotes           set user_id = owner_uid where user_id is null;
  update public.quote_acceptance set user_id = owner_uid where user_id is null;
  update public.load_tracking    set user_id = owner_uid where user_id is null;
  update public.leads            set user_id = owner_uid where user_id is null;
  update public.jobs             set user_id = owner_uid where user_id is null;
  update public.expenses         set user_id = owner_uid where user_id is null;
  update public.quote_requests   set user_id = owner_uid where user_id is null;
end $$;


-- ---------------------------------------------------------------------------
-- SECTION 3 — Owner-scoped policies for the strictly-private tables.
-- (Replaces the blanket "auth full" policies from supabase_setup.sql.)
-- ---------------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'quotes','quote_acceptance','load_tracking','leads','jobs','expenses'
  ]
  loop
    execute format('drop policy if exists "auth full %1$s" on public.%1$I;', t);
    execute format('drop policy if exists "owner all %1$s" on public.%1$I;', t);
    execute format(
      'create policy "owner all %1$s" on public.%1$I
         for all to authenticated
         using (user_id = auth.uid())
         with check (user_id = auth.uid());', t);
  end loop;
end $$;


-- ---------------------------------------------------------------------------
-- SECTION 4 — quote_requests: anon may still submit; an owner sees their own
-- rows plus any not-yet-assigned ones (the shared inbound pool). When the web
-- form later embeds a carrier id, set user_id at insert time and tighten this.
-- ---------------------------------------------------------------------------
drop policy if exists "auth full quote_requests"   on public.quote_requests;
drop policy if exists "anon insert quote_requests" on public.quote_requests;
drop policy if exists "owner read quote_requests"  on public.quote_requests;
drop policy if exists "owner edit quote_requests"  on public.quote_requests;
drop policy if exists "owner del quote_requests"   on public.quote_requests;

create policy "anon insert quote_requests" on public.quote_requests
  for insert to anon with check (true);
create policy "owner read quote_requests" on public.quote_requests
  for select to authenticated using (user_id = auth.uid() or user_id is null);
create policy "owner edit quote_requests" on public.quote_requests
  for update to authenticated using (user_id = auth.uid() or user_id is null) with check (true);
create policy "owner del quote_requests" on public.quote_requests
  for delete to authenticated using (user_id = auth.uid() or user_id is null);


-- ---------------------------------------------------------------------------
-- SECTION 5 — Carrier profile (branding + settings), one row per user.
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  user_id      uuid primary key default auth.uid(),
  company_name text,
  contact_name text,
  phone        text,
  email        text,
  address      text,
  website      text,
  logo_url     text,
  gst_rate     numeric,
  updated_at   timestamptz default now()
);

alter table public.profiles enable row level security;
drop policy if exists "owner profile" on public.profiles;
create policy "owner profile" on public.profiles
  for all to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());


-- ---------------------------------------------------------------------------
-- SECTION 6 — Re-create the public RPCs so they ALSO return the carrier's
-- branding (joined from profiles via the row's owner). SECURITY DEFINER, so
-- they can read profiles regardless of RLS, but still only by secret token.
-- ---------------------------------------------------------------------------
create or replace function public.get_acceptance(p_accept_id text)
returns jsonb language sql security definer set search_path = public, pg_temp as $$
  select to_jsonb(t) from (
    select a.accept_id, a.quote_num, a.company, a.contact, a.pickup, a.delivery,
           a.load_type, a.weight, a.pickup_date, a.total, a.status, a.responded_at,
           p.company_name as carrier_name, p.phone as carrier_phone,
           p.email as carrier_email, p.logo_url as carrier_logo, p.website as carrier_website
    from public.quote_acceptance a
    left join public.profiles p on p.user_id = a.user_id
    where a.accept_id = p_accept_id
    limit 1
  ) t;
$$;

create or replace function public.get_tracking(p_tracking_id text)
returns jsonb language sql security definer set search_path = public, pg_temp as $$
  select to_jsonb(t) from (
    select lt.tracking_id, lt.quote_num, lt.company, lt.pickup, lt.delivery, lt.load_type,
           lt.weight, lt.status, lt.pickup_confirmed_at, lt.delivered_at, lt.driver_note,
           lt.pod_urls, lt.updated_at,
           p.company_name as carrier_name, p.phone as carrier_phone,
           p.email as carrier_email, p.logo_url as carrier_logo, p.website as carrier_website
    from public.load_tracking lt
    left join public.profiles p on p.user_id = lt.user_id
    where lt.tracking_id = p_tracking_id
    limit 1
  ) t;
$$;

create or replace function public.get_driver_load(p_token text)
returns jsonb language sql security definer set search_path = public, pg_temp as $$
  select to_jsonb(t) from (
    select lt.tracking_id, lt.quote_num, lt.company, lt.pickup, lt.delivery, lt.load_type,
           lt.weight, lt.status, lt.pickup_confirmed_at, lt.delivered_at, lt.driver_note,
           lt.pod_urls,
           p.company_name as carrier_name, p.phone as carrier_phone
    from public.load_tracking lt
    left join public.profiles p on p.user_id = lt.user_id
    where lt.driver_token = p_token
    limit 1
  ) t;
$$;

-- (respond_to_quote and driver_update_load are unchanged from supabase_setup.sql.)
do $$
declare fn text;
begin
  foreach fn in array array[
    'public.get_acceptance(text)',
    'public.get_tracking(text)',
    'public.get_driver_load(text)'
  ]
  loop
    execute format('revoke all on function %s from public;', fn);
    execute format('grant execute on function %s to anon, authenticated;', fn);
  end loop;
end $$;


-- ============================================================================
-- VERIFY (optional):
--   select relname, relrowsecurity from pg_class
--   where relname in ('quotes','quote_acceptance','load_tracking','leads',
--                     'jobs','expenses','quote_requests','profiles');
--   select count(*) from public.quotes where user_id is null;  -- expect 0
-- ============================================================================
