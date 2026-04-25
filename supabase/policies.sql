-- Row Level Security policies for NetSec AI Scanner.
--
-- Apply this script from the Supabase SQL editor *after* the tables have been
-- created. It is idempotent — every statement uses IF NOT EXISTS / DROP IF
-- EXISTS so it can be re-run safely on upgrades.
--
-- The backend currently uses the ``service_role`` key (which bypasses RLS)
-- for every write. These policies are defence-in-depth so that, if a future
-- endpoint were ever wired to the anon key with a user-supplied filter, a
-- caller could still only read / write their own rows.

-- ── scans ────────────────────────────────────────────────────────────────
alter table if exists public.scans enable row level security;

drop policy if exists "Users can read their own scans" on public.scans;
create policy "Users can read their own scans"
    on public.scans for select
    using (auth.uid() = user_id);

drop policy if exists "Users can insert their own scans" on public.scans;
create policy "Users can insert their own scans"
    on public.scans for insert
    with check (auth.uid() = user_id);

drop policy if exists "Users can delete their own scans" on public.scans;
create policy "Users can delete their own scans"
    on public.scans for delete
    using (auth.uid() = user_id);

-- ── user_consent ─────────────────────────────────────────────────────────
alter table if exists public.user_consent enable row level security;

drop policy if exists "Users can read their own consent" on public.user_consent;
create policy "Users can read their own consent"
    on public.user_consent for select
    using (auth.uid() = user_id);

drop policy if exists "Users can upsert their own consent" on public.user_consent;
create policy "Users can upsert their own consent"
    on public.user_consent for insert
    with check (auth.uid() = user_id);

drop policy if exists "Users can delete their own consent" on public.user_consent;
create policy "Users can delete their own consent"
    on public.user_consent for delete
    using (auth.uid() = user_id);

-- ── global_ai_cache ──────────────────────────────────────────────────────
-- Read-only for authenticated users; writes are restricted to the service
-- role (which bypasses RLS by construction). Authenticated users may still
-- read to enable client-side cache probes if that is ever needed.
alter table if exists public.global_ai_cache enable row level security;

drop policy if exists "Authenticated users can read the global AI cache"
    on public.global_ai_cache;
create policy "Authenticated users can read the global AI cache"
    on public.global_ai_cache for select
    using (auth.role() = 'authenticated');

-- ── global_ai_cache TTL ──────────────────────────────────────────────────
-- The global cache otherwise grows indefinitely, paid for by whoever owns
-- the Supabase project (M-9). A simple "delete older than 90 days" policy
-- on the ``created_at`` column bounds it. The cache is purely optimisation;
-- evicted rows simply mean a Gemini call on the next matching scan.

create index if not exists idx_global_ai_cache_created_at
    on public.global_ai_cache (created_at);

create or replace function public.prune_global_ai_cache()
returns integer
language plpgsql
security definer
as $$
declare
    deleted integer;
begin
    delete from public.global_ai_cache
    where created_at < now() - interval '90 days';
    get diagnostics deleted = row_count;
    return deleted;
end;
$$;

-- Schedule the prune once per day if pg_cron is enabled on the project.
-- Supabase enables pg_cron by default; the DO block tolerates its absence
-- so this script keeps working on self-hosted instances without the
-- extension.
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.schedule(
            'prune-global-ai-cache',
            '0 3 * * *',
            $cron$select public.prune_global_ai_cache();$cron$
        );
    end if;
exception when others then
    raise notice 'Skipping cron schedule: %', sqlerrm;
end$$;
