-- Ruang / Komunikasi Data
-- Jalankan sekali di Supabase Dashboard > SQL Editor.
-- Semua tabel menggunakan RLS. Jangan masukkan service_role key ke frontend.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username = lower(username) and username ~ '^[a-z0-9_]{3,20}$'),
  display_name text not null check (char_length(display_name) between 1 and 32),
  public_key text,
  created_at timestamptz not null default now()
);

create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 12000),
  created_at timestamptz not null default now(),
  constraint messages_no_self_chat check (sender_id <> recipient_id)
);

create index if not exists messages_sender_created_idx on public.messages (sender_id, created_at desc);
create index if not exists messages_recipient_created_idx on public.messages (recipient_id, created_at desc);

alter table public.profiles add column if not exists public_key text;

alter table public.messages drop constraint if exists messages_body_check;
alter table public.messages add constraint messages_body_check check (char_length(body) between 1 and 12000);

alter table public.profiles enable row level security;
alter table public.messages enable row level security;

drop policy if exists "Signed-in users can find profiles" on public.profiles;
drop policy if exists "Authenticated users can find profiles" on public.profiles;
create policy "Signed-in users can find profiles" on public.profiles for select to authenticated using (true);

drop policy if exists "Users can insert their own profile" on public.profiles;
drop policy if exists "Users can create their own profile" on public.profiles;
create policy "Users can insert their own profile" on public.profiles for insert to authenticated with check ((select auth.uid()) = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile" on public.profiles for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

drop policy if exists "Participants can read their messages" on public.messages;
drop policy if exists "Members can read messages" on public.messages;
create policy "Participants can read their messages" on public.messages for select to authenticated using ((select auth.uid()) = sender_id or (select auth.uid()) = recipient_id);

drop policy if exists "Users can send messages as themselves" on public.messages;
drop policy if exists "Members can send messages as themselves" on public.messages;
create policy "Users can send messages as themselves" on public.messages for insert to authenticated with check ((select auth.uid()) = sender_id and sender_id <> recipient_id);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare requested_username text; requested_name text;
begin
  requested_username := lower(trim(coalesce(new.raw_user_meta_data ->> 'username', '')));
  requested_name := trim(coalesce(new.raw_user_meta_data ->> 'display_name', ''));

  -- User yang dibuat dari Dashboard Auth biasanya tidak punya metadata profil.
  -- Buat profil sementara yang valid; aplikasi akan meminta user melengkapinya.
  if requested_username !~ '^[a-z0-9_]{3,20}$'
     or requested_username ~ '^u_[0-9a-f]{16}$'
     or char_length(requested_name) < 1
     or char_length(requested_name) > 32 then
    requested_username := 'u_' || substr(replace(new.id::text, '-', ''), 1, 16);
    requested_name := 'Lengkapi Profil';
  end if;

  insert into public.profiles (id, username, display_name)
  values (new.id, requested_username, requested_name);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
exception when undefined_object then
  raise notice 'Publication supabase_realtime belum tersedia; aktifkan Realtime untuk tabel messages di Dashboard.';
end $$;

grant usage on schema public to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert on public.messages to authenticated;
grant usage, select on sequence public.messages_id_seq to authenticated;