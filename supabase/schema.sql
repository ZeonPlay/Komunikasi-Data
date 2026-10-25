-- Komunikasi Data: secure direct-message schema
-- Run this in Supabase SQL Editor before using the website.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  handle text not null unique check (handle ~ '^[a-z0-9_]{3,20}$'),
  display_name text not null check (char_length(display_name) between 1 and 40),
  created_at timestamptz not null default now()
);

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  user_a uuid not null references auth.users(id) on delete cascade,
  user_b uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  constraint different_members check (user_a <> user_b),
  constraint canonical_members check (user_a < user_b),
  unique (user_a, user_b)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);

create index if not exists messages_conversation_created_idx
  on public.messages (conversation_id, created_at);

alter table public.profiles enable row level security;
alter table public.conversations enable row level security;
alter table public.messages enable row level security;

-- Profiles are searchable by handle; only authenticated clients can read them.
create policy "Authenticated users can find profiles"
  on public.profiles for select to authenticated
  using (true);

create policy "Users can create their own profile"
  on public.profiles for insert to authenticated
  with check (id = auth.uid());

create policy "Users can update their own profile"
  on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

create policy "Members can read their conversations"
  on public.conversations for select to authenticated
  using (auth.uid() = user_a or auth.uid() = user_b);

create policy "Members can create conversations"
  on public.conversations for insert to authenticated
  with check (
    (auth.uid() = user_a or auth.uid() = user_b)
    and user_a < user_b
  );

create policy "Members can read messages"
  on public.messages for select to authenticated
  using (
    exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and (c.user_a = auth.uid() or c.user_b = auth.uid())
    )
  );

create policy "Members can send messages as themselves"
  on public.messages for insert to authenticated
  with check (
    sender_id = auth.uid()
    and exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and (c.user_a = auth.uid() or c.user_b = auth.uid())
    )
  );

-- Realtime messages. If already in publication, ignore the duplicate manually.
alter publication supabase_realtime add table public.messages;
