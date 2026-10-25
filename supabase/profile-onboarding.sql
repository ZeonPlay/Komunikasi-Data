-- Ruang / Komunikasi Data
-- Jalankan sekali di Supabase Dashboard > SQL Editor pada project yang sudah berjalan.
-- Tidak mengubah data anggota yang profilnya sudah lengkap.
-- Akun Auth baru tanpa metadata (mis. dibuat manual dari Dashboard) akan diberi
-- username sementara u_<16 karakter hex> dan diminta melengkapi profil setelah login.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  requested_username text;
  requested_name text;
begin
  requested_username := lower(trim(coalesce(new.raw_user_meta_data ->> 'username', '')));
  requested_name := trim(coalesce(new.raw_user_meta_data ->> 'display_name', ''));

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
