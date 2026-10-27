-- Migration untuk database Ruang yang sudah berjalan.
-- Jalankan sekali di Supabase Dashboard > SQL Editor sebelum deploy E2EE.
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS public_key text;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS key_backup text;
ALTER TABLE public.messages DROP CONSTRAINT IF EXISTS messages_body_check;
ALTER TABLE public.messages ADD CONSTRAINT messages_body_check CHECK (char_length(body) BETWEEN 1 AND 12000);
