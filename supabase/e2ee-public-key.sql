-- Migration untuk database Ruang yang sudah berjalan.
-- Jalankan sekali di Supabase Dashboard > SQL Editor sebelum deploy E2EE.
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS public_key text;

CREATE TABLE IF NOT EXISTS public.private_key_backups (
  user_id uuid PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  key_backup text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.private_key_backups ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can read their own key backup" ON public.private_key_backups;
CREATE POLICY "Users can read their own key backup" ON public.private_key_backups FOR SELECT TO authenticated USING ((select auth.uid()) = user_id);
DROP POLICY IF EXISTS "Users can insert their own key backup" ON public.private_key_backups;
CREATE POLICY "Users can insert their own key backup" ON public.private_key_backups FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) = user_id);
DROP POLICY IF EXISTS "Users can update their own key backup" ON public.private_key_backups;
CREATE POLICY "Users can update their own key backup" ON public.private_key_backups FOR UPDATE TO authenticated USING ((select auth.uid()) = user_id) WITH CHECK ((select auth.uid()) = user_id);
GRANT SELECT, INSERT, UPDATE ON public.private_key_backups TO authenticated;
ALTER TABLE public.messages DROP CONSTRAINT IF EXISTS messages_body_check;
ALTER TABLE public.messages ADD CONSTRAINT messages_body_check CHECK (char_length(body) BETWEEN 1 AND 12000);
