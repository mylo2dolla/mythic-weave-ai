-- Create the trigger to auto-create profiles on user signup
CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- Backfill any existing users that don't have profiles
INSERT INTO public.profiles (user_id, display_name)
SELECT id, COALESCE(raw_user_meta_data->>'display_name', split_part(email, '@', 1))
FROM auth.users u
WHERE NOT EXISTS (SELECT 1 FROM public.profiles p WHERE p.user_id = u.id);