-- Fix characters SELECT policy to include campaign owners
DROP POLICY IF EXISTS "Campaign members can view characters" ON public.characters;
CREATE POLICY "Campaign members can view characters" 
ON public.characters 
FOR SELECT 
USING (is_campaign_member(auth.uid(), campaign_id) OR is_campaign_owner(auth.uid(), campaign_id));

-- Fix characters INSERT policy - user must be member OR owner
DROP POLICY IF EXISTS "Users can create their own characters" ON public.characters;
CREATE POLICY "Users can create their own characters" 
ON public.characters 
FOR INSERT 
WITH CHECK (
  auth.uid() = user_id 
  AND (is_campaign_member(auth.uid(), campaign_id) OR is_campaign_owner(auth.uid(), campaign_id))
);