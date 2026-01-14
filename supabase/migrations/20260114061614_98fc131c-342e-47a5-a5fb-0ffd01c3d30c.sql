-- Create enum for user roles
CREATE TYPE public.app_role AS ENUM ('admin', 'moderator', 'user');

-- Create user_roles table
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    role app_role NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (user_id, role)
);

-- Enable RLS on user_roles
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- Security definer function for role checking
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role app_role)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND role = _role
  )
$$;

-- RLS policy for user_roles - users can see their own roles
CREATE POLICY "Users can view their own roles"
ON public.user_roles FOR SELECT
USING (auth.uid() = user_id);

-- Profiles table for user display info
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Profiles are viewable by everyone"
ON public.profiles FOR SELECT USING (true);

CREATE POLICY "Users can update their own profile"
ON public.profiles FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own profile"
ON public.profiles FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Campaigns table
CREATE TABLE public.campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    invite_code TEXT NOT NULL UNIQUE DEFAULT substring(md5(random()::text), 1, 8),
    owner_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    current_scene TEXT DEFAULT 'The adventure begins...',
    game_state JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.campaigns ENABLE ROW LEVEL SECURITY;

-- Campaign members junction table
CREATE TABLE public.campaign_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES public.campaigns(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    is_dm BOOLEAN NOT NULL DEFAULT false,
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (campaign_id, user_id)
);

ALTER TABLE public.campaign_members ENABLE ROW LEVEL SECURITY;

-- Characters table
CREATE TABLE public.characters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES public.campaigns(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    class TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    hp INTEGER NOT NULL DEFAULT 10,
    max_hp INTEGER NOT NULL DEFAULT 10,
    ac INTEGER NOT NULL DEFAULT 10,
    stats JSONB DEFAULT '{"strength": 10, "dexterity": 10, "constitution": 10, "intelligence": 10, "wisdom": 10, "charisma": 10}',
    abilities JSONB DEFAULT '[]',
    inventory JSONB DEFAULT '[]',
    xp INTEGER NOT NULL DEFAULT 0,
    xp_to_next INTEGER NOT NULL DEFAULT 300,
    position JSONB DEFAULT '{"x": 0, "y": 0}',
    status_effects TEXT[] DEFAULT '{}',
    avatar_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.characters ENABLE ROW LEVEL SECURITY;

-- Chat messages table
CREATE TABLE public.chat_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES public.campaigns(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    message_type TEXT NOT NULL DEFAULT 'player', -- 'player', 'dm', 'system', 'roll'
    content TEXT NOT NULL,
    roll_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

-- Combat state table
CREATE TABLE public.combat_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES public.campaigns(id) ON DELETE CASCADE NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT false,
    round_number INTEGER NOT NULL DEFAULT 1,
    current_turn_index INTEGER NOT NULL DEFAULT 0,
    initiative_order UUID[] DEFAULT '{}',
    enemies JSONB DEFAULT '[]',
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.combat_state ENABLE ROW LEVEL SECURITY;

-- Helper function to check campaign membership
CREATE OR REPLACE FUNCTION public.is_campaign_member(_user_id UUID, _campaign_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.campaign_members
    WHERE user_id = _user_id
      AND campaign_id = _campaign_id
  )
$$;

-- Helper function to check if user owns campaign
CREATE OR REPLACE FUNCTION public.is_campaign_owner(_user_id UUID, _campaign_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.campaigns
    WHERE id = _campaign_id
      AND owner_id = _user_id
  )
$$;

-- RLS Policies for campaigns
CREATE POLICY "Campaign members can view their campaigns"
ON public.campaigns FOR SELECT
USING (public.is_campaign_member(auth.uid(), id) OR owner_id = auth.uid());

CREATE POLICY "Users can create campaigns"
ON public.campaigns FOR INSERT
WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Owners can update their campaigns"
ON public.campaigns FOR UPDATE
USING (auth.uid() = owner_id);

CREATE POLICY "Owners can delete their campaigns"
ON public.campaigns FOR DELETE
USING (auth.uid() = owner_id);

-- RLS Policies for campaign_members
CREATE POLICY "Members can view campaign members"
ON public.campaign_members FOR SELECT
USING (public.is_campaign_member(auth.uid(), campaign_id) OR public.is_campaign_owner(auth.uid(), campaign_id));

CREATE POLICY "Users can join campaigns"
ON public.campaign_members FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can leave campaigns"
ON public.campaign_members FOR DELETE
USING (auth.uid() = user_id);

-- RLS Policies for characters
CREATE POLICY "Campaign members can view characters"
ON public.characters FOR SELECT
USING (public.is_campaign_member(auth.uid(), campaign_id));

CREATE POLICY "Users can create their own characters"
ON public.characters FOR INSERT
WITH CHECK (auth.uid() = user_id AND public.is_campaign_member(auth.uid(), campaign_id));

CREATE POLICY "Users can update their own characters"
ON public.characters FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own characters"
ON public.characters FOR DELETE
USING (auth.uid() = user_id);

-- RLS Policies for chat_messages
CREATE POLICY "Campaign members can view messages"
ON public.chat_messages FOR SELECT
USING (public.is_campaign_member(auth.uid(), campaign_id));

CREATE POLICY "Campaign members can send messages"
ON public.chat_messages FOR INSERT
WITH CHECK (public.is_campaign_member(auth.uid(), campaign_id));

-- RLS Policies for combat_state
CREATE POLICY "Campaign members can view combat state"
ON public.combat_state FOR SELECT
USING (public.is_campaign_member(auth.uid(), campaign_id));

CREATE POLICY "Campaign owners can manage combat state"
ON public.combat_state FOR ALL
USING (public.is_campaign_owner(auth.uid(), campaign_id));

CREATE POLICY "DMs can update combat state"
ON public.combat_state FOR UPDATE
USING (
  EXISTS (
    SELECT 1 FROM public.campaign_members
    WHERE campaign_id = combat_state.campaign_id
      AND user_id = auth.uid()
      AND is_dm = true
  )
);

-- Function to find campaign by invite code (for joining)
CREATE OR REPLACE FUNCTION public.get_campaign_by_invite_code(_invite_code TEXT)
RETURNS TABLE (id UUID, name TEXT, owner_id UUID)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, name, owner_id
  FROM public.campaigns
  WHERE invite_code = _invite_code
    AND is_active = true
$$;

-- Updated_at trigger function
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Apply updated_at triggers
CREATE TRIGGER update_profiles_updated_at
BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

CREATE TRIGGER update_campaigns_updated_at
BEFORE UPDATE ON public.campaigns
FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

CREATE TRIGGER update_characters_updated_at
BEFORE UPDATE ON public.characters
FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

CREATE TRIGGER update_combat_state_updated_at
BEFORE UPDATE ON public.combat_state
FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

-- Function to auto-create profile on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (user_id, display_name)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email, '@', 1)));
  
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'user');
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Trigger for new user signup
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Enable realtime for multiplayer tables
ALTER PUBLICATION supabase_realtime ADD TABLE public.chat_messages;
ALTER PUBLICATION supabase_realtime ADD TABLE public.characters;
ALTER PUBLICATION supabase_realtime ADD TABLE public.combat_state;
ALTER PUBLICATION supabase_realtime ADD TABLE public.campaigns;