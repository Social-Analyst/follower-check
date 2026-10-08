create table user_sessions (
  id uuid default gen_random_uuid() primary key,
  username text unique not null,
  encrypted_session text not null,
  whitelist text[] default '{}',
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Row level security ON with NO policies = the public anon key can read nothing.
-- Only the backend (service_role key, which bypasses RLS) can access this table.
alter table user_sessions enable row level security;
