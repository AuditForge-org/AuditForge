-- FORENSIQ schema

-- ─── Reports ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reports (
  id           UUID PRIMARY KEY,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  score        INTEGER NOT NULL,
  grade        TEXT NOT NULL,
  source_type  TEXT NOT NULL,
  source_label TEXT NOT NULL,
  payload      JSONB NOT NULL,
  owner_id     TEXT
);

CREATE INDEX IF NOT EXISTS reports_created_at_idx ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS reports_score_idx      ON reports (score);
CREATE INDEX IF NOT EXISTS reports_source_idx     ON reports (source_type, source_label);

-- ─── API request log ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_requests (
  id          BIGSERIAL PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip          INET,
  path        TEXT NOT NULL,
  status      INTEGER,
  duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS api_requests_created_at_idx ON api_requests (created_at DESC);
CREATE INDEX IF NOT EXISTS api_requests_ip_idx ON api_requests (ip, created_at DESC);

-- ─── Watched projects (webhook continuous-audit mode) ─────────────────

CREATE TABLE IF NOT EXISTS watched_projects (
  id             UUID PRIMARY KEY,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_id       TEXT NOT NULL,
  repo           TEXT NOT NULL,
  path_filter    TEXT,
  branch         TEXT NOT NULL DEFAULT 'main',
  webhook_secret TEXT NOT NULL,
  enabled        BOOLEAN NOT NULL DEFAULT true,
  notify_email   TEXT,
  notify_slack   TEXT,
  min_severity   TEXT NOT NULL DEFAULT 'medium',
  UNIQUE (repo, path_filter, branch)
);

CREATE INDEX IF NOT EXISTS watched_projects_owner_idx ON watched_projects (owner_id);
CREATE INDEX IF NOT EXISTS watched_projects_repo_idx  ON watched_projects (repo, branch) WHERE enabled = true;

CREATE TABLE IF NOT EXISTS watched_runs (
  id             UUID PRIMARY KEY,
  project_id     UUID NOT NULL REFERENCES watched_projects(id) ON DELETE CASCADE,
  audit_id       UUID,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  commit_sha     TEXT NOT NULL,
  commit_message TEXT,
  committer      TEXT,
  status         TEXT NOT NULL,
  score_delta    INTEGER,
  findings_delta INTEGER
);

CREATE INDEX IF NOT EXISTS watched_runs_project_idx ON watched_runs (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS watched_runs_audit_idx   ON watched_runs (audit_id);

-- ─── Public registry ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS registry_entries (
  id              UUID PRIMARY KEY,
  report_id       UUID NOT NULL REFERENCES reports(id),
  published_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_by    TEXT NOT NULL,
  contract_name   TEXT,
  chain           TEXT,
  address         TEXT,
  repo            TEXT,
  tags            TEXT[] NOT NULL DEFAULT '{}',
  score           INTEGER NOT NULL,
  grade           TEXT NOT NULL,
  findings_count  INTEGER NOT NULL,
  critical_count  INTEGER NOT NULL DEFAULT 0,
  high_count      INTEGER NOT NULL DEFAULT 0,
  superseded_by   UUID REFERENCES registry_entries(id),
  verified_source BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS registry_score_idx       ON registry_entries (score DESC) WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS registry_chain_idx       ON registry_entries (chain) WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS registry_published_idx   ON registry_entries (published_at DESC);
CREATE INDEX IF NOT EXISTS registry_address_idx     ON registry_entries (chain, address) WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS registry_tags_idx        ON registry_entries USING gin (tags);
CREATE INDEX IF NOT EXISTS registry_search_idx      ON registry_entries
  USING gin (to_tsvector('english',
    coalesce(contract_name,'') || ' ' ||
    coalesce(repo,'') || ' ' ||
    coalesce(address,'')));

-- ─── GitHub App installations ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS github_installations (
  installation_id BIGINT PRIMARY KEY,
  account_login   TEXT NOT NULL,
  account_type    TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  repo_selection  TEXT NOT NULL,
  repos           TEXT[] NOT NULL DEFAULT '{}',
  suspended       BOOLEAN NOT NULL DEFAULT false,
  owner_id        TEXT
);

CREATE INDEX IF NOT EXISTS gh_installs_account_idx ON github_installations (account_login);
CREATE INDEX IF NOT EXISTS gh_installs_owner_idx   ON github_installations (owner_id);

-- ─── Users (auth via GitHub or Google OAuth) ──────────────────────────
-- Provider columns are all nullable: a row carries github_* OR google_user_id
-- (or both, once linked by verified email). At least one is always present.

CREATE TABLE IF NOT EXISTS users (
  id              UUID PRIMARY KEY,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  github_user_id  BIGINT UNIQUE,
  github_username TEXT,
  google_user_id  TEXT UNIQUE,
  display_name    TEXT,
  email           TEXT,
  avatar_url      TEXT,
  plan            TEXT NOT NULL DEFAULT 'free'
);

CREATE INDEX IF NOT EXISTS users_github_username_idx ON users (github_username);

-- Idempotent upgrade path for databases created before Google sign-in:
ALTER TABLE users ALTER COLUMN github_user_id  DROP NOT NULL;
ALTER TABLE users ALTER COLUMN github_username DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_user_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name   TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_google_user_id_key ON users (google_user_id);
