-- One row per store that has installed the app. The Store API access token
-- arrives in the app.installed and app.token_rotated webhooks and is stored
-- encrypted.
CREATE TABLE installations (
  store_id TEXT PRIMARY KEY,
  access_token_ciphertext TEXT NOT NULL,
  scopes TEXT NOT NULL,
  -- When the stored token was issued. A delivery older than the stored token
  -- (a retry arriving late) never overwrites it.
  token_issued_at TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  uninstalled_at TEXT
);

-- Webhook deliveries can repeat; each event is handled once.
CREATE TABLE handled_events (
  event_id TEXT PRIMARY KEY,
  handled_at TEXT NOT NULL
);
