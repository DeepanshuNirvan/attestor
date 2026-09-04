-- Make the credential intake link say what it is asking for.
--
-- The link existed and pointed at a page that was never built, so nothing ever wrote a row into
-- `credential_set` and no authenticated testing was possible at all. Building the page needs the
-- link to carry the request: which accounts, for which role, and what kind of login each one is —
-- otherwise the client is handed a blank form and has to guess what we want.
--
-- Shape of `requested`, one entry per account we are asking for:
--
--   [{ "slot": "...", "label": "Standard user", "roleName": "user",
--      "kind": "emailPassword", "isSecondary": false }]
--
-- `slot` is generated when the link is made and is what a submitted value is filed under, so a
-- client who fills the form twice replaces their own entry rather than creating a duplicate.

ALTER TABLE credential_intake_link
  ADD COLUMN IF NOT EXISTS requested jsonb NOT NULL DEFAULT '[]'::jsonb;

-- A link may be filled in more than once — a client who forgets the admin account should be able to
-- come back to the same link rather than asking for a new one. `used_at` records the first
-- submission; expiry is what closes it.
COMMENT ON COLUMN credential_intake_link.used_at IS
  'First submission. The link stays usable until it expires, so a client can complete it in stages.';

-- The intake route is reached without a session, so the token is the whole of the authorisation.
-- Looking one up by hash on every submission wants an index rather than a sequential scan.
CREATE INDEX IF NOT EXISTS credential_intake_link_token_idx
  ON credential_intake_link (token_hash);

-- The portal role is deliberately given nothing here. The intake page is served by the portal's web
-- surface but submits to the console API, which is the only thing that holds the vault key — so the
-- public service never touches the credential tables at all.

-- Which slot on the link a stored credential came from. A client who fills the form twice — because
-- they mistyped a password, or came back for the admin account — replaces their own entry instead
-- of leaving two rows where a tester cannot tell which one is current.
ALTER TABLE credential_set
  ADD COLUMN IF NOT EXISTS intake_slot text;

CREATE UNIQUE INDEX IF NOT EXISTS credential_set_intake_slot_unique
  ON credential_set (engagement_id, intake_slot)
  WHERE intake_slot IS NOT NULL;
