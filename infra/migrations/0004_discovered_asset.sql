-- Record what reconnaissance actually found.
--
-- Every adapter may implement `parseAssets`, and the recon adapters do — hosts, open ports, service
-- banners, endpoints, certificates and technologies. Nothing called it, so all of that was parsed
-- and thrown away on every run.
--
-- Two things in the report depended on it and were therefore always wrong: the ports and services
-- appendix rendered "No port scanning was performed in this engagement" even when nmap and naabu
-- had both run, and the asset inventory listed the scope the tester typed in rather than the
-- estate the engagement actually found. An appendix that contradicts the methodology section is
-- the kind of detail that costs a report its credibility with an auditor.
--
-- One row per distinct asset per engagement. `first_seen_at` and `last_seen_at` make a retest able
-- to show what appeared and what went away between two engagements.

CREATE TABLE IF NOT EXISTS discovered_asset (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  engagement_id uuid NOT NULL REFERENCES engagement (id) ON DELETE CASCADE,
  scan_run_id uuid REFERENCES scan_run (id) ON DELETE SET NULL,
  kind text NOT NULL,
  value text NOT NULL,
  host text NOT NULL,
  port integer,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);

-- One row per asset per engagement; a second sighting updates the row rather than adding to it.
CREATE UNIQUE INDEX IF NOT EXISTS discovered_asset_unique_idx
  ON discovered_asset (engagement_id, kind, value);

CREATE INDEX IF NOT EXISTS discovered_asset_engagement_idx
  ON discovered_asset (engagement_id);

-- The portal never reads the asset inventory: it is working material for the report, and the
-- released document is what the client sees. No grant to attestor_portal.
