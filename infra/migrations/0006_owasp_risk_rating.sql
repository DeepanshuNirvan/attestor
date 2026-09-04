-- The OWASP Risk Rating alongside CVSS.
--
-- CVSS says how bad a class of flaw is in the abstract. It knows nothing about who the client is,
-- what the data is worth, or whether losing it is a regulatory matter — so a report that offers only
-- CVSS invites the reader to argue with a number that was never about their business. The OWASP
-- method asks sixteen questions that are specifically about this client, and those answers are what
-- the remediation conversation is actually about.
--
-- Stored as the raw factor answers rather than as the computed rating. The rating is a pure function
-- of the answers, so deriving it keeps one source of truth; and a client who asks "why is this
-- high?" gets the sixteen answers rather than a number.

ALTER TABLE finding
  ADD COLUMN IF NOT EXISTS owasp_risk_scores jsonb;

COMMENT ON COLUMN finding.owasp_risk_scores IS
  'OWASP Risk Rating factor answers, keyed by factor id. The rating is derived from these; see packages/findings/src/owasp-risk-rating.ts.';

-- No grant needed: 0001 gives the portal SELECT on the whole finding table and UPDATE on a named
-- list of columns only, so the client can read the rating and cannot write it.
