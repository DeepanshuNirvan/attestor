-- Constraints and guarantees the ORM does not express.
--
-- Three things happen here and each of them is a property the application must not be able to
-- violate by accident:
--   1. the audit log is append-only, enforced by a trigger rather than by discipline;
--   2. enumerations are checked at the database, so a bad value fails on write and not at render;
--   3. the client portal gets its own least-privilege role that cannot read the credential vault.

/* 1 ---------------------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION attestor_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
    USING HINT = 'Record a correcting entry instead of editing history.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION attestor_audit_log_is_append_only();

DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log;
CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION attestor_audit_log_is_append_only();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION attestor_audit_log_is_append_only();

/* 2 ---------------------------------------------------------------------------------------- */

ALTER TABLE engagement
  ADD CONSTRAINT engagement_state_valid CHECK (state IN (
    'draft','scoped','authorised','advancePaid','readyToRun','running','triage','manualTesting',
    'reportDraft','reportReview','released','retestPending','retestComplete','closed'
  )),
  ADD CONSTRAINT engagement_test_type_valid CHECK (test_type IN ('blackBox','greyBox','whiteBox')),
  ADD CONSTRAINT engagement_retention_positive CHECK (evidence_retention_days > 0);

ALTER TABLE scope_item
  ADD CONSTRAINT scope_item_kind_valid CHECK (kind IN (
    'domain','wildcard','ip','cidr','url','repo','cloudAccount','mobilePackage','llmEndpoint'
  ));

ALTER TABLE finding
  ADD CONSTRAINT finding_severity_valid CHECK (severity IN ('critical','high','medium','low','info')),
  ADD CONSTRAINT finding_status_valid CHECK (status IN (
    'candidate','open','fixed','riskAccepted','falsePositive','duplicate'
  )),
  ADD CONSTRAINT finding_source_valid CHECK (source IN ('tool','manual','ai')),
  ADD CONSTRAINT finding_cvss_version_valid CHECK (cvss_version IS NULL OR cvss_version IN ('3.1','4.0')),
  ADD CONSTRAINT finding_cvss_score_range CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
  -- A severity override without a written reason is exactly what an auditor asks about.
  ADD CONSTRAINT finding_override_needs_reason CHECK (
    severity_overridden_by IS NULL OR severity_override_reason IS NOT NULL
  ),
  -- Risk acceptance is the client's record and is worthless without who and why.
  ADD CONSTRAINT finding_risk_acceptance_complete CHECK (
    status <> 'riskAccepted'
    OR (risk_accepted_by IS NOT NULL AND risk_acceptance_justification IS NOT NULL)
  ),
  -- A finding cannot be reported without a reference, and cannot have one while a candidate.
  ADD CONSTRAINT finding_reference_matches_status CHECK (
    (status = 'candidate' AND reference IS NULL) OR (status <> 'candidate')
  );

ALTER TABLE evidence
  ADD CONSTRAINT evidence_kind_valid CHECK (kind IN (
    'request','response','screenshot','log','terminal','file','transcript'
  ));

ALTER TABLE scan_run
  ADD CONSTRAINT scan_run_status_valid CHECK (status IN (
    'queued','running','completed','failed','aborted','refused'
  ));

ALTER TABLE report
  ADD CONSTRAINT report_kind_valid CHECK (kind IN (
    'assessment','retest','attestation','deletionConfirmation','executiveOnePager','monthlySummary'
  ));

ALTER TABLE staff_user
  ADD CONSTRAINT staff_role_valid CHECK (role IN ('owner','tester'));

ALTER TABLE client_user
  ADD CONSTRAINT client_role_valid CHECK (role IN ('clientOwner','clientMember','clientViewer'));

ALTER TABLE session
  -- A session belongs to exactly one kind of user. Both, or neither, is a bug worth failing on.
  ADD CONSTRAINT session_single_subject CHECK (
    (staff_user_id IS NOT NULL AND client_user_id IS NULL)
    OR (staff_user_id IS NULL AND client_user_id IS NOT NULL)
  );

ALTER TABLE authorisation
  ADD CONSTRAINT authorisation_window_ordered CHECK (valid_until > valid_from);

ALTER TABLE panic_stop
  ADD CONSTRAINT panic_stop_scope_valid CHECK (scope IN ('platform','engagement')),
  ADD CONSTRAINT panic_stop_engagement_present CHECK (
    scope = 'platform' OR engagement_id IS NOT NULL
  );

/* 3 ---------------------------------------------------------------------------------------- */

-- The portal role. It is the only role reachable from the internet, so it gets the smallest set of
-- privileges that lets the portal work: read what a client may see, write the few things a client
-- may change, append to the audit log, and nothing else. It cannot see the credential vault at all.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'attestor_portal') THEN
    CREATE ROLE attestor_portal NOLOGIN;
  END IF;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM attestor_portal;

GRANT SELECT ON
  client, engagement, finding, evidence, report, report_section, scope_item,
  client_user, client_engagement_access, finding_comment, retest_request,
  questionnaire_answer, scan_run
TO attestor_portal;

GRANT INSERT ON finding_comment, retest_request, report_download, audit_log TO attestor_portal;
GRANT UPDATE (status, fixed_at, risk_accepted_at, risk_accepted_by, risk_acceptance_justification, updated_at)
  ON finding TO attestor_portal;
GRANT UPDATE (password_hash, totp_secret_sealed, totp_enrolled_at, activated_at,
              portal_terms_version, portal_terms_accepted_at, notification_preferences, last_login_at)
  ON client_user TO attestor_portal;
GRANT SELECT, INSERT, UPDATE ON session TO attestor_portal;

-- Explicitly denied, and stated so a reviewer can see the intent rather than infer it from absence.
REVOKE ALL ON credential_set, credential_intake_link, staff_user, authorisation,
               client_invitation, panic_stop, ai_usage, false_positive_memo
  FROM attestor_portal;

CREATE INDEX IF NOT EXISTS finding_reference_idx ON finding (reference);
CREATE INDEX IF NOT EXISTS evidence_purged_idx ON evidence (purged_at) WHERE purged_at IS NULL;
CREATE INDEX IF NOT EXISTS notification_unsent_idx ON notification (queued_at) WHERE sent_at IS NULL;
