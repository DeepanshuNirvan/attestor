import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  real,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

/**
 * The schema.
 *
 * Deliberately flat. Enumerations are stored as text with a check constraint added in the migration
 * rather than as Postgres enum types, because adding a value to a Postgres enum inside a
 * transaction is awkward and this system will gain finding statuses and engagement states over
 * time.
 *
 * Two tables are special:
 *   - `auditLog` is append-only, enforced by a trigger in the migration.
 *   - `credentialSet` never stores a value, only a sealed box and the id of the key that sealed it.
 */

const id = () => uuid('id').primaryKey().defaultRandom();
const createdAt = () => timestamp('created_at', { withTimezone: true }).notNull().defaultNow();
const updatedAt = () => timestamp('updated_at', { withTimezone: true }).notNull().defaultNow();

export const client = pgTable('client', {
  id: id(),
  name: text('name').notNull(),
  legalName: text('legal_name').notNull(),
  country: text('country').notNull().default('IN'),
  contacts: jsonb('contacts').notNull().default(sql`'[]'::jsonb`),
  billingDetails: jsonb('billing_details').notNull().default(sql`'{}'::jsonb`),
  dataProcessingAgreementSignedAt: timestamp('dpa_signed_at', { withTimezone: true }),
  /** Client-level policy layer, YAML. */
  policyYaml: text('policy_yaml').notNull().default(''),
  notes: text('notes').notNull().default(''),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const engagement = pgTable(
  'engagement',
  {
    id: id(),
    clientId: uuid('client_id')
      .notNull()
      .references(() => client.id, { onDelete: 'restrict' }),
    /** `ATT-2026-014`. Unique, quoted by the client for years. */
    reference: text('reference').notNull(),
    referenceYear: integer('reference_year').notNull(),
    referenceSequence: integer('reference_sequence').notNull(),
    type: text('type').notNull(),
    title: text('title').notNull(),
    state: text('state').notNull().default('draft'),
    testType: text('test_type').notNull().default('greyBox'),
    startsAt: timestamp('starts_at', { withTimezone: true }),
    endsAt: timestamp('ends_at', { withTimezone: true }),
    timezone: text('timezone').notNull().default('Asia/Kolkata'),
    currency: text('currency').notNull().default('INR'),
    quotedAmount: integer('quoted_amount').notNull().default(0),
    advancePaidAt: timestamp('advance_paid_at', { withTimezone: true }),
    finalPaidAt: timestamp('final_paid_at', { withTimezone: true }),
    advanceGateOverride: jsonb('advance_gate_override'),
    invoiceState: text('invoice_state').notNull().default('notIssued'),
    methodologyVersions: jsonb('methodology_versions').notNull().default(sql`'{}'::jsonb`),
    aiAssistEnabled: boolean('ai_assist_enabled').notNull().default(false),
    agenticEnabled: boolean('agentic_enabled').notNull().default(false),
    reportTemplateId: text('report_template_id').notNull().default('attestor-standard-v1'),
    /** Engagement-level policy layer, YAML. */
    policyYaml: text('policy_yaml').notNull().default(''),
    evidenceRetentionDays: integer('evidence_retention_days').notNull().default(90),
    legalHold: boolean('legal_hold').notNull().default(false),
    thirdPartyInfrastructureAcknowledgedAt: timestamp('third_party_ack_at', { withTimezone: true }),
    cloudTestingPolicyAcknowledgedAt: timestamp('cloud_policy_ack_at', { withTimezone: true }),
    preFlightChecklist: jsonb('pre_flight_checklist').notNull().default(sql`'{}'::jsonb`),
    reviewChecklist: jsonb('review_checklist').notNull().default(sql`'{}'::jsonb`),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex('engagement_reference_unique').on(table.reference),
    index('engagement_client_idx').on(table.clientId),
    index('engagement_state_idx').on(table.state),
  ],
);

export const authorisation = pgTable(
  'authorisation',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    signedBy: text('signed_by').notNull(),
    signerRole: text('signer_role').notNull(),
    signerEmail: text('signer_email').notNull(),
    signedAt: timestamp('signed_at', { withTimezone: true }),
    documentObjectKey: text('document_object_key').notNull(),
    documentSha256: text('document_sha256').notNull(),
    /** The asset list as written in the signed document, for diffing against entered scope. */
    assetList: jsonb('asset_list').notNull().default(sql`'[]'::jsonb`),
    exclusionList: jsonb('exclusion_list').notNull().default(sql`'[]'::jsonb`),
    sourceAddresses: jsonb('source_addresses').notNull().default(sql`'[]'::jsonb`),
    emergencyContact: jsonb('emergency_contact').notNull().default(sql`'{}'::jsonb`),
    criticalNotificationHours: integer('critical_notification_hours').notNull().default(24),
    validFrom: timestamp('valid_from', { withTimezone: true }).notNull(),
    validUntil: timestamp('valid_until', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedReason: text('revoked_reason'),
    createdAt: createdAt(),
  },
  (table) => [index('authorisation_engagement_idx').on(table.engagementId)],
);

export const scopeItem = pgTable(
  'scope_item',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(),
    value: text('value').notNull(),
    included: boolean('included').notNull().default(true),
    notes: text('notes').notNull().default(''),
    createdAt: createdAt(),
  },
  (table) => [
    index('scope_item_engagement_idx').on(table.engagementId),
    uniqueIndex('scope_item_unique').on(table.engagementId, table.kind, table.value, table.included),
  ],
);

export const credentialSet = pgTable(
  'credential_set',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    label: text('label').notNull(),
    roleName: text('role_name').notNull(),
    authType: text('auth_type').notNull(),
    /** libsodium sealed box. There is no column that holds a plaintext credential. */
    sealedValue: text('sealed_value').notNull(),
    /** Per-engagement key salt. Destroying it shreds this engagement's credentials only. */
    keySalt: text('key_salt').notNull(),
    nonce: text('nonce').notNull(),
    /** Whether this is the second account for the role, which access control testing needs. */
    isSecondary: boolean('is_secondary').notNull().default(false),
    /** Which slot on the intake link this came from, so a resubmission replaces rather than adds. */
    intakeSlot: text('intake_slot'),
    tenantId: text('tenant_id'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    lastVerifiedAt: timestamp('last_verified_at', { withTimezone: true }),
    verificationError: text('verification_error'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    shreddedAt: timestamp('shredded_at', { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    index('credential_set_engagement_idx').on(table.engagementId),
    // Partial, matching migration 0005: rows that predate intake have a null slot and must not
    // collide with each other. The `where` is not decoration — an ON CONFLICT that names these two
    // columns without it matches no index at all, and every submission fails with "no unique or
    // exclusion constraint matching the ON CONFLICT specification".
    uniqueIndex('credential_set_intake_slot_unique')
      .on(table.engagementId, table.intakeSlot)
      .where(sql`${table.intakeSlot} is not null`),
  ],
);

/** One-time links for the client to submit credentials without them travelling through email. */
export const credentialIntakeLink = pgTable('credential_intake_link', {
  id: id(),
  engagementId: uuid('engagement_id')
    .notNull()
    .references(() => engagement.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull(),
  /**
   * What this link is asking for: one entry per account, each with a label, a role, and the kind of
   * login it is. The client then sees the two or three boxes that kind needs rather than a blank
   * form they have to interpret.
   */
  requested: jsonb('requested').notNull().default(sql`'[]'::jsonb`),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  /** First submission. The link stays usable until it expires, so it can be completed in stages. */
  usedAt: timestamp('used_at', { withTimezone: true }),
  createdBy: uuid('created_by').notNull(),
  createdAt: createdAt(),
});

export const scanRun = pgTable(
  'scan_run',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    module: text('module').notNull(),
    toolName: text('tool_name').notNull(),
    toolVersionDigest: text('tool_version_digest').notNull().default(''),
    /** The resolved policy at the moment of the run, so an old run can be explained. */
    policySnapshot: jsonb('policy_snapshot').notNull().default(sql`'{}'::jsonb`),
    /** Catalogue check ids this run covers, which drives the coverage matrix. */
    coveredCheckIds: jsonb('covered_check_ids').notNull().default(sql`'[]'::jsonb`),
    targets: jsonb('targets').notNull().default(sql`'[]'::jsonb`),
    status: text('status').notNull().default('queued'),
    startedAt: timestamp('started_at', { withTimezone: true }),
    finishedAt: timestamp('finished_at', { withTimezone: true }),
    exitCode: integer('exit_code'),
    rawOutputKey: text('raw_output_key'),
    stats: jsonb('stats').notNull().default(sql`'{}'::jsonb`),
    abortReason: text('abort_reason'),
    dryRun: boolean('dry_run').notNull().default(false),
    createdAt: createdAt(),
  },
  (table) => [
    index('scan_run_engagement_idx').on(table.engagementId),
    index('scan_run_status_idx').on(table.status),
  ],
);

export const finding = pgTable(
  'finding',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    scanRunId: uuid('scan_run_id').references(() => scanRun.id, { onDelete: 'set null' }),
    /** `ATT-2026-014-003`, assigned on confirmation. Null while a candidate. */
    reference: text('reference'),
    referenceSequence: integer('reference_sequence'),
    source: text('source').notNull(),
    toolName: text('tool_name'),
    toolFindingRef: text('tool_finding_ref'),
    checkId: text('check_id'),

    title: text('title').notNull(),
    description: text('description').notNull().default(''),
    severity: text('severity').notNull(),
    severityOverrideReason: text('severity_override_reason'),
    severityOverriddenBy: uuid('severity_overridden_by'),

    cvssVersion: text('cvss_version'),
    cvssVector: text('cvss_vector'),
    cvssScore: real('cvss_score'),

    // The OWASP Risk Rating factor answers, keyed by factor id. The rating itself is derived rather
    // than stored, so there is one source of truth and a client asking "why is this high?" gets the
    // sixteen answers instead of a number.
    owaspRiskScores: jsonb('owasp_risk_scores'),

    cweId: integer('cwe_id'),
    owaspCategory: text('owasp_category'),
    apiCategory: text('api_category'),
    wstgId: text('wstg_id'),
    asvsRequirement: text('asvs_requirement'),
    masvsControl: text('masvs_control'),
    llmCategory: text('llm_category'),

    affectedAssets: jsonb('affected_assets').notNull().default(sql`'[]'::jsonb`),
    businessImpact: text('business_impact').notNull().default(''),
    likelihood: text('likelihood').notNull().default(''),
    attackerPrerequisites: text('attacker_prerequisites').notNull().default(''),
    reproductionSteps: jsonb('reproduction_steps').notNull().default(sql`'[]'::jsonb`),
    remediation: text('remediation').notNull().default(''),
    references: jsonb('references').notNull().default(sql`'[]'::jsonb`),

    status: text('status').notNull().default('candidate'),
    dedupeKey: text('dedupe_key').notNull(),
    correlatedIntoId: uuid('correlated_into_id'),

    attackSuccessRate: real('attack_success_rate'),
    attemptCount: integer('attempt_count'),

    /** Set when the AI assist layer drafted prose, so a reviewer knows what to read closely. */
    aiDraftFields: jsonb('ai_draft_fields').notNull().default(sql`'[]'::jsonb`),
    aiModel: text('ai_model'),

    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    confirmedAt: timestamp('confirmed_at', { withTimezone: true }),
    confirmedBy: uuid('confirmed_by'),
    fixedAt: timestamp('fixed_at', { withTimezone: true }),
    retestedAt: timestamp('retested_at', { withTimezone: true }),
    riskAcceptedAt: timestamp('risk_accepted_at', { withTimezone: true }),
    riskAcceptedBy: text('risk_accepted_by'),
    riskAcceptanceJustification: text('risk_acceptance_justification'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    index('finding_engagement_idx').on(table.engagementId),
    index('finding_status_idx').on(table.status),
    index('finding_severity_idx').on(table.severity),
    uniqueIndex('finding_dedupe_unique').on(table.engagementId, table.dedupeKey),
  ],
);

export const evidence = pgTable(
  'evidence',
  {
    id: id(),
    findingId: uuid('finding_id').references(() => finding.id, { onDelete: 'cascade' }),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    scanRunId: uuid('scan_run_id').references(() => scanRun.id, { onDelete: 'set null' }),
    kind: text('kind').notNull(),
    objectKey: text('object_key').notNull(),
    contentType: text('content_type').notNull().default('text/plain'),
    byteSize: integer('byte_size').notNull().default(0),
    sha256: text('sha256').notNull(),
    /** Masking rule ids that fired, recorded for defensibility. */
    redactionApplied: jsonb('redaction_applied').notNull().default(sql`'[]'::jsonb`),
    capturedAt: timestamp('captured_at', { withTimezone: true }).notNull().defaultNow(),
    purgedAt: timestamp('purged_at', { withTimezone: true }),
  },
  (table) => [
    index('evidence_finding_idx').on(table.findingId),
    index('evidence_engagement_idx').on(table.engagementId),
  ],
);

/**
 * What reconnaissance found, as distinct from what the tester typed into scope.
 *
 * Adapters have always produced this through `parseAssets`; nothing persisted it, so the report's
 * ports-and-services appendix was permanently empty and its asset inventory was a copy of the scope
 * list. One row per asset per engagement, updated rather than duplicated on a second sighting.
 */
export const discoveredAsset = pgTable(
  'discovered_asset',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    scanRunId: uuid('scan_run_id').references(() => scanRun.id, { onDelete: 'set null' }),
    kind: text('kind').notNull(),
    value: text('value').notNull(),
    host: text('host').notNull(),
    port: integer('port'),
    metadata: jsonb('metadata').notNull().default(sql`'{}'::jsonb`),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('discovered_asset_unique_idx').on(table.engagementId, table.kind, table.value),
    index('discovered_asset_engagement_idx').on(table.engagementId),
  ],
);

export const falsePositiveMemo = pgTable(
  'false_positive_memo',
  {
    id: id(),
    clientId: uuid('client_id')
      .notNull()
      .references(() => client.id, { onDelete: 'cascade' }),
    dedupeKey: text('dedupe_key').notNull(),
    reason: text('reason').notNull(),
    createdBy: uuid('created_by').notNull(),
    createdAt: createdAt(),
  },
  (table) => [uniqueIndex('false_positive_unique').on(table.clientId, table.dedupeKey)],
);

export const report = pgTable(
  'report',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(),
    version: text('version').notNull(),
    templateId: text('template_id').notNull(),
    /** Legal block versions used, so an issued document can be re-rendered exactly. */
    legalTemplateVersions: jsonb('legal_template_versions').notNull().default(sql`'{}'::jsonb`),
    renderedHtmlKey: text('rendered_html_key'),
    pdfKey: text('pdf_key'),
    coverageSnapshot: jsonb('coverage_snapshot').notNull().default(sql`'{}'::jsonb`),
    releasedAt: timestamp('released_at', { withTimezone: true }),
    releasedBy: uuid('released_by'),
    recipientList: jsonb('recipient_list').notNull().default(sql`'[]'::jsonb`),
    createdAt: createdAt(),
  },
  (table) => [index('report_engagement_idx').on(table.engagementId)],
);

/** Prose blocks a human edited in the console. Edits are stored, never regenerated. */
export const reportSection = pgTable(
  'report_section',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    sectionKey: text('section_key').notNull(),
    markdown: text('markdown').notNull().default(''),
    isAiDraft: boolean('is_ai_draft').notNull().default(false),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    approvedBy: uuid('approved_by'),
    updatedAt: updatedAt(),
  },
  (table) => [uniqueIndex('report_section_unique').on(table.engagementId, table.sectionKey)],
);

export const auditLog = pgTable(
  'audit_log',
  {
    id: id(),
    actorId: text('actor_id').notNull(),
    actorKind: text('actor_kind').notNull(),
    action: text('action').notNull(),
    subjectType: text('subject_type').notNull(),
    subjectId: text('subject_id').notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    metadata: jsonb('metadata').notNull().default(sql`'{}'::jsonb`),
    createdAt: createdAt(),
  },
  (table) => [
    index('audit_log_subject_idx').on(table.subjectType, table.subjectId),
    index('audit_log_created_idx').on(table.createdAt),
    index('audit_log_action_idx').on(table.action),
  ],
);

export const retainerSchedule = pgTable('retainer_schedule', {
  id: id(),
  clientId: uuid('client_id')
    .notNull()
    .references(() => client.id, { onDelete: 'cascade' }),
  engagementId: uuid('engagement_id').references(() => engagement.id, { onDelete: 'set null' }),
  cadence: text('cadence').notNull().default('monthly'),
  modules: jsonb('modules').notNull().default(sql`'[]'::jsonb`),
  windowRule: jsonb('window_rule').notNull().default(sql`'{}'::jsonb`),
  nextRunAt: timestamp('next_run_at', { withTimezone: true }),
  lastRunAt: timestamp('last_run_at', { withTimezone: true }),
  active: boolean('active').notNull().default(true),
  createdAt: createdAt(),
});

/** Every client-facing message is queued here and released by a human. Nothing auto-sends in v1. */
export const notification = pgTable(
  'notification',
  {
    id: id(),
    engagementId: uuid('engagement_id').references(() => engagement.id, { onDelete: 'cascade' }),
    clientUserId: uuid('client_user_id'),
    channel: text('channel').notNull().default('email'),
    template: text('template').notNull(),
    subject: text('subject').notNull(),
    body: text('body').notNull(),
    severityThreshold: text('severity_threshold'),
    queuedAt: timestamp('queued_at', { withTimezone: true }).notNull().defaultNow(),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    approvedBy: uuid('approved_by'),
    sentAt: timestamp('sent_at', { withTimezone: true }),
    failureReason: text('failure_reason'),
  },
  (table) => [index('notification_engagement_idx').on(table.engagementId)],
);

/* Staff and client accounts --------------------------------------------------------------- */

export const staffUser = pgTable(
  'staff_user',
  {
    id: id(),
    email: text('email').notNull(),
    name: text('name').notNull(),
    passwordHash: text('password_hash').notNull(),
    role: text('role').notNull().default('tester'),
    totpSecretSealed: text('totp_secret_sealed'),
    totpEnrolledAt: timestamp('totp_enrolled_at', { withTimezone: true }),
    /** The last TOTP timestep this account spent, so a code cannot be used twice. */
    totpLastTimestep: bigint('totp_last_timestep', { mode: 'number' }),
    active: boolean('active').notNull().default(true),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [uniqueIndex('staff_user_email_unique').on(table.email)],
);

export const clientUser = pgTable(
  'client_user',
  {
    id: id(),
    clientId: uuid('client_id')
      .notNull()
      .references(() => client.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    name: text('name').notNull(),
    passwordHash: text('password_hash'),
    role: text('role').notNull().default('clientMember'),
    totpSecretSealed: text('totp_secret_sealed'),
    totpEnrolledAt: timestamp('totp_enrolled_at', { withTimezone: true }),
    /** The last TOTP timestep this account spent, so a code cannot be used twice. */
    totpLastTimestep: bigint('totp_last_timestep', { mode: 'number' }),
    /** MFA is mandatory: an account without it cannot pass the login flow. */
    invitedBy: uuid('invited_by'),
    invitedAt: timestamp('invited_at', { withTimezone: true }),
    activatedAt: timestamp('activated_at', { withTimezone: true }),
    deactivatedAt: timestamp('deactivated_at', { withTimezone: true }),
    portalTermsVersion: text('portal_terms_version'),
    portalTermsAcceptedAt: timestamp('portal_terms_accepted_at', { withTimezone: true }),
    notificationPreferences: jsonb('notification_preferences').notNull().default(sql`'{}'::jsonb`),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex('client_user_email_unique').on(table.email),
    index('client_user_client_idx').on(table.clientId),
  ],
);

export const clientInvitation = pgTable('client_invitation', {
  id: id(),
  clientId: uuid('client_id')
    .notNull()
    .references(() => client.id, { onDelete: 'cascade' }),
  email: text('email').notNull(),
  role: text('role').notNull().default('clientMember'),
  tokenHash: text('token_hash').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  acceptedAt: timestamp('accepted_at', { withTimezone: true }),
  invitedBy: uuid('invited_by').notNull(),
  createdAt: createdAt(),
});

export const session = pgTable(
  'session',
  {
    id: id(),
    /** Exactly one of these is set. */
    staffUserId: uuid('staff_user_id').references(() => staffUser.id, { onDelete: 'cascade' }),
    clientUserId: uuid('client_user_id').references(() => clientUser.id, { onDelete: 'cascade' }),
    tokenHash: text('token_hash').notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    mfaSatisfiedAt: timestamp('mfa_satisfied_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex('session_token_unique').on(table.tokenHash),
    index('session_client_user_idx').on(table.clientUserId),
    index('session_staff_user_idx').on(table.staffUserId),
  ],
);

/** Which engagements a client user may see. clientOwner sees all of their organisation's. */
export const clientEngagementAccess = pgTable(
  'client_engagement_access',
  {
    clientUserId: uuid('client_user_id')
      .notNull()
      .references(() => clientUser.id, { onDelete: 'cascade' }),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    grantedAt: createdAt(),
  },
  (table) => [primaryKey({ columns: [table.clientUserId, table.engagementId] })],
);

export const findingComment = pgTable(
  'finding_comment',
  {
    id: id(),
    findingId: uuid('finding_id')
      .notNull()
      .references(() => finding.id, { onDelete: 'cascade' }),
    authorKind: text('author_kind').notNull(),
    staffUserId: uuid('staff_user_id').references(() => staffUser.id, { onDelete: 'set null' }),
    clientUserId: uuid('client_user_id').references(() => clientUser.id, { onDelete: 'set null' }),
    parentId: uuid('parent_id'),
    markdown: text('markdown').notNull(),
    createdAt: createdAt(),
  },
  (table) => [index('finding_comment_finding_idx').on(table.findingId)],
);

export const retestRequest = pgTable(
  'retest_request',
  {
    id: id(),
    engagementId: uuid('engagement_id')
      .notNull()
      .references(() => engagement.id, { onDelete: 'cascade' }),
    requestedBy: uuid('requested_by')
      .notNull()
      .references(() => clientUser.id, { onDelete: 'cascade' }),
    requestedAt: createdAt(),
    findingIds: jsonb('finding_ids').notNull().default(sql`'[]'::jsonb`),
    note: text('note').notNull().default(''),
    /** A request is a record only. A human starts the job. */
    scheduledAt: timestamp('scheduled_at', { withTimezone: true }),
    completedAt: timestamp('completed_at', { withTimezone: true }),
  },
  (table) => [index('retest_request_engagement_idx').on(table.engagementId)],
);

/** Every download is recorded with who took it, so a leaked report can be traced. */
export const reportDownload = pgTable(
  'report_download',
  {
    id: id(),
    reportId: uuid('report_id')
      .notNull()
      .references(() => report.id, { onDelete: 'cascade' }),
    clientUserId: uuid('client_user_id').references(() => clientUser.id, { onDelete: 'set null' }),
    staffUserId: uuid('staff_user_id').references(() => staffUser.id, { onDelete: 'set null' }),
    watermarkText: text('watermark_text').notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    downloadedAt: createdAt(),
  },
  (table) => [index('report_download_report_idx').on(table.reportId)],
);

export const acknowledgement = pgTable('acknowledgement', {
  id: id(),
  engagementId: uuid('engagement_id')
    .notNull()
    .references(() => engagement.id, { onDelete: 'cascade' }),
  kind: text('kind').notNull(),
  /** The exact text acknowledged, stored so what was agreed to is not a moving target. */
  acknowledgedText: text('acknowledged_text').notNull(),
  acknowledgedBy: uuid('acknowledged_by').notNull(),
  note: text('note').notNull().default(''),
  acknowledgedAt: createdAt(),
});

export const panicStop = pgTable('panic_stop', {
  id: id(),
  scope: text('scope').notNull(),
  engagementId: uuid('engagement_id').references(() => engagement.id, { onDelete: 'cascade' }),
  active: boolean('active').notNull().default(true),
  pressedBy: text('pressed_by').notNull(),
  reason: text('reason').notNull(),
  pressedAt: createdAt(),
  clearedBy: text('cleared_by'),
  clearedAt: timestamp('cleared_at', { withTimezone: true }),
});

/** Reusable security questionnaire answers, surfaced in the portal. */
export const questionnaireAnswer = pgTable(
  'questionnaire_answer',
  {
    id: id(),
    category: text('category').notNull(),
    question: text('question').notNull(),
    answer: text('answer').notNull(),
    sortOrder: integer('sort_order').notNull().default(0),
    updatedAt: updatedAt(),
  },
  (table) => [index('questionnaire_category_idx').on(table.category)],
);

export const aiUsage = pgTable('ai_usage', {
  id: id(),
  engagementId: uuid('engagement_id').references(() => engagement.id, { onDelete: 'cascade' }),
  model: text('model').notNull(),
  purpose: text('purpose').notNull(),
  inputTokens: integer('input_tokens').notNull().default(0),
  outputTokens: integer('output_tokens').notNull().default(0),
  estimatedCostUsd: real('estimated_cost_usd').notNull().default(0),
  createdAt: createdAt(),
});
