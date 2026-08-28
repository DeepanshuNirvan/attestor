import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { eq } from 'drizzle-orm';
import { createLogger, engagementReference, loadSeedConfig } from '@attestor/shared';
import { loadProfileYaml } from '@attestor/policy';
import { sampleFindings, buildSampleReportData } from '@attestor/report/fixtures';
import { consoleDatabase } from './client.ts';
import {
  acknowledgement,
  authorisation,
  client as clientTable,
  clientInvitation,
  engagement as engagementTable,
  finding as findingTable,
  questionnaireAnswer,
  reportSection,
  scanRun,
  scopeItem,
  staffUser,
} from './schema.ts';
import { beginTotpEnrolment, hashPassword, hashToken, newSessionToken } from '../services/auth.ts';
import { CredentialVault } from '../services/credential-vault.ts';

/**
 * Demo data.
 *
 * Seeds one client, one engagement in `reportDraft` with the sample findings already confirmed, the
 * report prose written, and a client invitation ready to accept. The point is that `docker compose
 * up && pnpm seed` produces something the owner can click through end to end, including generating
 * a report that is genuinely presentable.
 *
 * It is idempotent: running it twice does not duplicate anything.
 */

const DEMO_CLIENT_NAME = 'Sample Retail';

const QUESTIONNAIRE_ANSWERS = [
  {
    category: 'Testing process',
    question: 'How often do you perform penetration testing, and by whom?',
    answer:
      'Independent penetration testing is performed by Attestor Security, a specialist firm that does not design, build or operate any of our systems. Testing follows OWASP WSTG 4.2 and ASVS 5.0, with findings mapped to the OWASP Top 10:2025 and, for our APIs, the OWASP API Security Top 10. Each engagement includes a retest of remediated findings.',
    sortOrder: 1,
  },
  {
    category: 'Testing process',
    question: 'What is the scope of your most recent test?',
    answer:
      'The most recent assessment covered our customer-facing web application, the API behind it, and every user role including administrative access. The report contains a coverage matrix recording what was tested, what was partially tested and what was not, with a reason in each case. We can share the attestation letter on request.',
    sortOrder: 2,
  },
  {
    category: 'Testing process',
    question: 'Are findings tracked to closure?',
    answer:
      'Yes. Every finding is tracked with a first-seen date, an owner and a remediation date, and is independently re-verified at retest. Findings we accept rather than fix carry a written justification and a named approver.',
    sortOrder: 3,
  },
  {
    category: 'Tester independence',
    question: 'Is your security testing independent of your development team?',
    answer:
      'Yes. Attestor Security did not design, develop, operate or maintain any of the systems it assesses, and holds no interest in our company beyond the engagement fee. This independence is stated in every report.',
    sortOrder: 1,
  },
  {
    category: 'Data handling',
    question: 'What data does your penetration testing provider hold, and for how long?',
    answer:
      'Testing evidence is masked at capture so personal data does not reach storage, is encrypted at rest, and is deleted 90 days after report release with a written deletion confirmation. Credentials we supply are held in an encrypted vault, never travel through email, and are cryptographically destroyed when the engagement closes. A data processing agreement is in place.',
    sortOrder: 1,
  },
  {
    category: 'Data handling',
    question: 'Is any of your data sent to third-party AI services?',
    answer:
      'No. Our provider\'s AI-assist layer is disabled for our engagements. Where it is enabled, only redacted findings text is sent — never raw evidence, credentials or customer data.',
    sortOrder: 2,
  },
  {
    category: 'Vulnerability management',
    question: 'How do you handle critical vulnerabilities found during testing?',
    answer:
      'Critical findings are notified to a nominated contact as soon as they are validated, ahead of the report, with reproduction steps. Our engagement documents set a maximum notification window for this.',
    sortOrder: 1,
  },
  {
    category: 'Vulnerability management',
    question: 'Do you scan dependencies and container images?',
    answer:
      'Yes. Dependency, container and infrastructure-as-code scanning runs in our pipeline, and a software bill of materials is generated for each release. Reachable high-severity matches fail the build.',
    sortOrder: 2,
  },
];

export async function seed(databaseUrl: string, vaultMasterKey: string): Promise<void> {
  const logger = createLogger({ service: 'seed' });
  const database = consoleDatabase(databaseUrl);
  const vault = new CredentialVault(vaultMasterKey);

  /* Staff -------------------------------------------------------------------------------- */

  const existingStaff = await database.select({ id: staffUser.id }).from(staffUser).limit(1);
  let ownerId = existingStaff[0]?.id;

  if (!ownerId) {
    const enrolment = beginTotpEnrolment('owner@attestorsecurity.com');
    const [created] = await database
      .insert(staffUser)
      .values({
        email: 'owner@attestorsecurity.com',
        name: 'Attestor owner',
        passwordHash: await hashPassword('change-this-password-now'),
        role: 'owner',
        // Sealed exactly as the bootstrap route seals it, under the same 'staff-mfa' context. A
        // demo account whose secret is stored differently is a demo account that cannot sign in,
        // and the first thing anybody does with seeded data is try to sign in.
        totpSecretSealed: JSON.stringify(await vault.seal('staff-mfa', enrolment.secretBase32)),
        totpEnrolledAt: new Date(),
      })
      .returning({ id: staffUser.id });
    ownerId = created?.id;

    // The logger redacts anything that looks like a secret, which is correct everywhere else and
    // fatal here: an otpauth URL logged through it arrives as secret=[REDACTED], and the enrolment
    // secret is random per seed, so nobody can ever enrol and the demo account cannot sign in.
    // Written to a gitignored file instead — deliberate to open, trivial to delete, never in a log.
    const credentialsPath = fileURLToPath(new URL('../../../../.seed-credentials.txt', import.meta.url));
    await writeFile(
      credentialsPath,
      [
        'Attestor demo credentials',
        '=========================',
        'Delete this file once you have enrolled. It is gitignored, not secret-safe.',
        '',
        'Console sign-in: http://localhost:3000/login',
        'Email:    owner@attestorsecurity.com',
        'Password: change-this-password-now',
        '',
        'Add this to an authenticator app to get the six-digit code:',
        enrolment.otpauthUrl,
        '',
        `Or enter the secret by hand: ${enrolment.secretBase32}`,
        '',
      ].join('\n'),
      'utf8',
    );

    logger.info('demo staff account created', {
      email: 'owner@attestorsecurity.com',
      credentialsPath,
      note: 'Password and MFA enrolment written to that file. Change the password and re-enrol MFA before this touches anything real.',
    });
  }

  /* Client and engagement ---------------------------------------------------------------- */

  const existingClients = await database
    .select()
    .from(clientTable)
    .where(eq(clientTable.name, DEMO_CLIENT_NAME))
    .limit(1);

  let clientId = existingClients[0]?.id;
  if (!clientId) {
    const [created] = await database
      .insert(clientTable)
      .values({
        name: DEMO_CLIENT_NAME,
        legalName: 'Sample Retail Private Limited',
        country: 'IN',
        contacts: [
          { name: 'Head of Engineering', email: 'engineering@sample-retail.example', role: 'primary' },
        ],
        dataProcessingAgreementSignedAt: new Date('2026-06-20T00:00:00Z'),
        policyYaml: '',
        notes: 'Demo client. Everything under this record is seeded data.',
      })
      .returning({ id: clientTable.id });
    clientId = created?.id;
  }
  if (!clientId || !ownerId) throw new Error('seed could not create the demo client');

  const reference = engagementReference({ year: 2026, sequence: 1 });
  const existingEngagements = await database
    .select()
    .from(engagementTable)
    .where(eq(engagementTable.reference, reference))
    .limit(1);

  if (existingEngagements[0]) {
    logger.info('demo engagement already present; nothing to do', { reference });
    return;
  }

  const [engagement] = await database
    .insert(engagementTable)
    .values({
      clientId,
      reference,
      referenceYear: 2026,
      referenceSequence: 1,
      type: 'webApplication',
      title: 'Web application and API security assessment',
      state: 'reportDraft',
      testType: 'greyBox',
      startsAt: new Date('2026-07-13T04:00:00Z'),
      endsAt: new Date('2026-07-17T13:00:00Z'),
      timezone: 'Asia/Kolkata',
      currency: 'INR',
      quotedAmount: 55_000,
      advancePaidAt: new Date('2026-07-10T00:00:00Z'),
      policyYaml: await loadProfileYaml('standard-web-app'),
      thirdPartyInfrastructureAcknowledgedAt: new Date('2026-07-12T00:00:00Z'),
      preFlightChecklist: {
        authorisationValid: true,
        windowOpen: true,
        credentialsVerified: true,
        emergencyContactRecorded: true,
        backupsConfirmed: true,
        wafAllowlisted: true,
        environmentAcknowledged: true,
      },
    })
    .returning();

  const engagementId = engagement?.id;
  if (!engagementId) throw new Error('seed could not create the demo engagement');

  await database.insert(scopeItem).values([
    { engagementId, kind: 'domain', value: 'juice.attestor-lab.internal', included: true, notes: 'Customer web application, staging' },
    { engagementId, kind: 'url', value: 'https://juice.attestor-lab.internal/rest', included: true, notes: 'REST API' },
    { engagementId, kind: 'domain', value: 'payments.provider.example', included: false, notes: 'Third-party payment provider, out of scope by agreement' },
  ]);

  await database.insert(authorisation).values({
    engagementId,
    signedBy: 'A. Director',
    signerRole: 'Chief Technology Officer',
    signerEmail: 'cto@sample-retail.example',
    signedAt: new Date('2026-07-10T09:00:00Z'),
    documentObjectKey: 'engagements/demo/authorisation.pdf',
    documentSha256: 'a'.repeat(64),
    assetList: ['juice.attestor-lab.internal', 'https://juice.attestor-lab.internal/rest'],
    exclusionList: ['payments.provider.example'],
    sourceAddresses: ['198.51.100.7'],
    emergencyContact: {
      name: 'On-call engineer',
      role: 'Platform',
      phone: '+91 90000 00000',
      email: 'oncall@sample-retail.example',
    },
    criticalNotificationHours: 4,
    validFrom: new Date('2026-07-13T00:00:00Z'),
    validUntil: new Date('2026-07-18T00:00:00Z'),
  });

  await database.insert(acknowledgement).values({
    engagementId,
    kind: 'thirdPartyInfrastructure',
    acknowledgedText:
      "The client's authorisation may not cover shared or third-party infrastructure that the in-scope names resolve to. The tester has confirmed that it does.",
    acknowledgedBy: ownerId,
    note: 'Staging runs on a dedicated host confirmed by the client.',
  });

  /* Runs and findings --------------------------------------------------------------------- */

  const demoRuns = [
    { module: 'recon', toolName: 'subfinder', checks: ['recon-subdomain-enumeration'] },
    { module: 'recon', toolName: 'httpx', checks: ['recon-http-probing', 'recon-technology-inventory'] },
    { module: 'recon', toolName: 'tlsx', checks: ['recon-tls-configuration'] },
    { module: 'web', toolName: 'zap', checks: ['web-security-headers', 'web-cookie-attributes', 'web-reflected-xss'] },
    { module: 'web', toolName: 'nuclei', checks: ['web-security-headers', 'web-error-handling'] },
    { module: 'api', toolName: 'schemathesis', checks: ['api-injection-through-schema', 'api-error-verbosity'] },
  ];

  for (const run of demoRuns) {
    await database.insert(scanRun).values({
      engagementId,
      module: run.module,
      toolName: run.toolName,
      toolVersionDigest: `sha256:${'0'.repeat(64)}`,
      coveredCheckIds: run.checks,
      targets: ['juice.attestor-lab.internal'],
      status: 'completed',
      startedAt: new Date('2026-07-13T05:00:00Z'),
      finishedAt: new Date('2026-07-13T06:00:00Z'),
      exitCode: 0,
      stats: { rawFindings: 4, created: 3, updated: 0, suppressed: 0 },
    });
  }

  for (const [index, sample] of sampleFindings.entries()) {
    await database.insert(findingTable).values({
      engagementId,
      reference: sample.reference?.replace('ATT-2026-000', reference) ?? null,
      referenceSequence: index + 1,
      source: sample.source,
      toolName: sample.toolName ?? null,
      checkId: sample.checkId ?? null,
      title: sample.title,
      description: sample.description,
      severity: sample.severity,
      cvssVersion: sample.cvssVersion ?? null,
      cvssVector: sample.cvssVector ?? null,
      cvssScore: sample.cvssScore ?? null,
      cweId: sample.cweId ?? null,
      owaspCategory: sample.owaspCategory ?? null,
      apiCategory: sample.apiCategory ?? null,
      wstgId: sample.wstgId ?? null,
      asvsRequirement: sample.asvsRequirement ?? null,
      affectedAssets: sample.affectedAssets,
      businessImpact: sample.businessImpact,
      likelihood: sample.likelihood,
      attackerPrerequisites: sample.attackerPrerequisites,
      reproductionSteps: sample.reproductionSteps,
      remediation: sample.remediation,
      references: sample.references,
      status: 'open',
      dedupeKey: sample.dedupeKey,
      confirmedAt: new Date('2026-07-17T10:00:00Z'),
      confirmedBy: ownerId,
      firstSeenAt: sample.firstSeenAt,
      lastSeenAt: sample.lastSeenAt,
    });
  }

  /* Report prose --------------------------------------------------------------------------- */

  const sampleData = buildSampleReportData();
  const sections: [string, string][] = [
    ['executiveSummary', sampleData.executiveSummary.join('\n\n')],
    ['headlineActions', sampleData.headlineActions.join('\n\n')],
    ['positiveObservations', sampleData.positiveObservations.join('\n\n')],
    ['roadmap30', sampleData.roadmap[0]?.items.join('\n\n') ?? ''],
    ['roadmap60', sampleData.roadmap[1]?.items.join('\n\n') ?? ''],
    ['roadmap90', sampleData.roadmap[2]?.items.join('\n\n') ?? ''],
    ['environments', sampleData.environments.join('\n\n')],
    ['rolesTested', sampleData.rolesTested.join('\n\n')],
    ['constraints', sampleData.constraints.join('\n\n')],
    ['attackNarrativeTitle', sampleData.attackNarrative?.title ?? ''],
    [
      'attackNarrative',
      (sampleData.attackNarrative?.steps ?? [])
        .map((step) => `${step.heading}\n${step.body}`)
        .join('\n\n'),
    ],
    ['attackNarrativeConclusion', sampleData.attackNarrative?.conclusion ?? ''],
    ['attackNarrativeDiagram', sampleData.attackNarrative?.diagram ?? ''],
    [
      'manualCoverage',
      [
        'web-workflow-bypass: Tested by hand across the checkout and returns flows.',
        'web-price-and-quantity-manipulation: Tested by hand.',
        'web-finding-chaining: Tested by hand; produced the attack narrative.',
        'web-vertical-access-control: Replay matrix across three roles.',
        'web-horizontal-access-control: Replay matrix across two customer accounts.',
      ].join('\n'),
    ],
  ];

  for (const [key, markdown] of sections) {
    if (markdown.trim() === '') continue;
    await database.insert(reportSection).values({
      engagementId,
      sectionKey: key,
      markdown,
      isAiDraft: false,
      approvedAt: new Date(),
      approvedBy: ownerId,
    });
  }

  /* Questionnaire and a client invitation --------------------------------------------------- */

  const existingAnswers = await database
    .select({ id: questionnaireAnswer.id })
    .from(questionnaireAnswer)
    .limit(1);
  if (!existingAnswers[0]) {
    await database.insert(questionnaireAnswer).values(QUESTIONNAIRE_ANSWERS);
  }

  const invitationToken = newSessionToken();
  await database.insert(clientInvitation).values({
    clientId,
    email: 'engineering@sample-retail.example',
    role: 'clientOwner',
    tokenHash: hashToken(invitationToken),
    expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000),
    invitedBy: ownerId,
  });

  logger.info('demo data seeded', {
    engagement: reference,
    findings: sampleFindings.length,
    portalInvitation: `open /invitation/${invitationToken} on the portal to accept it`,
  });
}

const isEntryPoint = process.argv[1]?.endsWith('seed.ts') === true;
if (isEntryPoint) {
  const config = loadSeedConfig();
  await seed(config.DATABASE_URL, config.VAULT_MASTER_KEY);
}
