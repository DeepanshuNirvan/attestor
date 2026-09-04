import { and, asc, eq, inArray } from 'drizzle-orm';
import { buildCoverageMatrix, type Finding } from '@attestor/findings';
import { resolvePolicy } from '@attestor/policy';
import { TOOL_IMAGES } from '@attestor/core';
import type { ReportData, ReportEvidence, ReportFinding } from '@attestor/report';
import type { Database } from '../db/client.ts';
import {
  client as clientTable,
  discoveredAsset as discoveredAssetTable,
  engagement as engagementTable,
  evidence as evidenceTable,
  finding as findingTable,
  reportSection as reportSectionTable,
  scanRun as scanRunTable,
  scopeItem as scopeItemTable,
  report as reportTable,
} from '../db/schema.ts';
import type { EvidenceStore } from './evidence-store.ts';
import { coverageFromRuns } from './run-service.ts';
import { loadToolDigests } from './tool-digests.ts';

/**
 * Assembling a report from the database.
 *
 * Two things are deliberate:
 *
 *   1. Only confirmed findings are included. A candidate cannot reach a document, and the
 *      pre-release checklist checks for it again.
 *   2. Prose blocks come from `report_section`, which is where a human's edits live. They are never
 *      regenerated at render time — an edited executive summary that reverts on the next render is
 *      how a report goes out with the wrong words in it.
 */

const DATE_FORMAT = new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'long',
  year: 'numeric',
  timeZone: 'UTC',
});

function formatDate(value: Date | null | undefined): string {
  return value ? DATE_FORMAT.format(value) : '';
}

function sectionText(sections: Map<string, string>, key: string, fallback: string[] = []): string[] {
  const stored = sections.get(key);
  if (!stored || stored.trim() === '') return fallback;
  return stored.split(/\n{2,}/).map((block) => block.trim()).filter(Boolean);
}

export interface BuildReportInput {
  engagementId: string;
  kind: 'assessment' | 'retest';
  reportVersion: string;
  branding: ReportData['branding'];
  /** Evidence is fetched and inlined; a report must open with no network. */
  evidenceStore: EvidenceStore;
  testerName: string;
  reviewerName: string;
  now?: Date;
}

export async function buildReportData(
  database: Database,
  input: BuildReportInput,
): Promise<ReportData> {
  const now = input.now ?? new Date();

  const engagements = await database
    .select()
    .from(engagementTable)
    .where(eq(engagementTable.id, input.engagementId))
    .limit(1);
  const record = engagements[0];
  if (!record) throw new Error('engagement not found');

  const clients = await database
    .select()
    .from(clientTable)
    .where(eq(clientTable.id, record.clientId))
    .limit(1);
  const clientRecord = clients[0];
  if (!clientRecord) throw new Error('client not found');

  const { policy } = resolvePolicy([
    { name: 'client', yamlSource: clientRecord.policyYaml },
    { name: 'engagement', yamlSource: record.policyYaml },
  ]);

  const [scopeItems, findings, sections, runs, assets, digests] = await Promise.all([
    database.select().from(scopeItemTable).where(eq(scopeItemTable.engagementId, input.engagementId)),
    database
      .select()
      .from(findingTable)
      .where(
        and(
          eq(findingTable.engagementId, input.engagementId),
          inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
        ),
      )
      .orderBy(asc(findingTable.referenceSequence)),
    database
      .select()
      .from(reportSectionTable)
      .where(eq(reportSectionTable.engagementId, input.engagementId)),
    database.select().from(scanRunTable).where(eq(scanRunTable.engagementId, input.engagementId)),
    database
      .select()
      .from(discoveredAssetTable)
      .where(eq(discoveredAssetTable.engagementId, input.engagementId))
      .orderBy(asc(discoveredAssetTable.host), asc(discoveredAssetTable.port)),
    loadToolDigests(),
  ]);

  const sectionMap = new Map(sections.map((section) => [section.sectionKey, section.markdown]));

  const findingIds = findings.map((item) => item.id);
  const evidenceRows =
    findingIds.length > 0
      ? await database
          .select()
          .from(evidenceTable)
          .where(inArray(evidenceTable.findingId, findingIds))
      : [];

  const evidenceByFinding = new Map<string, ReportEvidence[]>();
  for (const row of evidenceRows) {
    if (!row.findingId || row.purgedAt) continue;
    const list = evidenceByFinding.get(row.findingId) ?? [];

    // Evidence is inlined so the document opens offline. Images become data URIs; text is embedded
    // as-is, already masked and redacted at capture time.
    const body = await input.evidenceStore.read(row.objectKey).catch(() => null);
    if (body) {
      const isImage = row.contentType.startsWith('image/');
      list.push({
        kind: row.kind,
        caption: `${row.kind} · sha256 ${row.sha256.slice(0, 16)}…`,
        ...(isImage
          ? { imageDataUri: `data:${row.contentType};base64,${body.toString('base64')}` }
          : { text: body.toString('utf8').slice(0, 20_000) }),
      });
    }
    evidenceByFinding.set(row.findingId, list);
  }

  const reportFindings: ReportFinding[] = findings.map((item) => ({
    id: item.id,
    engagementId: item.engagementId,
    reference: item.reference ?? undefined,
    source: item.source as Finding['source'],
    scanRunId: item.scanRunId ?? undefined,
    toolFindingRef: item.toolFindingRef ?? undefined,
    toolName: item.toolName ?? undefined,
    checkId: item.checkId ?? undefined,
    title: item.title,
    description: item.description,
    severity: item.severity as Finding['severity'],
    severityOverrideReason: item.severityOverrideReason ?? undefined,
    cvssVersion: (item.cvssVersion as Finding['cvssVersion']) ?? undefined,
    cvssVector: item.cvssVector ?? undefined,
    cvssScore: item.cvssScore ?? undefined,
    owaspRiskScores: (item.owaspRiskScores as Finding['owaspRiskScores']) ?? undefined,
    cweId: item.cweId ?? undefined,
    owaspCategory: item.owaspCategory ?? undefined,
    apiCategory: item.apiCategory ?? undefined,
    wstgId: item.wstgId ?? undefined,
    asvsRequirement: item.asvsRequirement ?? undefined,
    masvsControl: item.masvsControl ?? undefined,
    llmCategory: item.llmCategory ?? undefined,
    affectedAssets: item.affectedAssets as Finding['affectedAssets'],
    businessImpact: item.businessImpact,
    likelihood: item.likelihood,
    attackerPrerequisites: item.attackerPrerequisites,
    reproductionSteps: item.reproductionSteps as string[],
    remediation: item.remediation,
    references: item.references as Finding['references'],
    status: item.status as Finding['status'],
    dedupeKey: item.dedupeKey,
    attackSuccessRate: item.attackSuccessRate ?? undefined,
    attemptCount: item.attemptCount ?? undefined,
    firstSeenAt: item.firstSeenAt,
    lastSeenAt: item.lastSeenAt,
    confirmedAt: item.confirmedAt ?? undefined,
    confirmedBy: item.confirmedBy ?? undefined,
    fixedAt: item.fixedAt ?? undefined,
    retestedAt: item.retestedAt ?? undefined,
    evidence: evidenceByFinding.get(item.id) ?? [],
  }));

  const findingCountByCheckId = new Map<string, number>();
  for (const item of findings) {
    if (!item.checkId) continue;
    findingCountByCheckId.set(item.checkId, (findingCountByCheckId.get(item.checkId) ?? 0) + 1);
  }

  const { completedRuns, abortedRuns } = await coverageFromRuns(database, input.engagementId);

  const manuallyCovered = new Map<string, string>();
  const manualCoverage = sectionMap.get('manualCoverage');
  if (manualCoverage) {
    for (const line of manualCoverage.split('\n')) {
      const [checkId, ...rest] = line.split(':');
      if (checkId && rest.length > 0) manuallyCovered.set(checkId.trim(), rest.join(':').trim());
    }
  }

  const excludedCheckIds = new Map<string, string>();
  for (const checkId of policy.checks.exclude) {
    excludedCheckIds.set(checkId, 'Excluded by the engagement policy at the client’s request.');
  }

  const coverage = buildCoverageMatrix({
    selectedModules: policy.modules,
    excludedCheckIds,
    completedRuns,
    abortedRuns,
    manuallyCovered,
    findingCountByCheckId,
  });

  // Only tools that actually ran. Listing every scan_run row put dry runs, scope refusals and
  // crashes into a table headed "Tools used", which is a claim about work that was not done. The
  // digest is printed in full because "we used nuclei" is not a statement anyone can check and
  // "we used nuclei at sha256:…" is — it is the same reason the images are pinned at all.
  const toolsUsed = [
    ...new Set(runs.filter((run) => run.status === 'completed' && !run.dryRun).map((run) => run.toolName)),
  ]
    .sort()
    .map((toolName) => {
      const tool = TOOL_IMAGES.find((image) => image.id === toolName);
      return {
        name: tool?.displayName ?? toolName,
        version: digests[toolName] ?? 'digest not recorded',
        purpose: tool?.purpose ?? 'Not recorded.',
      };
    });

  const narrativeStored = sectionMap.get('attackNarrative');

  return {
    kind: input.kind,
    templateId: record.reportTemplateId,
    branding: input.branding,

    clientLegalName: clientRecord.legalName,
    clientDisplayName: clientRecord.name,
    engagementTitle: record.title,
    reportReference: record.reference,
    reportVersion: input.reportVersion,
    reportDate: formatDate(now),
    testStartDate: formatDate(record.startsAt),
    testEndDate: formatDate(record.endsAt),
    statusDate: formatDate(now),

    testType: record.testType as ReportData['testType'],
    cvssVersion: policy.report.cvssVersion,
    methodology: [
      'OWASP Web Security Testing Guide 4.2',
      'OWASP Application Security Verification Standard 5.0',
      'OWASP Top 10:2025',
      'OWASP API Security Top 10:2023',
      ...(policy.modules.includes('mobile') ? ['OWASP MASVS 2.1'] : []),
      ...(policy.modules.includes('llm') ? ['OWASP Top 10 for LLM Applications 2025'] : []),
      'NIST SP 800-115',
      'PTES',
    ],
    timezone: record.timezone,

    scopeIncluded: scopeItems.filter((item) => item.included).map((item) => `${item.value} (${item.kind})`),
    scopeExcluded: [
      ...scopeItems.filter((item) => !item.included).map((item) => `${item.value} (${item.kind})`),
      'Denial-of-service, load and volumetric testing of any kind, which this platform cannot perform.',
      'Social engineering of personnel and physical intrusion.',
    ],
    environments: sectionText(sectionMap, 'environments', ['Not recorded.']),
    rolesTested: sectionText(sectionMap, 'rolesTested', ['Not recorded.']),
    constraints: sectionText(sectionMap, 'constraints', []),
    toolsUsed,

    documentControl: {
      author: input.testerName,
      reviewer: input.reviewerName,
      distribution: [`${clientRecord.legalName} — as agreed in the engagement documents`],
      versionHistory: [
        { version: input.reportVersion, date: formatDate(now), note: 'Issued to the client' },
      ],
    },

    executiveSummary: sectionText(sectionMap, 'executiveSummary'),
    headlineActions: sectionText(sectionMap, 'headlineActions'),
    positiveObservations: sectionText(sectionMap, 'positiveObservations'),
    roadmap: [
      { horizon: 'First 30 days', items: sectionText(sectionMap, 'roadmap30') },
      { horizon: 'Days 30 to 60', items: sectionText(sectionMap, 'roadmap60') },
      { horizon: 'Days 60 to 90', items: sectionText(sectionMap, 'roadmap90') },
    ].filter((horizon) => horizon.items.length > 0),

    attackNarrative: narrativeStored
      ? {
          title: sectionMap.get('attackNarrativeTitle') ?? 'Attack narrative',
          steps: narrativeStored
            .split(/\n{2,}/)
            .map((block) => {
              const [heading = '', ...body] = block.split('\n');
              return { heading: heading.trim(), body: body.join(' ').trim() };
            })
            .filter((step) => step.heading !== ''),
          conclusion: sectionMap.get('attackNarrativeConclusion') ?? '',
          diagram: sectionMap.get('attackNarrativeDiagram'),
        }
      : undefined,

    findings: reportFindings,
    coverage,
    complianceFrameworks: policy.report.complianceFrameworks,

    appendices: {
      // What the engagement found, falling back to what was scoped when reconnaissance produced
      // nothing — an inventory that silently equals the scope list tells the reader nothing.
      assetInventory:
        assets.length > 0
          ? [...new Set(assets.map((asset) => asset.host))].sort()
          : scopeItems.filter((item) => item.included).map((item) => item.value),
      portsAndServices: assets
        .filter((asset) => asset.kind === 'port' && asset.port !== null)
        .map((asset) => {
          const metadata = asset.metadata as Record<string, string | number | boolean>;
          return {
            host: asset.host,
            port: asset.port ?? 0,
            service: String(metadata.service ?? 'unknown'),
            version: String(metadata.version ?? ''),
          };
        }),
      outOfScopeNotes: sectionText(sectionMap, 'outOfScopeNotes', [
        'No denial-of-service, load or volumetric testing was performed. The platform used for this assessment contains no such capability.',
      ]),
      glossary: [
        {
          term: 'CVSS',
          definition:
            'Common Vulnerability Scoring System. The vector string beside each score records how it was derived, so the score can be recomputed.',
        },
        {
          term: 'Coverage matrix',
          definition:
            'A record of what was tested, partially tested and not tested, generated from what actually ran rather than asserted.',
        },
      ],
    },
  };
}

export async function nextReportVersion(
  database: Database,
  engagementId: string,
  kind: string,
): Promise<string> {
  const existing = await database
    .select({ version: reportTable.version })
    .from(reportTable)
    .where(and(eq(reportTable.engagementId, engagementId), eq(reportTable.kind, kind)));

  const majors = existing
    .map((row) => Number.parseFloat(row.version))
    .filter((value) => Number.isFinite(value));

  return majors.length === 0 ? '1.0' : (Math.max(...majors) + 0.1).toFixed(1);
}
