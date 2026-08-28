import { and, desc, eq, isNull } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  LEGAL_BLOCKS,
  renderAttestationLetterHtml,
  renderDeletionConfirmationHtml,
  renderPdf,
  renderReportHtml,
  runChecklist,
  watermarkFor,
} from '@attestor/report';
import type { ConsoleContext } from '../context.ts';
import {
  client as clientTable,
  engagement as engagementTable,
  report as reportTable,
  reportDownload,
  reportSection as reportSectionTable,
} from '../db/schema.ts';
import { buildReportData, nextReportVersion } from '../services/report-service.ts';
import { actorIdOf, requestContext, requireSession } from './session-guard.ts';

/**
 * Reports.
 *
 * Release is gated by the checklist, and the gate is here rather than in the console UI: a request
 * that would release a report with a finding missing evidence is refused with the list of what is
 * missing, whatever the caller sends.
 */

function brandingFor(): Parameters<typeof buildReportData>[1]['branding'] {
  return {
    wordmark: 'Attestor',
    legalEntityName: 'Attestor Security',
    brandName: 'Attestor Security',
    contactEmail: 'hello@attestorsecurity.com',
    country: 'India',
    jurisdiction: 'the courts at the registered office of Attestor Security',
  };
}

/**
 * Section keys that a model wrote and nobody has approved.
 *
 * Read at preflight and again at release, from the database rather than from the request, so a
 * console that forgot to refresh cannot release a report with an unapproved draft in it.
 */
async function unapprovedAiDrafts(
  database: ConsoleContext['database'],
  engagementId: string,
): Promise<string[]> {
  const rows = await database
    .select({ sectionKey: reportSectionTable.sectionKey })
    .from(reportSectionTable)
    .where(
      and(
        eq(reportSectionTable.engagementId, engagementId),
        eq(reportSectionTable.isAiDraft, true),
        isNull(reportSectionTable.approvedAt),
      ),
    );
  return rows.map((row) => row.sectionKey);
}

export function registerReportRoutes(app: FastifyInstance, context: ConsoleContext): void {
  const guard = requireSession({ database: context.database, expect: 'staff' });

  app.get('/engagements/:id/report/sections', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const sections = await context.database
      .select()
      .from(reportSectionTable)
      .where(eq(reportSectionTable.engagementId, id));
    return reply.send({ sections });
  });

  app.put('/engagements/:id/report/sections/:key', { preHandler: guard }, async (request, reply) => {
    const { id, key } = request.params as { id: string; key: string };
    const parsed = z
      .object({ markdown: z.string().max(60_000), approve: z.boolean().default(false) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    await context.database
      .insert(reportSectionTable)
      .values({
        engagementId: id,
        sectionKey: key,
        markdown: parsed.data.markdown,
        isAiDraft: false,
        approvedAt: parsed.data.approve ? new Date() : null,
        approvedBy: parsed.data.approve ? actorIdOf(request) : null,
      })
      .onConflictDoUpdate({
        target: [reportSectionTable.engagementId, reportSectionTable.sectionKey],
        set: {
          markdown: parsed.data.markdown,
          // A human edit clears the AI-draft marker: once somebody has rewritten it, it is theirs.
          isAiDraft: false,
          approvedAt: parsed.data.approve ? new Date() : null,
          approvedBy: parsed.data.approve ? actorIdOf(request) : null,
          updatedAt: new Date(),
        },
      });

    return reply.send({ ok: true });
  });

  app.get('/engagements/:id/report/preflight', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const data = await buildReportData(context.database, {
      engagementId: id,
      kind: 'assessment',
      reportVersion: await nextReportVersion(context.database, id, 'assessment'),
      branding: brandingFor(),
      evidenceStore: context.evidence,
      testerName: 'Attestor Security',
      reviewerName: 'Attestor Security',
    });

    const engagements = await context.database
      .select({ reviewChecklist: engagementTable.reviewChecklist })
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);

    const outcome = runChecklist(
      data,
      (engagements[0]?.reviewChecklist as Record<string, boolean>) ?? {},
      { unapprovedAiDrafts: await unapprovedAiDrafts(context.database, id) },
    );

    const unreviewedLegal = LEGAL_BLOCKS.filter(
      (block) => block.mandatory && block.lawyerReviewedAt === null,
    ).map((block) => block.id);

    return reply.send({ ...outcome, unreviewedLegal });
  });

  app.put('/engagements/:id/report/checklist', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z.record(z.string(), z.boolean()).safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    await context.database
      .update(engagementTable)
      .set({ reviewChecklist: parsed.data, updatedAt: new Date() })
      .where(eq(engagementTable.id, id));

    return reply.send({ ok: true });
  });

  app.post('/engagements/:id/report', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ kind: z.enum(['assessment', 'retest']).default('assessment') })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const version = await nextReportVersion(context.database, id, parsed.data.kind);
    const data = await buildReportData(context.database, {
      engagementId: id,
      kind: parsed.data.kind,
      reportVersion: version,
      branding: brandingFor(),
      evidenceStore: context.evidence,
      testerName: 'Attestor Security',
      reviewerName: 'Attestor Security',
    });

    const html = await renderReportHtml(data);
    const pdf = await renderPdf(html, { format: 'A4' });

    const htmlObject = await context.reports.capture({
      engagementId: id,
      kind: 'file',
      binary: Buffer.from(html, 'utf8'),
      contentType: 'text/html; charset=utf-8',
      filename: `${data.reportReference}-v${version}.html`,
    });
    const pdfObject = await context.reports.capture({
      engagementId: id,
      kind: 'file',
      binary: pdf,
      contentType: 'application/pdf',
      filename: `${data.reportReference}-v${version}.pdf`,
    });

    const [created] = await context.database
      .insert(reportTable)
      .values({
        engagementId: id,
        kind: parsed.data.kind,
        version,
        templateId: data.templateId,
        legalTemplateVersions: Object.fromEntries(
          LEGAL_BLOCKS.map((block) => [block.id, block.version]),
        ),
        renderedHtmlKey: htmlObject.objectKey,
        pdfKey: pdfObject.objectKey,
        coverageSnapshot: {
          total: data.coverage.length,
          tested: data.coverage.filter((entry) => entry.state === 'tested').length,
        },
      })
      .returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'report.generated',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { reportId: created?.id, kind: parsed.data.kind, version },
      ...requestContext(request),
    });

    return reply.code(201).send({ report: created });
  });

  app.post('/reports/:reportId/release', { preHandler: guard }, async (request, reply) => {
    const { reportId } = request.params as { reportId: string };
    const parsed = z
      .object({ recipients: z.array(z.string().email()).min(1).max(20) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select()
      .from(reportTable)
      .where(eq(reportTable.id, reportId))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });
    if (record.releasedAt) return reply.code(409).send({ error: 'already released' });

    // Re-run the checklist at release rather than trusting the one that ran at generation: findings
    // change between the two, and this is the last gate before a client sees the document.
    const data = await buildReportData(context.database, {
      engagementId: record.engagementId,
      kind: record.kind as 'assessment' | 'retest',
      reportVersion: record.version,
      branding: brandingFor(),
      evidenceStore: context.evidence,
      testerName: 'Attestor Security',
      reviewerName: 'Attestor Security',
    });

    const engagements = await context.database
      .select({ reviewChecklist: engagementTable.reviewChecklist })
      .from(engagementTable)
      .where(eq(engagementTable.id, record.engagementId))
      .limit(1);

    const outcome = runChecklist(
      data,
      (engagements[0]?.reviewChecklist as Record<string, boolean>) ?? {},
      { unapprovedAiDrafts: await unapprovedAiDrafts(context.database, record.engagementId) },
    );

    if (!outcome.releasable) {
      return reply.code(409).send({
        error: 'the pre-release checklist is not complete',
        blocking: outcome.blocking,
        awaitingHuman: outcome.awaitingHuman,
      });
    }

    await context.database
      .update(reportTable)
      .set({
        releasedAt: new Date(),
        releasedBy: actorIdOf(request),
        recipientList: parsed.data.recipients,
      })
      .where(eq(reportTable.id, reportId));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'report.released',
      subjectType: 'report',
      subjectId: reportId,
      metadata: { recipients: parsed.data.recipients, version: record.version },
      ...requestContext(request),
    });

    // Nothing is emailed here. The client-facing notification is queued for a human to release.
    return reply.send({ ok: true, note: 'Report released in the portal. No email has been sent.' });
  });

  app.post('/engagements/:id/attestation-letter', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const data = await buildReportData(context.database, {
      engagementId: id,
      kind: 'assessment',
      reportVersion: await nextReportVersion(context.database, id, 'attestation'),
      branding: brandingFor(),
      evidenceStore: context.evidence,
      testerName: 'Attestor Security',
      reviewerName: 'Attestor Security',
    });

    const html = await renderAttestationLetterHtml({
      branding: data.branding,
      clientLegalName: data.clientLegalName,
      engagementTitle: data.engagementTitle,
      reportReference: data.reportReference,
      reportVersion: data.reportVersion,
      reportDate: data.reportDate,
      statusDate: data.reportDate,
      testStartDate: data.testStartDate,
      testEndDate: data.testEndDate,
      testType: data.testType,
      cvssVersion: data.cvssVersion,
      methodology: data.methodology,
      scopeSummary: data.scopeIncluded,
      findings: data.findings,
      testerName: 'Attestor Security',
      testerTitle: 'Principal consultant',
      registeredAddress: 'Registered address to be published on incorporation',
    });

    const pdf = await renderPdf(html, { format: 'A4' });
    const stored = await context.reports.capture({
      engagementId: id,
      kind: 'file',
      binary: pdf,
      contentType: 'application/pdf',
      filename: `${data.reportReference}-attestation.pdf`,
    });

    const [created] = await context.database
      .insert(reportTable)
      .values({
        engagementId: id,
        kind: 'attestation',
        version: data.reportVersion,
        templateId: data.templateId,
        pdfKey: stored.objectKey,
        legalTemplateVersions: { 'attestation-letter': '1.0.0-draft' },
      })
      .returning();

    return reply.code(201).send({ report: created });
  });

  app.post('/engagements/:id/deletion-confirmation', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        evidenceObjects: z.number().int().nonnegative(),
        credentialSets: z.number().int().nonnegative(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const engagements = await context.database
      .select()
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);
    const record = engagements[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const clients = await context.database
      .select()
      .from(clientTable)
      .where(eq(clientTable.id, record.clientId))
      .limit(1);

    const dateFormat = new Intl.DateTimeFormat('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      timeZone: 'UTC',
    });

    const html = await renderDeletionConfirmationHtml({
      branding: brandingFor(),
      clientLegalName: clients[0]?.legalName ?? 'the client',
      engagementTitle: record.title,
      reportReference: record.reference,
      testStartDate: record.startsAt ? dateFormat.format(record.startsAt) : '',
      testEndDate: record.endsAt ? dateFormat.format(record.endsAt) : '',
      retentionDays: record.evidenceRetentionDays,
      deletionDate: dateFormat.format(new Date()),
      reportDate: dateFormat.format(new Date()),
      testerName: 'Attestor Security',
      testerTitle: 'Principal consultant',
      destroyed: parsed.data,
    });

    const pdf = await renderPdf(html, { format: 'A4' });
    const stored = await context.reports.capture({
      engagementId: id,
      kind: 'file',
      binary: pdf,
      contentType: 'application/pdf',
      filename: `${record.reference}-deletion-confirmation.pdf`,
    });

    const [created] = await context.database
      .insert(reportTable)
      .values({
        engagementId: id,
        kind: 'deletionConfirmation',
        version: '1.0',
        templateId: 'attestor-standard-v1',
        pdfKey: stored.objectKey,
        legalTemplateVersions: { 'evidence-deletion-confirmation': '1.0.0-draft' },
      })
      .returning();

    return reply.code(201).send({ report: created });
  });

  app.get('/reports/:reportId/download', { preHandler: guard }, async (request, reply) => {
    const { reportId } = request.params as { reportId: string };

    const rows = await context.database
      .select()
      .from(reportTable)
      .where(eq(reportTable.id, reportId))
      .limit(1);
    const record = rows[0];
    if (!record?.pdfKey) return reply.code(404).send({ error: 'not found' });

    const source = await context.reports.read(record.pdfKey);
    const watermark = watermarkFor({
      name: 'Attestor staff',
      email: actorIdOf(request),
      organisation: 'Attestor Security',
      at: new Date(),
    });

    await context.database.insert(reportDownload).values({
      reportId,
      staffUserId: actorIdOf(request),
      watermarkText: watermark,
      ...requestContext(request),
    });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'report.downloaded',
      subjectType: 'report',
      subjectId: reportId,
      ...requestContext(request),
    });

    return reply
      .header('Content-Type', 'application/pdf')
      .header('Content-Disposition', `attachment; filename="${record.version}.pdf"`)
      .send(source);
  });

  app.get('/engagements/:id/reports', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const rows = await context.database
      .select()
      .from(reportTable)
      .where(eq(reportTable.engagementId, id))
      .orderBy(desc(reportTable.createdAt));
    return reply.send({ reports: rows });
  });

  app.get('/legal-blocks', { preHandler: guard }, (unusedRequest, reply) =>
    reply.send({
      blocks: LEGAL_BLOCKS.map((block) => ({
        id: block.id,
        title: block.title,
        version: block.version,
        mandatory: block.mandatory,
        lawyerReviewedAt: block.lawyerReviewedAt,
        appearsIn: block.appearsIn,
        // Our own boilerplate, not client data. Shown in the console so the person who has to get
        // it reviewed can read exactly what goes out.
        text: block.text,
      })),
      // The console shows a banner until every mandatory block has been reviewed.
      allReviewed: LEGAL_BLOCKS.filter((block) => block.mandatory).every(
        (block) => block.lawyerReviewedAt !== null,
      ),
    }),
  );
}
