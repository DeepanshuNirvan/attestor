'use client';

import { useState, useTransition } from 'react';
import {
  approveSection,
  draftWithAi,
  generateAttestationLetter,
  generateDeletionConfirmation,
  generateReport,
  releaseReport,
  saveChecklist,
  saveSection,
} from '@/app/actions';
import { formText } from '@/lib/form';

/**
 * Report editing and the release gate.
 *
 * The three manual checklist items are the ones a machine cannot decide. The last of them is
 * deliberately worded as a claim rather than a box: "I have read every line of this report".
 */

export interface SectionRow {
  sectionKey: string;
  markdown: string;
  isAiDraft: boolean;
  approvedAt: string | null;
}

export interface ChecklistResult {
  id: string;
  label: string;
  manual: boolean;
  passed: boolean;
  reason: string | null;
}

export interface ReportRow {
  id: string;
  kind: string;
  version: string;
  releasedAt: string | null;
  createdAt: string;
}

export function ReportWorkbench({
  engagementId,
  sectionOrder,
  sections,
  checklist,
  releasable,
  reports,
}: {
  engagementId: string;
  sectionOrder: { key: string; label: string; help: string }[];
  sections: SectionRow[];
  checklist: ChecklistResult[];
  releasable: boolean;
  reports: ReportRow[];
}) {
  const stored = new Map(sections.map((section) => [section.sectionKey, section]));
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [blocking, setBlocking] = useState<ChecklistResult[]>([]);

  const manual = checklist.filter((item) => item.manual);
  const automated = checklist.filter((item) => !item.manual);

  function onSaveSection(key: string, value: string) {
    startTransition(async () => {
      const result = await saveSection(engagementId, key, value);
      setMessage(result.ok ? `Saved ${key}.` : (result.error ?? 'save failed'));
    });
  }

  function onDraftWithAi(key: string) {
    const instruction = window.prompt(
      'What should it write? It may only state what the findings and evidence already say.',
    );
    if (!instruction) return;

    startTransition(async () => {
      const result = await draftWithAi(engagementId, key, instruction);
      setMessage(
        result.ok
          ? 'Drafted. Read it against the evidence, edit it, then approve it — release is blocked until you do.'
          : (result.error ?? 'the draft was refused'),
      );
    });
  }

  function onApproveSection(key: string, value: string) {
    startTransition(async () => {
      const result = await approveSection(engagementId, key, value);
      setMessage(result.ok ? `Approved ${key}.` : (result.error ?? 'approval failed'));
    });
  }

  function onToggleManual(form: HTMLFormElement) {
    const data = new FormData(form);
    const confirmations: Record<string, boolean> = {};
    for (const item of manual) confirmations[item.id] = data.get(item.id) === 'on';

    startTransition(async () => {
      const result = await saveChecklist(engagementId, confirmations);
      setMessage(result.ok ? 'Checklist saved.' : (result.error ?? 'save failed'));
    });
  }

  function onGenerate(kind: 'assessment' | 'retest') {
    startTransition(async () => {
      const result = await generateReport(engagementId, kind);
      setMessage(result.ok ? 'Report generated.' : (result.error ?? 'generation failed'));
    });
  }

  function onAttestation() {
    startTransition(async () => {
      const result = await generateAttestationLetter(engagementId);
      setMessage(result.ok ? 'Attestation letter generated.' : (result.error ?? 'generation failed'));
    });
  }

  /**
   * The deletion confirmation states counts, so it asks for them rather than inventing them. They
   * are what the retention worker actually destroyed; a letter that says "all data" without a
   * number says nothing a client can check.
   */
  function onDeletionConfirmation() {
    const evidence = window.prompt('How many evidence objects were destroyed?');
    if (evidence === null) return;
    const credentials = window.prompt('How many credential sets were shredded?');
    if (credentials === null) return;

    const evidenceObjects = Number(evidence);
    const credentialSets = Number(credentials);
    if (!Number.isInteger(evidenceObjects) || !Number.isInteger(credentialSets)) {
      setMessage('both counts have to be whole numbers');
      return;
    }

    startTransition(async () => {
      const result = await generateDeletionConfirmation(
        engagementId,
        evidenceObjects,
        credentialSets,
      );
      setMessage(result.ok ? 'Deletion confirmation generated.' : (result.error ?? 'generation failed'));
    });
  }

  function onRelease(reportId: string) {
    const recipients = window.prompt('Recipient email addresses, comma separated');
    if (!recipients) return;

    startTransition(async () => {
      const result = await releaseReport(
        engagementId,
        reportId,
        recipients.split(',').map((value) => value.trim()).filter(Boolean),
      );
      if (result.ok) {
        setMessage('Released in the portal. No email has been sent.');
        setBlocking([]);
        return;
      }
      const detail = result.detail as { blocking?: ChecklistResult[]; awaitingHuman?: ChecklistResult[] } | undefined;
      setBlocking([...(detail?.blocking ?? []), ...(detail?.awaitingHuman ?? [])]);
      setMessage(result.error ?? 'release refused');
    });
  }

  return (
    <div className="columns" style={{ gridTemplateColumns: 'minmax(0, 2fr) minmax(18rem, 1fr)' }}>
      <div className="stack">
        {sectionOrder.map((section) => {
          const record = stored.get(section.key);
          return (
            <section className="panel" key={section.key}>
              <h3>
                {section.label}
                {record?.isAiDraft ? (
                  <span className="tag" style={{ marginLeft: '0.5rem' }}>
                    AI draft — approve before release
                  </span>
                ) : null}
              </h3>
              {section.help ? <p className="small muted">{section.help}</p> : null}
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  onSaveSection(section.key, formText(new FormData(event.currentTarget), 'markdown'));
                }}
              >
                <textarea
                  name="markdown"
                  defaultValue={record?.markdown ?? ''}
                  rows={section.key.startsWith('roadmap') ? 5 : 8}
                />
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                  <button type="submit" disabled={pending}>
                    Save
                  </button>
                  {record?.isAiDraft ? (
                    <button
                      type="button"
                      className="button-quiet"
                      disabled={pending}
                      onClick={(event) => {
                        const form = event.currentTarget.closest('form');
                        const field = form?.elements.namedItem('markdown');
                        onApproveSection(
                          section.key,
                          field instanceof HTMLTextAreaElement ? field.value : '',
                        );
                      }}
                    >
                      Approve this draft
                    </button>
                  ) : null}
                  {section.key === 'executiveSummary' ? (
                    <button
                      type="button"
                      className="button-quiet"
                      disabled={pending}
                      onClick={() => onDraftWithAi(section.key)}
                    >
                      Draft with AI
                    </button>
                  ) : null}
                </div>
              </form>
            </section>
          );
        })}
      </div>

      <div className="stack">
        <section className="panel">
          <h3>Pre-release checklist</h3>
          {message ? (
            <p className="notice small" role="status">
              {message}
            </p>
          ) : null}

          <table>
            <tbody>
              {automated.map((item) => (
                <tr key={item.id}>
                  <td style={{ width: '1.5rem' }}>{item.passed ? '✓' : '✗'}</td>
                  <td>
                    {item.label}
                    {item.reason ? <div className="small muted">{item.reason}</div> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <form
            onSubmit={(event) => {
              event.preventDefault();
              onToggleManual(event.currentTarget);
            }}
            style={{ marginTop: '1rem' }}
          >
            {manual.map((item) => (
              <label
                key={item.id}
                style={{ fontWeight: 400, display: 'flex', gap: '0.4rem', marginBottom: '0.4rem' }}
              >
                <input
                  type="checkbox"
                  name={item.id}
                  defaultChecked={item.passed}
                  style={{ width: 'auto' }}
                />
                {item.label}
              </label>
            ))}
            <button type="submit" className="button-quiet" disabled={pending}>
              Save confirmations
            </button>
          </form>
        </section>

        {blocking.length > 0 ? (
          <section className="panel notice-danger">
            <h3>Release refused</h3>
            <ul className="small">
              {blocking.map((item) => (
                <li key={item.id}>
                  {item.label}
                  {item.reason ? ` — ${item.reason}` : ''}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <section className="panel">
          <h3>Documents</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <button type="button" onClick={() => onGenerate('assessment')} disabled={pending}>
              {pending ? 'Working…' : 'Generate assessment report'}
            </button>
            <button
              type="button"
              className="button-quiet"
              onClick={() => onGenerate('retest')}
              disabled={pending}
            >
              Generate retest report
            </button>
            <button
              type="button"
              className="button-quiet"
              onClick={onAttestation}
              disabled={pending}
            >
              Generate attestation letter
            </button>
            <button
              type="button"
              className="button-quiet"
              onClick={onDeletionConfirmation}
              disabled={pending}
            >
              Generate deletion confirmation
            </button>
          </div>

          {reports.length === 0 ? (
            <p className="small muted" style={{ marginTop: '0.75rem' }}>
              Nothing generated yet.
            </p>
          ) : (
            <table style={{ marginTop: '0.75rem' }}>
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Version</th>
                  <th>Released</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => (
                  <tr key={report.id}>
                    <td className="small">{report.kind}</td>
                    <td className="mono small">{report.version}</td>
                    <td className="small muted">{report.releasedAt ? 'Yes' : 'No'}</td>
                    <td>
                      {report.releasedAt ? null : (
                        <button
                          type="button"
                          className="button-quiet"
                          disabled={pending || !releasable}
                          onClick={() => onRelease(report.id)}
                        >
                          Release
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <p className="small muted" style={{ marginTop: '0.75rem' }}>
            Releasing publishes the report in the client portal. Nothing is emailed: the
            client-facing notification is queued for a person to review and send.
          </p>
        </section>
      </div>
    </div>
  );
}
