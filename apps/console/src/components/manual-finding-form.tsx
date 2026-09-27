'use client';

import { useActionState } from 'react';
import { recordManualFinding, type ActionResult } from '@/app/actions';

/**
 * Recording a finding a tester found by hand, such as one user reading another's records. The minimum
 * lengths match what the API and the release checklist will accept, so a short field fails here
 * rather than at release.
 */

const initial: ActionResult = { ok: false };

export function ManualFindingForm({ engagementId }: { engagementId: string }) {
  const [state, action, pending] = useActionState(
    recordManualFinding.bind(null, engagementId),
    initial,
  );

  return (
    <form action={action}>
      <div className="field">
        <label htmlFor="title">Title</label>
        <input id="title" name="title" required minLength={5} maxLength={300} />
        <p className="small muted">What is wrong, in one line. For example: Any user can read other users' invoices.</p>
      </div>

      <div className="field">
        <label htmlFor="severity">Severity</label>
        <select id="severity" name="severity" defaultValue="medium">
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Informational</option>
        </select>
      </div>

      <div className="field">
        <label htmlFor="cvssVector">CVSS vector (optional)</label>
        <input id="cvssVector" name="cvssVector" placeholder="CVSS:4.0/AV:N/AC:L/…" />
        <p className="small muted">Leave blank to use a standard vector for the severity you chose.</p>
      </div>

      <div className="field">
        <label htmlFor="url">Affected URL</label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <select name="method" defaultValue="GET" style={{ width: 'auto' }} aria-label="Method">
            <option>GET</option>
            <option>POST</option>
            <option>PUT</option>
            <option>PATCH</option>
            <option>DELETE</option>
          </select>
          <input id="url" name="url" required placeholder="http://192.168.29.249:8080/api/v1/users/2" />
        </div>
      </div>

      <div className="field">
        <label htmlFor="description">What you found</label>
        <textarea id="description" name="description" rows={4} required minLength={20} />
      </div>

      <div className="field">
        <label htmlFor="businessImpact">Business impact</label>
        <textarea id="businessImpact" name="businessImpact" rows={3} required minLength={41} />
        <p className="small muted">What it means for the client's business, in plain words.</p>
      </div>

      <div className="field">
        <label htmlFor="reproductionSteps">Reproduction steps</label>
        <textarea id="reproductionSteps" name="reproductionSteps" rows={5} required />
        <p className="small muted">One step per line, at least two.</p>
      </div>

      <div className="field">
        <label htmlFor="remediation">Remediation</label>
        <textarea id="remediation" name="remediation" rows={3} required minLength={41} />
        <p className="small muted">The specific fix for this application.</p>
      </div>

      <div className="field">
        <label htmlFor="evidence">Evidence</label>
        <textarea
          id="evidence"
          name="evidence"
          rows={8}
          placeholder={'The request you sent and the response that proves it.\nPersonal data is masked when it is stored.'}
        />
      </div>

      <div className="field">
        <label htmlFor="screenshot">Screenshot (optional)</label>
        <input id="screenshot" name="screenshot" type="file" accept="image/png,image/jpeg" />
      </div>

      {state.error ? (
        <p className="notice notice-danger" role="alert">
          {state.error}
        </p>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Saving…' : 'Save as a candidate'}
      </button>
      <p className="small muted">It then appears in Triage. Confirm it there and it goes into the report.</p>
    </form>
  );
}
