'use client';

import { useActionState } from 'react';
import { recordAuthorisation, type ActionResult } from '@/app/actions';

/**
 * Recording a signed authorisation.
 *
 * The asset list is pre-filled from the scope, but it is the list written in the signed document
 * that belongs here. After saving, the difference between the two is shown — that comparison is the
 * cheapest protection there is against testing something nobody signed for.
 */
export function AuthorisationForm({
  engagementId,
  includedScope,
  excludedScope,
}: {
  engagementId: string;
  includedScope: string[];
  excludedScope: string[];
}) {
  const [state, action, pending] = useActionState<ActionResult, FormData>(
    recordAuthorisation.bind(null, engagementId),
    { ok: false },
  );

  const diff = (state.detail as { diff?: { inDocumentNotEntered: string[]; enteredNotInDocument: string[] } } | undefined)
    ?.diff;

  if (state.ok) {
    const clean = diff && diff.inDocumentNotEntered.length === 0 && diff.enteredNotInDocument.length === 0;
    return (
      <div className={`notice ${clean ? '' : 'notice-danger'} small`} role="status">
        <p>
          <strong>Authorisation recorded.</strong>{' '}
          {clean
            ? 'The signed asset list matches the scope exactly.'
            : 'The signed document and the scope do not match. Fix the scope, or get a corrected form signed, before running anything.'}
        </p>
        {!clean && diff ? (
          <ul>
            {diff.inDocumentNotEntered.map((value) => (
              <li key={`d-${value}`}>In the signed document but not in the scope: <code>{value}</code></li>
            ))}
            {diff.enteredNotInDocument.map((value) => (
              <li key={`s-${value}`}>In the scope but not signed for: <code>{value}</code></li>
            ))}
          </ul>
        ) : null}
      </div>
    );
  }

  return (
    <form action={action}>
      <div className="field">
        <label htmlFor="document">Signed authorisation (PDF)</label>
        <input id="document" name="document" type="file" accept="application/pdf" required />
        <p className="small muted">Stored with the engagement and fingerprinted, so the report can prove which document was signed.</p>
      </div>

      <div className="columns">
        <div className="field">
          <label htmlFor="signedBy">Signed by</label>
          <input id="signedBy" name="signedBy" required minLength={2} />
        </div>
        <div className="field">
          <label htmlFor="signerRole">Their role</label>
          <input id="signerRole" name="signerRole" required minLength={2} placeholder="Chief Technology Officer" />
        </div>
      </div>

      <div className="columns">
        <div className="field">
          <label htmlFor="signerEmail">Their email</label>
          <input id="signerEmail" name="signerEmail" type="email" required />
        </div>
        <div className="field">
          <label htmlFor="signedAt">Date signed</label>
          <input id="signedAt" name="signedAt" type="date" required />
        </div>
      </div>

      <div className="columns">
        <div className="field">
          <label htmlFor="validFrom">Testing allowed from</label>
          <input id="validFrom" name="validFrom" type="date" required />
        </div>
        <div className="field">
          <label htmlFor="validUntil">Testing allowed until</label>
          <input id="validUntil" name="validUntil" type="date" required />
        </div>
      </div>

      <div className="field">
        <label htmlFor="assetList">Assets, exactly as written in the signed document (one per line)</label>
        <textarea id="assetList" name="assetList" rows={4} required defaultValue={includedScope.join('\n')} />
      </div>

      <div className="field">
        <label htmlFor="exclusionList">Exclusions in the document (one per line)</label>
        <textarea id="exclusionList" name="exclusionList" rows={2} defaultValue={excludedScope.join('\n')} />
      </div>

      <div className="field">
        <label htmlFor="sourceAddresses">Your testing IP addresses named on the form (one per line)</label>
        <textarea id="sourceAddresses" name="sourceAddresses" rows={2} />
      </div>

      <p className="small">
        <strong>Emergency contact during testing</strong>
      </p>
        <div className="columns">
          <div className="field">
            <label htmlFor="emergencyName">Name</label>
            <input id="emergencyName" name="emergencyName" required />
          </div>
          <div className="field">
            <label htmlFor="emergencyRole">Role</label>
            <input id="emergencyRole" name="emergencyRole" required />
          </div>
        </div>
        <div className="columns">
          <div className="field">
            <label htmlFor="emergencyPhone">Mobile</label>
            <input id="emergencyPhone" name="emergencyPhone" type="tel" required minLength={5} />
          </div>
          <div className="field">
            <label htmlFor="emergencyEmail">Email</label>
            <input id="emergencyEmail" name="emergencyEmail" type="email" required />
          </div>
        </div>

      <div className="field">
        <label htmlFor="criticalNotificationHours">Notify a critical finding within (hours)</label>
        <input id="criticalNotificationHours" name="criticalNotificationHours" type="number" min={1} max={168} defaultValue={24} />
      </div>

      {state.error ? (
        <p className="notice notice-danger small" role="alert">
          {state.error}
        </p>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Saving…' : 'Record authorisation'}
      </button>
    </form>
  );
}
