'use client';

import { useActionState, useState } from 'react';
import {
  OWASP_RISK_FACTORS,
  owaspRiskRating,
  type RiskFactor,
} from '@attestor/findings';
import { saveRiskRating, type ActionResult } from '@/app/actions';

/**
 * The OWASP risk rating form.
 *
 * Sixteen questions about this client rather than about the class of flaw, which is the half CVSS
 * cannot answer. The rating recalculates as the tester answers, because the useful part is watching
 * which factor moves the number — that is the conversation the client will want to have.
 *
 * The factor list comes from the methodology module rather than being retyped here, so the form and
 * the calculator cannot drift apart, and a score that is not a published option cannot be submitted.
 */

const GROUP_LABELS: Record<RiskFactor['group'], string> = {
  threatAgent: 'Threat agent factors',
  vulnerability: 'Vulnerability factors',
  technicalImpact: 'Technical impact factors',
  businessImpact: 'Business impact factors',
};

const GROUP_ORDER: RiskFactor['group'][] = [
  'threatAgent',
  'vulnerability',
  'technicalImpact',
  'businessImpact',
];

const SEVERITY_LABEL: Record<string, string> = {
  note: 'Note',
  low: 'Low',
  moderate: 'Moderate',
  high: 'High',
  critical: 'Critical',
};

const initial: ActionResult = { ok: false };

export function RiskRating({
  engagementId,
  findingId,
  saved,
}: {
  engagementId: string;
  findingId: string;
  saved: Record<string, number> | null;
}) {
  const [state, action, pending] = useActionState(
    saveRiskRating.bind(null, engagementId, findingId),
    initial,
  );
  const [scores, setScores] = useState<Record<string, number>>(saved ?? {});

  const answered = Object.keys(scores).length;
  const rating = owaspRiskRating(scores);

  return (
    <form action={action}>
      <p className="small muted">
        Scored against the OWASP Risk Rating Methodology. Every option below is one the method
        publishes, so a client can check the arithmetic against their own copy of the sheet. An
        unanswered factor is left out of its average rather than counted as zero — a half-filled
        form must not argue the risk is lower than anyone has established.
      </p>

      {GROUP_ORDER.map((group) => (
        <fieldset key={group} style={{ border: 0, padding: 0, margin: '0 0 1.25rem' }}>
          <legend className="small">
            <strong>{GROUP_LABELS[group]}</strong>
          </legend>
          {OWASP_RISK_FACTORS.filter((factor) => factor.group === group).map((factor) => (
            <div className="field" key={factor.id}>
              <label htmlFor={factor.id}>{factor.label}</label>
              <select
                id={factor.id}
                name={factor.id}
                defaultValue={saved?.[factor.id] ?? ''}
                onChange={(event) => {
                  const raw = event.target.value;
                  setScores((current) => {
                    const next = { ...current };
                    if (raw === '') delete next[factor.id];
                    else next[factor.id] = Number(raw);
                    return next;
                  });
                }}
              >
                <option value="">Not scored</option>
                {factor.options.map((option) => (
                  <option key={`${option.label}-${option.score}`} value={option.score}>
                    {option.label} [{option.score}]
                  </option>
                ))}
              </select>
            </div>
          ))}
        </fieldset>
      ))}

      <div className="panel" style={{ marginBottom: '1rem' }}>
        <p className="small">
          Likelihood <strong>{rating.likelihood.toFixed(2)}</strong> ({rating.likelihoodLevel}) ·
          impact <strong>{rating.impact.toFixed(2)}</strong> ({rating.impactLevel}) ·{' '}
          <strong>{SEVERITY_LABEL[rating.severity] ?? rating.severity}</strong>
        </p>
        <p className="small muted">
          {answered} of {OWASP_RISK_FACTORS.length} factors answered.
          {answered < OWASP_RISK_FACTORS.length
            ? ' The rating is provisional until all sixteen are.'
            : ''}
        </p>
      </div>

      {state.error ? <p className="small error">{state.error}</p> : null}
      {state.ok ? <p className="small">Saved.</p> : null}

      <button className="button" type="submit" disabled={pending || answered === 0}>
        {pending ? 'Saving…' : 'Save risk rating'}
      </button>
    </form>
  );
}
