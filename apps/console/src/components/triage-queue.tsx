'use client';

import { useCallback, useEffect, useState, useTransition } from 'react';
import { confirmFindings, discardFindings, markFalsePositive } from '@/app/actions';
import { Severity } from '@/components/shell';

/**
 * Keyboard-driven triage.
 *
 * A tester working through two hundred candidates one modal at a time stops doing it properly
 * somewhere around candidate forty. So: arrow keys move, space selects, c confirms, d discards, f
 * marks a false positive with a reason, and the selection survives the action.
 */

export interface Candidate {
  id: string;
  title: string;
  severity: string;
  toolName: string | null;
  checkId: string | null;
  affectedAssets: { value: string; location?: string; parameter?: string; method?: string }[];
  firstSeenAt: string;
  attackSuccessRate: number | null;
}

const SHORTCUTS: { key: string; label: string }[] = [
  { key: '↑ ↓', label: 'move' },
  { key: 'space', label: 'select' },
  { key: 'a', label: 'select all' },
  { key: 'c', label: 'confirm' },
  { key: 'd', label: 'discard' },
  { key: 'f', label: 'false positive' },
  { key: 'esc', label: 'clear selection' },
];

export function TriageQueue({
  engagementId,
  candidates,
}: {
  engagementId: string;
  candidates: Candidate[];
}) {
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const targets = useCallback((): string[] => {
    if (selected.size > 0) return [...selected];
    const current = candidates[cursor];
    return current ? [current.id] : [];
  }, [candidates, cursor, selected]);

  const runAction = useCallback(
    (action: 'confirm' | 'discard' | 'falsePositive') => {
      const ids = targets();
      if (ids.length === 0) return;

      if (action === 'falsePositive') {
        // A false positive is remembered against the client for every future run, so the reason is
        // not optional — somebody reading the suppression in six months needs to know why.
        const reason = window.prompt(
          'Why is this a false positive? Recorded against the client and suppressed in future runs.',
        );
        if (!reason || reason.trim().length < 10) {
          setMessage('A false positive needs a written reason of at least ten characters.');
          return;
        }
        startTransition(async () => {
          for (const id of ids) {
            const result = await markFalsePositive(engagementId, id, reason);
            if (!result.ok) setMessage(result.error ?? 'that did not work');
          }
          setSelected(new Set());
          setMessage(`Marked ${ids.length} as false positive.`);
        });
        return;
      }

      startTransition(async () => {
        const result =
          action === 'confirm'
            ? await confirmFindings(engagementId, ids)
            : await discardFindings(engagementId, ids);
        if (!result.ok) {
          setMessage(result.error ?? 'that did not work');
          return;
        }
        setSelected(new Set());
        setMessage(`${action === 'confirm' ? 'Confirmed' : 'Discarded'} ${ids.length}.`);
      });
    },
    [engagementId, targets],
  );

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return;

      switch (event.key) {
        case 'ArrowDown':
        case 'j':
          event.preventDefault();
          setCursor((value) => Math.min(candidates.length - 1, value + 1));
          break;
        case 'ArrowUp':
        case 'k':
          event.preventDefault();
          setCursor((value) => Math.max(0, value - 1));
          break;
        case ' ': {
          event.preventDefault();
          const current = candidates[cursor];
          if (!current) break;
          setSelected((previous) => {
            const next = new Set(previous);
            if (next.has(current.id)) next.delete(current.id);
            else next.add(current.id);
            return next;
          });
          break;
        }
        case 'a':
          event.preventDefault();
          setSelected(new Set(candidates.map((candidate) => candidate.id)));
          break;
        case 'Escape':
          setSelected(new Set());
          break;
        case 'c':
          event.preventDefault();
          runAction('confirm');
          break;
        case 'd':
          event.preventDefault();
          runAction('discard');
          break;
        case 'f':
          event.preventDefault();
          runAction('falsePositive');
          break;
        default:
          break;
      }
    }

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [candidates, cursor, runAction]);

  return (
    <div>
      <div className="panel" style={{ marginBottom: '1rem' }}>
        <p className="small">
          {SHORTCUTS.map((shortcut) => (
            <span key={shortcut.key} style={{ marginRight: '1rem' }}>
              <kbd>{shortcut.key}</kbd> {shortcut.label}
            </span>
          ))}
        </p>
        <p className="small muted">
          {selected.size > 0
            ? `${selected.size} selected. Actions apply to the selection.`
            : 'Nothing selected. Actions apply to the highlighted row.'}
        </p>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button type="button" onClick={() => runAction('confirm')} disabled={pending}>
            Confirm
          </button>
          <button
            type="button"
            className="button-quiet"
            onClick={() => runAction('discard')}
            disabled={pending}
          >
            Discard
          </button>
          <button
            type="button"
            className="button-quiet"
            onClick={() => runAction('falsePositive')}
            disabled={pending}
          >
            False positive
          </button>
        </div>
        {message ? (
          <p className="notice small" role="status" style={{ marginTop: '0.75rem' }}>
            {message}
          </p>
        ) : null}
      </div>

      <div className="panel">
        <table>
          <thead>
            <tr>
              <th style={{ width: '2rem' }} />
              <th>Severity</th>
              <th>Finding</th>
              <th>Asset</th>
              <th>Tool</th>
              <th>Check</th>
              <th className="numeric">Success</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((candidate, index) => {
              const asset = candidate.affectedAssets[0];
              return (
                <tr
                  key={candidate.id}
                  data-selected={selected.has(candidate.id)}
                  style={
                    index === cursor
                      ? { outline: '2px solid var(--accent)', outlineOffset: '-2px' }
                      : undefined
                  }
                  onClick={() => setCursor(index)}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(candidate.id)}
                      onChange={() =>
                        setSelected((previous) => {
                          const next = new Set(previous);
                          if (next.has(candidate.id)) next.delete(candidate.id);
                          else next.add(candidate.id);
                          return next;
                        })
                      }
                      style={{ width: 'auto' }}
                      aria-label={`Select ${candidate.title}`}
                    />
                  </td>
                  <td>
                    <Severity value={candidate.severity} />
                  </td>
                  <td>{candidate.title}</td>
                  <td className="mono small">
                    {asset ? `${asset.value}${asset.location ?? ''}` : '—'}
                    {asset?.parameter ? ` (${asset.parameter})` : ''}
                  </td>
                  <td className="small muted">{candidate.toolName ?? 'manual'}</td>
                  <td className="small muted">{candidate.checkId ?? '—'}</td>
                  <td className="numeric small">
                    {candidate.attackSuccessRate === null
                      ? '—'
                      : `${Math.round(candidate.attackSuccessRate * 100)}%`}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
