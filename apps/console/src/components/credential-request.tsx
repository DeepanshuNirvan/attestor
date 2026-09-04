'use client';

import { useActionState, useState } from 'react';
import { requestCredentials, type ActionResult } from '@/app/actions';

/**
 * Asking a client for test accounts.
 *
 * You name the accounts you want and what kind of login each is; the client gets a link showing
 * exactly those boxes. Ask for **two accounts per role** you intend to test access control on —
 * comparing what one user can see of another's data is the whole technique, and it cannot be done
 * with one account.
 *
 * The link is shown once. Only its hash is stored and nothing can read it back, so send it yourself
 * through a channel you trust.
 */

export interface CredentialKindOption {
  id: string;
  label: string;
  description: string;
}

const initial: ActionResult = { ok: false };

interface Row {
  label: string;
  roleName: string;
  kind: string;
  isSecondary: boolean;
}

const BLANK: Row = { label: '', roleName: '', kind: 'emailPassword', isSecondary: false };

export function CredentialRequest({
  engagementId,
  kinds,
}: {
  engagementId: string;
  kinds: CredentialKindOption[];
}) {
  const [rows, setRows] = useState<Row[]>([{ ...BLANK, label: 'Standard user', roleName: 'user' }]);
  const [state, action, pending] = useActionState(
    requestCredentials.bind(null, engagementId),
    initial,
  );

  const link = (state.detail as { url?: string; expiresAt?: string } | undefined) ?? {};

  const update = (index: number, patch: Partial<Row>) =>
    setRows((current) => current.map((row, position) => (position === index ? { ...row, ...patch } : row)));

  if (state.ok && link.url) {
    return (
      <div>
        <p className="notice small">
          Send this to your client yourself. It is shown once — nothing can read it back, so a lost
          link means issuing a new one.
        </p>
        <p className="field">
          <code>{link.url}</code>
        </p>
        <p className="small muted">
          Works until{' '}
          {link.expiresAt
            ? new Date(link.expiresAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
            : 'it expires'}
          .
        </p>
      </div>
    );
  }

  return (
    <form action={action}>
      <input type="hidden" name="accounts" value={JSON.stringify(rows)} />

      {rows.map((row, index) => (
        <fieldset className="field" key={index}>
          <div className="field">
            <label htmlFor={`label-${index}`}>What to call it</label>
            <input
              id={`label-${index}`}
              value={row.label}
              onChange={(event) => update(index, { label: event.target.value })}
              placeholder="Standard user"
              required
            />
          </div>

          <div className="field">
            <label htmlFor={`role-${index}`}>Role</label>
            <input
              id={`role-${index}`}
              value={row.roleName}
              onChange={(event) => update(index, { roleName: event.target.value })}
              placeholder="user"
              required
            />
          </div>

          <div className="field">
            <label htmlFor={`kind-${index}`}>How they sign in</label>
            <select
              id={`kind-${index}`}
              value={row.kind}
              onChange={(event) => update(index, { kind: event.target.value })}
            >
              {kinds.map((kind) => (
                <option key={kind.id} value={kind.id}>
                  {kind.label}
                </option>
              ))}
            </select>
            <p className="small muted">
              {kinds.find((kind) => kind.id === row.kind)?.description ?? ''}
            </p>
          </div>

          <div className="field">
            <label htmlFor={`secondary-${index}`}>
              <input
                type="checkbox"
                id={`secondary-${index}`}
                checked={row.isSecondary}
                onChange={(event) => update(index, { isSecondary: event.target.checked })}
              />{' '}
              Second account for this role
            </label>
            <p className="small muted">
              Needed to test whether one user can reach another user&apos;s data.
            </p>
          </div>

          {rows.length > 1 ? (
            <button
              type="button"
              onClick={() => setRows((current) => current.filter((unused, position) => position !== index))}
            >
              Remove
            </button>
          ) : null}
        </fieldset>
      ))}

      <button type="button" onClick={() => setRows((current) => [...current, { ...BLANK }])}>
        Add another account
      </button>

      <div className="field">
        <label htmlFor="expiresInHours">Link works for (hours)</label>
        <input id="expiresInHours" name="expiresInHours" type="number" min={1} max={336} defaultValue={72} />
      </div>

      {state.error ? (
        <p className="notice notice-warning small" role="alert">
          {state.error}
        </p>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Creating…' : 'Create the link'}
      </button>
    </form>
  );
}
