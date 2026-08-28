'use client';

import { useActionState, useState, useTransition } from 'react';
import {
  acceptPortalTerms,
  changePortalPassword,
  deactivateTeamMember,
  signOutEverywhere,
  type ActionResult,
} from '@/app/actions';

/**
 * Account controls: the password, the terms, and ending sessions.
 *
 * The password form never sends the value anywhere but the API, and the API revokes every session
 * when it changes — including this one, which is why the action redirects to the sign-in page
 * rather than returning here.
 */

const ROLE_LABEL: Record<string, string> = {
  clientOwner: 'Owner',
  clientMember: 'Member',
  clientViewer: 'Read-only',
};

export function AccountControls({
  termsAcceptanceRequired,
  termsText,
}: {
  termsAcceptanceRequired: boolean;
  termsText: string | null;
}) {
  const [state, action, pending] = useActionState<ActionResult, FormData>(changePortalPassword, {
    ok: false,
  });
  const [termsPending, startTermsTransition] = useTransition();
  const [termsMessage, setTermsMessage] = useState<string | null>(null);

  return (
    <div className="stack">
      <section className="panel">
        <h2>Change your password</h2>
        <p className="small muted">
          Changing it signs you out of every device, including this one.
        </p>
        <form action={action}>
          <div className="field">
            <label htmlFor="current">Current password</label>
            <input
              id="current"
              name="current"
              type="password"
              autoComplete="current-password"
              required
            />
          </div>
          <div className="field">
            <label htmlFor="next">New password</label>
            <input
              id="next"
              name="next"
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
            />
            <p className="small muted">
              At least twelve characters. Length beats complexity; a passphrase is fine.
            </p>
          </div>
          <div className="field">
            <label htmlFor="confirm">New password again</label>
            <input
              id="confirm"
              name="confirm"
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
            />
          </div>
          {state.error ? (
            <p className="notice notice-danger small" role="alert">
              {state.error}
            </p>
          ) : null}
          <button type="submit" disabled={pending}>
            {pending ? 'Changing…' : 'Change password'}
          </button>
        </form>
      </section>

      {termsAcceptanceRequired ? (
        <section className="panel">
          <h2>Terms of access</h2>
          <pre style={{ maxHeight: '18rem', overflow: 'auto' }}>{termsText ?? ''}</pre>
          {termsMessage ? (
            <p className="notice small" role="status">
              {termsMessage}
            </p>
          ) : null}
          <button
            type="button"
            disabled={termsPending}
            onClick={() => {
              startTermsTransition(async () => {
                const result = await acceptPortalTerms();
                setTermsMessage(result.ok ? 'Accepted, thank you.' : (result.error ?? 'that did not work'));
              });
            }}
          >
            {termsPending ? 'Recording…' : 'I accept these terms'}
          </button>
        </section>
      ) : null}

      <section className="panel">
        <h2>Sessions</h2>
        <p className="small muted">
          If you have signed in somewhere you no longer control, end every session now. You will
          need to sign in again.
        </p>
        <form action={signOutEverywhere}>
          <button type="submit" className="button-quiet">
            Sign out everywhere
          </button>
        </form>
      </section>
    </div>
  );
}

export function TeamTable({
  members,
  currentUserId,
}: {
  members: {
    id: string;
    email: string;
    name: string;
    role: string;
    activatedAt: string | null;
    deactivatedAt: string | null;
    lastLoginAt: string | null;
  }[];
  currentUserId: string;
}) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);

  if (members.length === 0) return <p className="muted small">Only you.</p>;

  return (
    <>
      {message ? (
        <p className="notice small" role="status">
          {message}
        </p>
      ) : null}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>Last signed in</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {members.map((member) => (
            <tr key={member.id}>
              <td>{member.name}</td>
              <td className="mono small">{member.email}</td>
              <td className="small">{ROLE_LABEL[member.role] ?? member.role}</td>
              <td className="small muted">
                {member.deactivatedAt
                  ? 'Deactivated'
                  : member.lastLoginAt
                    ? new Intl.DateTimeFormat('en-GB', {
                        day: 'numeric',
                        month: 'short',
                        year: 'numeric',
                        timeZone: 'UTC',
                      }).format(new Date(member.lastLoginAt))
                    : 'Never'}
              </td>
              <td>
                {member.deactivatedAt || member.id === currentUserId ? null : (
                  <button
                    type="button"
                    className="button-quiet"
                    disabled={pending}
                    onClick={() => {
                      if (
                        !window.confirm(
                          `Deactivate ${member.email}? Their sessions end immediately and they lose access to every report.`,
                        )
                      ) {
                        return;
                      }
                      startTransition(async () => {
                        const result = await deactivateTeamMember(member.id);
                        setMessage(
                          result.ok
                            ? `${member.email} no longer has access.`
                            : (result.error ?? 'that did not work'),
                        );
                      });
                    }}
                  >
                    Deactivate
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
