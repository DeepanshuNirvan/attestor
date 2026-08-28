'use client';

import { useState, useTransition } from 'react';
import {
  inviteClientUser,
  recordDpa,
  revokeInvitation,
  setRetainerActive,
} from '@/app/actions';
import { formText } from '@/lib/form';

/**
 * Portal access and retainers for one client.
 *
 * The invitation link is displayed once, here, and then it is gone: the API stores only a hash and
 * has no endpoint that reads a token back. Sending it is a person's job, through a channel they
 * choose — the platform sends nothing to a client on its own.
 */

const ROLE_LABEL: Record<string, string> = {
  clientOwner: 'Owner',
  clientMember: 'Member',
  clientViewer: 'Read-only',
};

function formatDate(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export function ClientControls({
  clientId,
  dpaSignedAt,
  users,
  invitations,
  retainers,
}: {
  clientId: string;
  dpaSignedAt: string | null;
  users: {
    id: string;
    email: string;
    name: string;
    role: string;
    activatedAt: string | null;
    deactivatedAt: string | null;
    totpEnrolledAt: string | null;
  }[];
  invitations: {
    id: string;
    email: string;
    role: string;
    expiresAt: string;
    acceptedAt: string | null;
  }[];
  retainers: {
    id: string;
    cadence: string;
    modules: string[];
    nextRunAt: string | null;
    lastRunAt: string | null;
    active: boolean;
  }[];
}) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [issuedLink, setIssuedLink] = useState<string | null>(null);

  const pendingInvitations = invitations.filter((invitation) => !invitation.acceptedAt);

  return (
    <div className="columns" style={{ gridTemplateColumns: 'minmax(0, 3fr) minmax(18rem, 2fr)' }}>
      <div className="stack">
        <section className="panel">
          <h2>Portal access</h2>
          {message ? (
            <p className="notice small" role="status">
              {message}
            </p>
          ) : null}

          {issuedLink ? (
            <div className="notice notice-warning">
              <p>
                <strong>Copy this link now.</strong> It is shown once and expires in seven days.
                Nothing has been emailed — send it yourself.
              </p>
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{issuedLink}</pre>
              <button type="button" className="button-quiet" onClick={() => setIssuedLink(null)}>
                I have copied it
              </button>
            </div>
          ) : null}

          {users.length === 0 ? (
            <p className="muted small">Nobody has portal access yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Two-factor</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.name}</td>
                    <td className="mono small">{user.email}</td>
                    <td className="small">{ROLE_LABEL[user.role] ?? user.role}</td>
                    <td className="small">{user.totpEnrolledAt ? 'Enrolled' : 'Not enrolled'}</td>
                    <td className="small muted">
                      {user.deactivatedAt
                        ? 'Deactivated'
                        : user.activatedAt
                          ? 'Active'
                          : 'Invited, not accepted'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {pendingInvitations.length > 0 ? (
            <>
              <h3>Outstanding invitations</h3>
              <table>
                <tbody>
                  {pendingInvitations.map((invitation) => (
                    <tr key={invitation.id}>
                      <td className="mono small">{invitation.email}</td>
                      <td className="small">{ROLE_LABEL[invitation.role] ?? invitation.role}</td>
                      <td className="small muted">expires {formatDate(invitation.expiresAt)}</td>
                      <td>
                        <button
                          type="button"
                          className="button-quiet"
                          disabled={pending}
                          onClick={() => {
                            startTransition(async () => {
                              const result = await revokeInvitation(clientId, invitation.id);
                              setMessage(
                                result.ok ? 'Invitation revoked.' : (result.error ?? 'that did not work'),
                              );
                            });
                          }}
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : null}
        </section>

        <section className="panel">
          <h2>Retainers</h2>
          {retainers.length === 0 ? (
            <p className="muted small">None configured.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Cadence</th>
                  <th>Modules</th>
                  <th>Next</th>
                  <th>Last</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {retainers.map((retainer) => (
                  <tr key={retainer.id}>
                    <td className="small">{retainer.cadence}</td>
                    <td className="small">{retainer.modules.join(', ')}</td>
                    <td className="small muted">{formatDate(retainer.nextRunAt)}</td>
                    <td className="small muted">{formatDate(retainer.lastRunAt)}</td>
                    <td>
                      <button
                        type="button"
                        className="button-quiet"
                        disabled={pending}
                        onClick={() => {
                          startTransition(async () => {
                            const result = await setRetainerActive(
                              clientId,
                              retainer.id,
                              !retainer.active,
                            );
                            setMessage(
                              result.ok
                                ? retainer.active
                                  ? 'Paused.'
                                  : 'Resumed.'
                                : (result.error ?? 'that did not work'),
                            );
                          });
                        }}
                      >
                        {retainer.active ? 'Pause' : 'Resume'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="small muted">
            A retainer creates a draft engagement at the due date. It does not start one: somebody
            still has to confirm the authorisation is current.
          </p>
        </section>
      </div>

      <div className="stack">
        <section className="panel">
          <h3>Invite someone to the portal</h3>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const data = new FormData(form);

              startTransition(async () => {
                const result = await inviteClientUser(
                  clientId,
                  formText(data, 'email'),
                  formText(data, 'role', 'clientMember'),
                );
                if (result.ok) {
                  const detail = result.detail as { acceptUrl?: string } | undefined;
                  setIssuedLink(detail?.acceptUrl ?? null);
                  setMessage('Invitation created.');
                  form.reset();
                  return;
                }
                setMessage(result.error ?? 'that did not work');
              });
            }}
          >
            <div className="field">
              <label htmlFor="invite-email">Email</label>
              <input id="invite-email" name="email" type="email" required maxLength={320} />
              <p className="small muted">
                They give their own name when they accept, so there is nothing to correct later.
              </p>
            </div>
            <div className="field">
              <label htmlFor="invite-role">Role</label>
              <select id="invite-role" name="role" defaultValue="clientMember">
                <option value="clientOwner">Owner — can manage their own team</option>
                <option value="clientMember">Member — can act on findings</option>
                <option value="clientViewer">Read-only — cannot download reports</option>
              </select>
            </div>
            <button type="submit" disabled={pending}>
              {pending ? 'Creating…' : 'Create invitation'}
            </button>
          </form>
        </section>

        <section className="panel">
          <h3>Data processing agreement</h3>
          {dpaSignedAt ? (
            <p className="small">Signed {formatDate(dpaSignedAt)}.</p>
          ) : (
            <>
              <p className="small muted">
                Record this once the signed agreement is on file. It is a record of a thing that
                happened elsewhere, not a signature captured here.
              </p>
              <button
                type="button"
                className="button-quiet"
                disabled={pending}
                onClick={() => {
                  startTransition(async () => {
                    const result = await recordDpa(clientId);
                    setMessage(result.ok ? 'Recorded.' : (result.error ?? 'that did not work'));
                  });
                }}
              >
                Record as signed
              </button>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
