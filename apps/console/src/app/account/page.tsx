import { redirect } from 'next/navigation';
import { Notice, PageHeader, Shell } from '@/components/shell';
import { AccountControls, TeamTable } from '@/components/account-controls';
import { tryGet } from '@/lib/api';

/**
 * The client's own account: who they are, who else on their team has access, and the controls that
 * end that access.
 *
 * Everything destructive here is deliberately dull and immediate. Deactivating a colleague revokes
 * their sessions in the same transaction, so "removed" means removed now, not at the next expiry.
 */

interface Account {
  id: string;
  email: string;
  name: string;
  role: string;
  totpEnrolledAt: string | null;
  portalTermsVersion: string | null;
}

interface TeamMember {
  id: string;
  email: string;
  name: string;
  role: string;
  activatedAt: string | null;
  deactivatedAt: string | null;
  lastLoginAt: string | null;
}

const ROLE_LABEL: Record<string, string> = {
  clientOwner: 'Owner',
  clientMember: 'Member',
  clientViewer: 'Read-only',
};

export default async function AccountPage() {
  const data = await tryGet<{ account: Account | undefined; termsAcceptanceRequired: boolean }>(
    '/account',
  );
  if (!data) redirect('/login');
  if (!data.account) redirect('/login');

  const isOwner = data.account.role === 'clientOwner';
  // Only an owner may list the team; asking as anyone else is a 403, which tryGet turns into null.
  const team = isOwner ? await tryGet<{ users: TeamMember[] }>('/account/users') : null;
  const terms = data.termsAcceptanceRequired
    ? await tryGet<{ version: string; text: string }>('/terms')
    : null;

  return (
    <Shell>
      <PageHeader title="Account" subtitle={data.account.email} />

      {data.termsAcceptanceRequired ? (
        <Notice tone="warning">
          <p>
            <strong>The portal terms of access have changed.</strong> Please read and accept them
            below.
          </p>
        </Notice>
      ) : null}

      <div className="columns" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)' }}>
        <section className="panel">
          <h2>You</h2>
          <table>
            <tbody>
              <tr>
                <th>Name</th>
                <td>{data.account.name}</td>
              </tr>
              <tr>
                <th>Email</th>
                <td className="mono small">{data.account.email}</td>
              </tr>
              <tr>
                <th>Role</th>
                <td>{ROLE_LABEL[data.account.role] ?? data.account.role}</td>
              </tr>
              <tr>
                <th>Two-factor</th>
                <td>
                  {data.account.totpEnrolledAt
                    ? 'Enrolled'
                    : 'Not enrolled — required before you can sign in'}
                </td>
              </tr>
            </tbody>
          </table>
        </section>

        <AccountControls
          termsAcceptanceRequired={data.termsAcceptanceRequired}
          termsText={terms?.text ?? null}
        />
      </div>

      {isOwner ? (
        <section className="panel" style={{ marginTop: '1.5rem' }}>
          <h2>Your team</h2>
          <p className="small muted">
            Ask us to invite someone. Invitations are single-use, expire in seven days, and require
            two-factor enrolment before the account works.
          </p>
          <TeamTable members={team?.users ?? []} currentUserId={data.account.id} />
        </section>
      ) : null}
    </Shell>
  );
}
