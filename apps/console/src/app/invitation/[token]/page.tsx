import { AcceptInvitation } from '@/components/accept-invitation';

/**
 * Accepting a portal invitation.
 *
 * Three steps: set a password, enrol an authenticator, confirm a code. The account does not work
 * until the third completes — a second factor a client can postpone is a second factor a client
 * never enables.
 *
 * The token is in the path, so it will appear in this server's access log. That is accepted: it is
 * single-use, it expires in seven days, and it is worthless once accepted.
 */
export default async function InvitationPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  return (
    <div className="auth">
      <AcceptInvitation token={token} />
    </div>
  );
}
