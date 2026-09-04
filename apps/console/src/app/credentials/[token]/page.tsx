import { CredentialIntake } from '@/components/credential-intake';
import { loadIntake } from '@/lib/intake-api';

/**
 * Where a client hands over a test account.
 *
 * Public: there is no session, because demanding one would mean the client needed an account before
 * they could give us a password. The one-time token in the path is the authorisation — it was
 * generated once, only its hash is stored, and it expires.
 *
 * The token appears in this server's access log, which is accepted for the same reasons the
 * invitation token is: it expires, it is scoped to one engagement, and it can only ever be used to
 * *write* a credential. Nothing it unlocks can be read back through it.
 */
export default async function CredentialIntakePage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;
  const lookup = await loadIntake(token);

  if (!lookup.ok) {
    return (
      <div className="auth">
        <div className="panel">
          <h1>This link cannot be used</h1>
          <p className="small">{lookup.message}</p>
          <p className="small muted">
            Reply to the message that sent you here and ask for a new link. Please do not send a
            password by email or chat in the meantime.
          </p>
        </div>
      </div>
    );
  }

  return (
    <CredentialIntake
      token={token}
      clientName={lookup.details.clientName}
      engagementReference={lookup.details.engagementReference}
      engagementTitle={lookup.details.engagementTitle}
      expiresAt={lookup.details.expiresAt}
      forms={lookup.details.forms}
    />
  );
}
