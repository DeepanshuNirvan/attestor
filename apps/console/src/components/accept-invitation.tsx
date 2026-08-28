'use client';

import { useActionState, useState, useTransition } from 'react';
import { acceptInvitation, confirmInvitationMfa, type ActionResult } from '@/app/actions';
import { formText } from '@/lib/form';

/**
 * The three steps of accepting an invitation.
 *
 * The authenticator secret is shown as the otpauth URL and as the key itself, for typing in. No QR
 * code: rendering one needs either a dependency or a canvas, and every authenticator accepts a
 * pasted key. It is not worth a library on a page that runs once per person.
 */

const initial: ActionResult = { ok: false };

/** Pulls the base32 secret out of the otpauth URL so it can be typed into an authenticator. */
function secretFrom(otpauthUrl: string): string {
  try {
    return new URL(otpauthUrl).searchParams.get('secret') ?? '';
  } catch {
    return '';
  }
}

export function AcceptInvitation({ token }: { token: string }) {
  const [state, action, pending] = useActionState(
    acceptInvitation.bind(null, token),
    initial,
  );
  const [email, setEmail] = useState('');
  const [confirming, startConfirming] = useTransition();
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const detail = state.detail as { otpauthUrl?: string } | undefined;
  const otpauthUrl = detail?.otpauthUrl;

  if (done) {
    return (
      <div className="panel">
        <h2>You are set up</h2>
        <p className="small">
          Your account is active. Sign in with your email address, your password and a code from
          your authenticator.
        </p>
        <a className="button" href="/login">
          Sign in
        </a>
        <Styles />
      </div>
    );
  }

  if (otpauthUrl) {
    return (
      <div className="panel">
        <h2>Add this to your authenticator</h2>
        <p className="small muted">
          Paste this key into any authenticator app — 1Password, Aegis, Google Authenticator, or
          whatever your team already uses. Then enter the code it shows.
        </p>

        <p className="small">Key</p>
        <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
          {secretFrom(otpauthUrl)}
        </pre>

        <p className="small">Full setup URL</p>
        <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{otpauthUrl}</pre>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            const code = formText(new FormData(event.currentTarget), 'code');

            startConfirming(async () => {
              const result = await confirmInvitationMfa(email, code);
              if (result.ok) {
                setDone(true);
                return;
              }
              setConfirmError(result.error ?? 'that code was not accepted');
            });
          }}
        >
          <div className="field">
            <label htmlFor="code">Code from your authenticator</label>
            <input
              id="code"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9 ]{6,8}"
              required
              autoFocus
            />
          </div>

          {confirmError ? (
            <p className="notice notice-danger" role="alert">
              {confirmError}
            </p>
          ) : null}

          <button type="submit" disabled={confirming}>
            {confirming ? 'Checking…' : 'Confirm'}
          </button>
        </form>
        <Styles />
      </div>
    );
  }

  return (
    <form action={action} className="panel">
      <h2>Choose a password</h2>
      <p className="small muted">
        You will also enrol an authenticator on the next screen. Both are required — there is no way
        to use the portal with only a password.
      </p>

      <div className="field">
        <label htmlFor="name">Your name</label>
        <input id="name" name="name" required maxLength={120} autoComplete="name" />
      </div>

      <div className="field">
        <label htmlFor="email">Your email address</label>
        <input
          id="email"
          name="email"
          type="email"
          required
          autoComplete="username"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />
        <p className="small muted">
          The address the invitation was sent to. It is not submitted with this step; it is used to
          confirm your authenticator on the next one.
        </p>
      </div>

      <div className="field">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          minLength={12}
          required
          autoComplete="new-password"
        />
        <p className="small muted">
          At least twelve characters. Length beats complexity; a passphrase is fine.
        </p>
      </div>

      <div className="field">
        <label htmlFor="confirm">Password again</label>
        <input
          id="confirm"
          name="confirm"
          type="password"
          minLength={12}
          required
          autoComplete="new-password"
        />
      </div>

      {state.error ? (
        <p className="notice notice-danger" role="alert">
          {state.error}
        </p>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Setting up…' : 'Continue'}
      </button>
      <Styles />
    </form>
  );
}

function Styles() {
  return (
    <style>{`
      .auth {
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 2rem 1rem;
      }
      .auth .panel {
        width: min(30rem, 100%);
      }
      .auth button,
      .auth .button {
        width: 100%;
        margin-top: 0.5rem;
        text-align: center;
      }
    `}</style>
  );
}
