'use client';

import { useActionState } from 'react';
import { submitMfa, type ActionResult } from '@/app/actions';

const initial: ActionResult = { ok: false };

export default function MfaPage() {
  const [state, action, pending] = useActionState(submitMfa, initial);

  return (
    <div className="auth">
      <form action={action} className="panel">
        <h1>Second factor</h1>
        <p className="muted small">
          Enter the six-digit code from your authenticator. Your session does nothing until this is
          confirmed.
        </p>

        <div className="field">
          <label htmlFor="code">Code</label>
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

        {state.error ? (
          <p className="notice notice-danger" role="alert">
            {state.error}
          </p>
        ) : null}

        <button type="submit" disabled={pending}>
          {pending ? 'Checking…' : 'Sign in'}
        </button>
      </form>

      <style>{`
        .auth {
          min-height: 100vh;
          display: grid;
          place-items: center;
          padding: 2rem 1rem;
        }
        .auth form {
          width: min(22rem, 100%);
        }
        .auth button {
          width: 100%;
          margin-top: 0.5rem;
        }
        .auth input {
          font-family: var(--font-mono);
          font-size: 1.2rem;
          letter-spacing: 0.2em;
          text-align: center;
        }
      `}</style>
    </div>
  );
}
