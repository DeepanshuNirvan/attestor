'use client';

import { useActionState } from 'react';
import { signIn, type ActionResult } from '@/app/actions';

const initial: ActionResult = { ok: false };

export default function LoginPage() {
  const [state, action, pending] = useActionState(signIn, initial);

  return (
    <div className="auth">
      <form action={action} className="panel">
        <h1>Attestor</h1>
        <p className="muted small">
          Sign in, then confirm your authenticator. Both are required; there is no way round the
          second factor.
        </p>

        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="username" required />
        </div>

        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </div>

        {state.error ? (
          <p className="notice notice-danger" role="alert">
            {state.error}
          </p>
        ) : null}

        <button type="submit" disabled={pending}>
          {pending ? 'Checking…' : 'Continue'}
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
          width: min(24rem, 100%);
        }
        .auth button {
          width: 100%;
          margin-top: 0.5rem;
        }
      `}</style>
    </div>
  );
}
