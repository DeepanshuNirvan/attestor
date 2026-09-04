'use client';

import { useActionState } from 'react';
import { submitCredentials, type ActionResult } from '@/app/actions';
import type { IntakeForm } from '@/lib/intake-api';

/**
 * The form a client fills in to hand over a test account.
 *
 * This is the only page in the product a client sees before they have an account, and it is the
 * moment they are most likely to give up and email a password instead. So: one page, the two or
 * three boxes that this kind of login actually needs, plain words under each, and a submit per
 * account rather than one big form that fails as a whole.
 *
 * Each account submits on its own, so getting one wrong does not lose the others, and a client can
 * come back to the same link later to finish.
 */

const initial: ActionResult = { ok: false };

function AccountForm({ token, form }: { token: string; form: IntakeForm }) {
  const [state, action, pending] = useActionState(
    submitCredentials.bind(null, token, form.slot, form.fields.map((field) => field.name)),
    initial,
  );

  const saved = state.ok || form.alreadyProvided;

  return (
    <form action={action} className="panel">
      <h3>{form.label}</h3>
      <p className="small muted">
        {form.kindLabel}
        {form.description ? ` — ${form.description}` : ''}
      </p>

      {saved && !state.error ? (
        <p className="notice small">
          Saved and encrypted. You can submit again if you need to change it.
        </p>
      ) : null}

      {form.fields.map((field) => (
        <div className="field" key={field.name}>
          <label htmlFor={`${form.slot}-${field.name}`}>
            {field.label}
            {field.optional ? <span className="muted"> (optional)</span> : null}
          </label>
          {field.input === 'textarea' ? (
            <textarea
              id={`${form.slot}-${field.name}`}
              name={field.name}
              rows={3}
              required={!field.optional}
              autoComplete="off"
            />
          ) : (
            <input
              id={`${form.slot}-${field.name}`}
              name={field.name}
              type={field.input}
              required={!field.optional}
              autoComplete="off"
              spellCheck={false}
            />
          )}
          <p className="small muted">{field.help}</p>
        </div>
      ))}

      {state.error ? (
        <p className="notice notice-warning small" role="alert">
          {state.error}
        </p>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Saving…' : saved ? 'Replace this account' : `Send ${form.label}`}
      </button>
    </form>
  );
}

export function CredentialIntake({
  token,
  clientName,
  engagementReference,
  engagementTitle,
  expiresAt,
  forms,
}: {
  token: string;
  clientName: string;
  engagementReference: string;
  engagementTitle: string;
  expiresAt: string;
  forms: IntakeForm[];
}) {
  return (
    <div className="auth">
      <header>
        <h1>Test accounts for {clientName}</h1>
        <p className="small muted">
          {engagementTitle} · {engagementReference} · this page stops working on{' '}
          {new Date(expiresAt).toLocaleDateString('en-GB', {
            day: 'numeric',
            month: 'long',
            year: 'numeric',
          })}
        </p>
      </header>

      <div className="panel">
        <h2>Before you start</h2>
        <ul className="small">
          <li>
            Use <strong>accounts made for this test</strong>, not a real customer&apos;s and not your
            own admin login.
          </li>
          <li>
            What you type here is encrypted before it is stored. <strong>Nobody can display it
            again</strong> — not you, not us.
          </li>
          <li>
            Send each account separately. If one is wrong, the others are still saved, and you can
            come back to this page later.
          </li>
          <li>Change these passwords when the test is over.</li>
        </ul>
      </div>

      {forms.map((form) => (
        <AccountForm key={form.slot} token={token} form={form} />
      ))}

      <p className="small muted">
        Something not right, or an account you cannot create? Reply to the message that sent you this
        link rather than emailing a password.
      </p>

    </div>
  );
}
