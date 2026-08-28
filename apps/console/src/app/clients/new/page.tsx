'use client';

import Link from 'next/link';
import { useActionState } from 'react';
import { createClient, type ActionResult } from '@/app/actions';
import { PageHeader, Shell } from '@/components/shell';

/** A new client. Deliberately short: the rest is filled in as the relationship starts. */
export default function NewClientPage() {
  const [state, action, pending] = useActionState<ActionResult, FormData>(createClient, {
    ok: false,
  });

  return (
    <Shell>
      <PageHeader
        title="Add a client"
        actions={
          <Link className="button button-quiet" href="/clients">
            Cancel
          </Link>
        }
      />

      <div className="panel" style={{ maxWidth: '40rem' }}>
        <form action={action}>
          <div className="field">
            <label htmlFor="name">Name we use day to day</label>
            <input id="name" name="name" required maxLength={200} />
          </div>

          <div className="field">
            <label htmlFor="legalName">Registered legal name</label>
            <input id="legalName" name="legalName" required maxLength={300} />
            <p className="small muted">
              This is what appears on the contract, the authorisation and the report cover. It has to
              match their registration, not their brand.
            </p>
          </div>

          <div className="field">
            <label htmlFor="country">Country</label>
            <input id="country" name="country" defaultValue="IN" maxLength={2} size={4} />
          </div>

          <div className="field">
            <label htmlFor="notes">Notes</label>
            <textarea id="notes" name="notes" rows={4} />
          </div>

          {state.error ? (
            <p className="notice notice-danger small" role="alert">
              {state.error}
            </p>
          ) : null}

          <button type="submit" disabled={pending}>
            {pending ? 'Saving…' : 'Create'}
          </button>
        </form>
      </div>
    </Shell>
  );
}
