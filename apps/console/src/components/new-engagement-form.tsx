'use client';

import { useActionState } from 'react';
import { createEngagement, type ActionResult } from '@/app/actions';

/**
 * A new engagement for an existing client.
 *
 * The test window is asked for here rather than later because the report prints it, the legal
 * blocks quote it, and the release gate refuses a report without it.
 */
export function NewEngagementForm({
  clients,
  types,
  profiles,
  preselectedClientId,
}: {
  clients: { id: string; name: string }[];
  types: readonly string[];
  profiles: string[];
  preselectedClientId?: string;
}) {
  const [state, action, pending] = useActionState<ActionResult, FormData>(createEngagement, {
    ok: false,
  });

  return (
    <form action={action}>
      <div className="field">
        <label htmlFor="clientId">Client</label>
        <select id="clientId" name="clientId" required defaultValue={preselectedClientId ?? ''}>
          <option value="" disabled>
            Choose a client
          </option>
          {clients.map((client) => (
            <option key={client.id} value={client.id}>
              {client.name}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="title">Title</label>
        <input
          id="title"
          name="title"
          required
          minLength={3}
          maxLength={200}
          placeholder="Web application and API assessment"
        />
      </div>

      <div className="field">
        <label htmlFor="type">Type</label>
        <select id="type" name="type" defaultValue="webApplication">
          {types.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="testType">Test type</label>
        <select id="testType" name="testType" defaultValue="greyBox">
          <option value="greyBox">Grey box — you have test accounts, not source code</option>
          <option value="blackBox">Black box — no accounts, no source</option>
          <option value="whiteBox">White box — accounts and source code</option>
        </select>
      </div>

      <div className="columns">
        <div className="field">
          <label htmlFor="startsAt">Test window starts</label>
          <input id="startsAt" name="startsAt" type="date" required />
        </div>
        <div className="field">
          <label htmlFor="endsAt">Test window ends</label>
          <input id="endsAt" name="endsAt" type="date" required />
        </div>
      </div>

      <div className="field">
        <label htmlFor="profileId">Policy profile</label>
        <select id="profileId" name="profileId" defaultValue="standard-web-app">
          {profiles.map((profile) => (
            <option key={profile} value={profile}>
              {profile}
            </option>
          ))}
        </select>
        <p className="small muted">The starting policy. You add login details and anything client-specific afterwards.</p>
      </div>

      <div className="columns">
        <div className="field">
          <label htmlFor="currency">Currency</label>
          <select id="currency" name="currency" defaultValue="INR">
            <option value="INR">INR</option>
            <option value="USD">USD</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="quotedAmount">Quoted amount</label>
          <input id="quotedAmount" name="quotedAmount" type="number" min={0} step={1} defaultValue={0} />
        </div>
      </div>

      <div className="field">
        <label htmlFor="timezone">Timezone</label>
        <input id="timezone" name="timezone" defaultValue="Asia/Kolkata" />
      </div>

      {state.error ? (
        <p className="notice notice-danger small" role="alert">
          {state.error}
        </p>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Creating…' : 'Create engagement'}
      </button>
    </form>
  );
}
