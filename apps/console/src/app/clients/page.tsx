import Link from 'next/link';
import { redirect } from 'next/navigation';
import { PageHeader, Shell } from '@/components/shell';
import { tryGet } from '@/lib/api';

/** Clients, with their engagements folded in. Console surface only. */

interface ClientRow {
  id: string;
  name: string;
  legalName: string;
  country: string;
  dataProcessingAgreementSignedAt: string | null;
  engagements: { id: string; reference: string; title: string; state: string }[];
}

const ACTIVE_STATES = new Set(['scoped', 'authorised', 'running', 'triage', 'manualTesting', 'reporting', 'retestPending']);

export default async function ClientsPage() {
  const data = await tryGet<{ clients: ClientRow[] }>('/clients');
  if (!data) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Clients"
        subtitle={`${data.clients.length} on record`}
        actions={
          <Link className="button" href="/clients/new">
            Add a client
          </Link>
        }
      />

      <div className="panel">
        {data.clients.length === 0 ? (
          <p className="muted small">
            No clients yet. Seed the demo data with <code>pnpm --filter @attestor/api seed</code>, or
            add one.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Client</th>
                <th>Legal name</th>
                <th>Country</th>
                <th>Active work</th>
                <th>Total</th>
                <th>DPA</th>
              </tr>
            </thead>
            <tbody>
              {data.clients.map((client) => {
                const active = client.engagements.filter((item) => ACTIVE_STATES.has(item.state));
                return (
                  <tr key={client.id}>
                    <td>
                      <Link href={`/clients/${client.id}`}>{client.name}</Link>
                    </td>
                    <td className="small muted">{client.legalName}</td>
                    <td className="small">{client.country}</td>
                    <td className="small">
                      {active.length === 0
                        ? '—'
                        : active.map((item) => item.reference).join(', ')}
                    </td>
                    <td className="small muted">{client.engagements.length}</td>
                    <td className="small">
                      {client.dataProcessingAgreementSignedAt ? 'Signed' : 'Not signed'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
