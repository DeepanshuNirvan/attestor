import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { PageHeader, Shell, Stat } from '@/components/shell';
import { ClientControls } from '@/components/client-controls';
import { tryGet } from '@/lib/api';

/** One client: their engagements, their portal users, their retainers. */

interface ClientDetail {
  client: {
    id: string;
    name: string;
    legalName: string;
    country: string;
    dataProcessingAgreementSignedAt: string | null;
    notes: string;
  };
  engagements: {
    id: string;
    reference: string;
    title: string;
    state: string;
    startsAt: string | null;
    endsAt: string | null;
    invoiceState: string;
  }[];
  users: {
    id: string;
    email: string;
    name: string;
    role: string;
    activatedAt: string | null;
    deactivatedAt: string | null;
    totpEnrolledAt: string | null;
  }[];
  invitations: {
    id: string;
    email: string;
    role: string;
    expiresAt: string;
    acceptedAt: string | null;
  }[];
  retainers: {
    id: string;
    cadence: string;
    modules: string[];
    nextRunAt: string | null;
    lastRunAt: string | null;
    active: boolean;
  }[];
}

function formatDate(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function ClientPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await tryGet<ClientDetail>(`/clients/${id}`);
  if (data === null) redirect('/login');
  if (!data.client) notFound();

  const activeUsers = data.users.filter((user) => !user.deactivatedAt);

  return (
    <Shell>
      <PageHeader
        title={data.client.name}
        subtitle={data.client.legalName}
        actions={
          <Link className="button button-quiet" href="/clients">
            All clients
          </Link>
        }
      />

      <div className="stats" style={{ marginBottom: '1.5rem' }}>
        <Stat label="Engagements" value={data.engagements.length} />
        <Stat label="Portal users" value={activeUsers.length} note={`${data.users.length} total`} />
        <Stat
          label="Retainers"
          value={data.retainers.filter((item) => item.active).length}
          note={`${data.retainers.length} configured`}
        />
        <Stat
          label="Data processing agreement"
          value={data.client.dataProcessingAgreementSignedAt ? 'Signed' : 'Not signed'}
          note={formatDate(data.client.dataProcessingAgreementSignedAt)}
        />
      </div>

      <section className="panel" style={{ marginBottom: '1.5rem' }}>
        <h2>Engagements</h2>
        {data.engagements.length === 0 ? (
          <p className="muted small">None yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Reference</th>
                <th>Title</th>
                <th>Stage</th>
                <th>Window</th>
                <th>Invoice</th>
              </tr>
            </thead>
            <tbody>
              {data.engagements.map((engagement) => (
                <tr key={engagement.id}>
                  <td>
                    <Link className="mono" href={`/engagements/${engagement.id}`}>
                      {engagement.reference}
                    </Link>
                  </td>
                  <td>{engagement.title}</td>
                  <td className="small">{engagement.state}</td>
                  <td className="small muted">
                    {formatDate(engagement.startsAt)} — {formatDate(engagement.endsAt)}
                  </td>
                  <td className="small">{engagement.invoiceState}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <ClientControls
        clientId={id}
        dpaSignedAt={data.client.dataProcessingAgreementSignedAt}
        users={data.users}
        invitations={data.invitations}
        retainers={data.retainers}
      />

      {data.client.notes ? (
        <section className="panel" style={{ marginTop: '1.5rem' }}>
          <h2>Notes</h2>
          <p style={{ whiteSpace: 'pre-wrap' }}>{data.client.notes}</p>
        </section>
      ) : null}
    </Shell>
  );
}
