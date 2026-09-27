import Link from 'next/link';
import { redirect } from 'next/navigation';
import { ENGAGEMENT_TYPES } from '@attestor/shared';
import { PageHeader, Shell } from '@/components/shell';
import { NewEngagementForm } from '@/components/new-engagement-form';
import { tryGet } from '@/lib/api';

export default async function NewEngagementPage({
  searchParams,
}: {
  searchParams: Promise<{ clientId?: string }>;
}) {
  const { clientId } = await searchParams;
  const clients = await tryGet<{ clients: { id: string; name: string }[] }>('/clients');
  if (!clients) redirect('/login');
  const profiles = await tryGet<{ profiles: { id: string }[] }>('/profiles');

  return (
    <Shell>
      <PageHeader
        title="New engagement"
        actions={
          <Link className="button button-quiet" href="/engagements">
            Cancel
          </Link>
        }
      />

      <div className="panel" style={{ maxWidth: '40rem' }}>
        {clients.clients.length === 0 ? (
          <p className="muted small">
            Add the client first. <Link href="/clients/new">Add a client</Link>
          </p>
        ) : (
          <NewEngagementForm
            clients={clients.clients}
            types={ENGAGEMENT_TYPES}
            profiles={(profiles?.profiles ?? []).map((profile) => profile.id)}
            preselectedClientId={clientId}
          />
        )}
      </div>
    </Shell>
  );
}
