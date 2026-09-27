import Link from 'next/link';
import { redirect } from 'next/navigation';
import { PageHeader, Shell } from '@/components/shell';
import { ManualFindingForm } from '@/components/manual-finding-form';
import { tryGet } from '@/lib/api';

/** Recording a finding from manual testing. */
export default async function NewFindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await tryGet<{ engagement: { reference: string; title: string } }>(`/engagements/${id}`);
  if (!data) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Record a finding"
        subtitle={`${data.engagement.reference} · something you found by hand. Tools' findings arrive in Triage on their own.`}
        actions={
          <Link className="button button-quiet" href={`/engagements/${id}`}>
            Cancel
          </Link>
        }
      />
      <div className="panel" style={{ maxWidth: '44rem' }}>
        <ManualFindingForm engagementId={id} />
      </div>
    </Shell>
  );
}
