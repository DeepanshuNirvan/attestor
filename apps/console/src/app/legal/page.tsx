import { redirect } from 'next/navigation';
import { Notice, PageHeader, Shell } from '@/components/shell';
import { tryGet } from '@/lib/api';

/**
 * The legal text that goes into documents.
 *
 * It is versioned in code rather than edited here, because a clause that can be changed in a form
 * is a clause nobody can prove the wording of afterwards. Changing it is a commit and a review.
 */

interface LegalBlock {
  id: string;
  title: string;
  version: string;
  mandatory: boolean;
  lawyerReviewedAt: string | null;
  appearsIn: string[];
  text: string;
}

export default async function LegalPage() {
  const data = await tryGet<{ blocks: LegalBlock[]; allReviewed: boolean }>('/legal-blocks');
  if (!data) redirect('/login');

  const unreviewed = data.blocks.filter((block) => block.lawyerReviewedAt === null);

  return (
    <Shell>
      <PageHeader
        title="Legal text"
        subtitle={`${data.blocks.length} blocks, ${unreviewed.length} not yet reviewed`}
      />

      {unreviewed.length > 0 ? (
        <Notice tone="warning">
          <p>
            <strong>{unreviewed.length} block(s) have not been reviewed by a lawyer.</strong> Every
            document that contains one renders with a visible draft banner, and the pre-release
            checklist reports it. This is a business risk with a name, not a bug.
          </p>
        </Notice>
      ) : null}

      {data.blocks.map((block) => (
        <section className="panel" key={block.id} style={{ marginBottom: '1.5rem' }}>
          <h2>{block.title}</h2>
          <p className="small muted">
            <span className="mono">{block.id}</span> · version {block.version} ·{' '}
            {block.mandatory ? 'mandatory' : 'optional'} · appears in {block.appearsIn.join(', ')} ·{' '}
            {block.lawyerReviewedAt
              ? `reviewed ${block.lawyerReviewedAt}`
              : 'NOT REVIEWED BY A LAWYER'}
          </p>
          <pre style={{ whiteSpace: 'pre-wrap', maxHeight: '22rem', overflow: 'auto' }}>
            {block.text}
          </pre>
        </section>
      ))}
    </Shell>
  );
}
