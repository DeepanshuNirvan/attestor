import { redirect } from 'next/navigation';
import { PageHeader, Shell } from '@/components/shell';
import { CopyableAnswer } from '@/components/copyable-answer';
import { tryGet } from '@/lib/api';

/**
 * The questionnaire helper.
 *
 * Buyers send our clients security questionnaires, and the answers about their testing programme
 * are the same every time. These are ours to give: they describe how we work, so nothing here is
 * specific to one client and nothing here is a claim we cannot support.
 */

interface Answer {
  id: string;
  category: string;
  question: string;
  answer: string;
}

interface QuestionnaireResponse {
  categories: { category: string; items: Answer[] }[];
  note: string;
}

export default async function QuestionnairePage() {
  const data = await tryGet<QuestionnaireResponse>('/questionnaire');
  if (!data) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Questionnaire answers"
        subtitle="Ready-made answers for the security questions your customers ask you"
      />

      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <p className="small">{data.note}</p>
      </div>

      {data.categories.length === 0 ? (
        <div className="panel">
          <p className="muted small">Nothing here yet.</p>
        </div>
      ) : (
        data.categories.map((group) => (
          <section className="panel" key={group.category} style={{ marginBottom: '1.5rem' }}>
            <h2>{group.category}</h2>
            {group.items.map((item) => (
              <CopyableAnswer key={item.id} question={item.question} answer={item.answer} />
            ))}
          </section>
        ))
      )}
    </Shell>
  );
}
