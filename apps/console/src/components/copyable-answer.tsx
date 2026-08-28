'use client';

import { useState } from 'react';

/** One question and answer, with a copy button because that is the only thing anyone does here. */
export function CopyableAnswer({ question, answer }: { question: string; answer: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <div style={{ borderTop: '1px solid var(--rule)', padding: '0.9rem 0' }}>
      <h3 style={{ marginBottom: '0.3rem' }}>{question}</h3>
      <p style={{ whiteSpace: 'pre-wrap' }}>{answer}</p>
      <button
        type="button"
        className="button-quiet"
        onClick={() => {
          void navigator.clipboard.writeText(answer).then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 2_000);
          });
        }}
      >
        {copied ? 'Copied' : 'Copy answer'}
      </button>
    </div>
  );
}
