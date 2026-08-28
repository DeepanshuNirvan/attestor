'use client';

/**
 * The error boundary.
 *
 * It says what is wrong in one line and nothing else. `error.digest` is the identifier the server
 * log carries; the message and the stack stay on the server, because a stack trace on a client's
 * screen is both useless to them and useful to somebody else.
 */
export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="auth">
      <div className="panel">
        <h1>That did not load</h1>
        <p className="small">
          Something went wrong on our side. It is on the record; if it keeps happening, tell us and
          quote the reference below.
        </p>
        {error.digest ? (
          <p className="small muted">
            Reference <span className="mono">{error.digest}</span>
          </p>
        ) : null}
        <button type="button" onClick={reset}>
          Try again
        </button>
      </div>

      <style>{`
        .auth {
          min-height: 100vh;
          display: grid;
          place-items: center;
          padding: 2rem 1rem;
        }
        .auth .panel {
          width: min(28rem, 100%);
        }
        .auth button {
          width: 100%;
          margin-top: 0.5rem;
        }
      `}</style>
    </div>
  );
}
