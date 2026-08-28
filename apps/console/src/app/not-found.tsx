import Link from 'next/link';

/** Nothing here. Says so without naming what does exist elsewhere. */
export default function NotFound() {
  return (
    <div className="auth">
      <div className="panel">
        <h1>Not found</h1>
        <p className="small">There is nothing at that address.</p>
        <Link className="button" href="/">
          Back
        </Link>
      </div>

      <style>{`
        .auth {
          min-height: 100vh;
          display: grid;
          place-items: center;
          padding: 2rem 1rem;
        }
        .auth .panel {
          width: min(24rem, 100%);
        }
        .auth .button {
          display: block;
          width: 100%;
          margin-top: 0.5rem;
          text-align: center;
        }
      `}</style>
    </div>
  );
}
