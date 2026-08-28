import type { Metadata } from 'next';
import { currentSurface } from '@/lib/surface';
import './globals.css';

export const metadata: Metadata = {
  title: 'Attestor',
  // The console is not reachable from the internet and the portal must not be indexed either.
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const surface = currentSurface();

  return (
    <html lang="en-GB">
      <body data-surface={surface}>{children}</body>
    </html>
  );
}
