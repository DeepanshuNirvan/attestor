import Link from 'next/link';
import { currentSurface } from '@/lib/surface';

/**
 * The application shell. A sidebar and a content column, deliberately dense: this is a tool, and
 * data density is the correct choice here in a way it is not on the marketing site.
 */

export interface ShellProps {
  children: React.ReactNode;
  /** Rendered at the top of the sidebar, under the wordmark. Used for the engagement switcher. */
  aside?: React.ReactNode;
}

const CONSOLE_NAV = [
  {
    group: 'Work',
    links: [
      { href: '/', label: 'Dashboard' },
      { href: '/engagements', label: 'Engagements' },
      { href: '/clients', label: 'Clients' },
    ],
  },
  {
    group: 'Platform',
    links: [
      { href: '/queue', label: 'Job queue' },
      { href: '/legal', label: 'Legal text' },
      { href: '/settings', label: 'Settings' },
    ],
  },
];

const PORTAL_NAV = [
  {
    group: 'Your security',
    links: [
      { href: '/', label: 'Dashboard' },
      { href: '/findings', label: 'Findings' },
      { href: '/reports', label: 'Reports and documents' },
    ],
  },
  {
    group: 'Working with us',
    links: [
      { href: '/retest', label: 'Retests' },
      { href: '/questionnaire', label: 'Questionnaire answers' },
      { href: '/account', label: 'Account' },
    ],
  },
];

export function Shell({ children, aside }: ShellProps) {
  const surface = currentSurface();
  const navigation = surface === 'portal' ? PORTAL_NAV : CONSOLE_NAV;

  return (
    <div className="shell">
      <aside className="sidebar">
        <Link href="/" className="wordmark">
          Attestor{surface === 'portal' ? '' : ' console'}
        </Link>
        {aside}
        {navigation.map((section) => (
          <div className="sidebar-group" key={section.group}>
            <p className="sidebar-group-label">{section.group}</p>
            <nav>
              {section.links.map((link) => (
                <Link key={link.href} href={link.href}>
                  {link.label}
                </Link>
              ))}
            </nav>
          </div>
        ))}
      </aside>
      <main>{children}</main>
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle ? <p className="muted small">{subtitle}</p> : null}
      </div>
      {actions ? <div>{actions}</div> : null}
    </div>
  );
}

export function Severity({ value }: { value: string }) {
  const label = value.charAt(0).toUpperCase() + value.slice(1);
  return <span className={`severity severity-${value}`}>{label}</span>;
}

export function Notice({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warning' | 'danger';
  children: React.ReactNode;
}) {
  const className = tone === 'info' ? 'notice' : `notice notice-${tone}`;
  return <div className={className}>{children}</div>;
}

export function Stat({ label, value, note }: { label: string; value: string | number; note?: string }) {
  return (
    <div className="stat">
      <span className="label">{label}</span>
      <span className="value">{value}</span>
      {note ? <span className="small muted">{note}</span> : null}
    </div>
  );
}
