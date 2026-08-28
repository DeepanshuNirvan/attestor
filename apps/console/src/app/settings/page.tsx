import { redirect } from 'next/navigation';
import { Notice, PageHeader, Shell } from '@/components/shell';
import { tryGet } from '@/lib/api';

/**
 * What this deployment is configured to do.
 *
 * No secret appears here, and there is nothing to edit. Configuration comes from the environment
 * and is validated at start-up; a settings screen that could change a security control at runtime
 * is a second way to turn one off.
 */

interface Settings {
  configuration: {
    aiEnabled: boolean;
    aiProvider: string;
    aiMonthlyBudgetUsd: number;
    egressIp: string;
    portalOrigin: string;
    consoleOrigin: string;
    evidenceBucket: string;
    reportBucket: string;
  };
  capabilities: {
    denialOfService: boolean;
    rateCeilings: Record<string, number>;
  };
  tools: {
    id: string;
    displayName: string;
    image: string;
    modules: string[];
    purpose: string;
    digest: string | null;
    runnable: boolean;
  }[];
  legal: {
    blocks: { id: string; version: string; lawyerReviewedAt: string | null }[];
    unreviewed: string[];
  };
  aiUsage: {
    model: string;
    purpose: string;
    inputTokens: number;
    outputTokens: number;
    cost: number;
  }[];
}

export default async function SettingsPage() {
  const data = await tryGet<Settings>('/settings');
  if (!data) redirect('/login');

  const unpinned = data.tools.filter((tool) => !tool.runnable);

  return (
    <Shell>
      <PageHeader title="Settings" subtitle="What this deployment is configured to do" />

      {unpinned.length > 0 ? (
        <Notice tone="warning">
          <p>
            <strong>{unpinned.length} tool(s) have no pinned digest and will not run.</strong> Run{' '}
            <code>node scripts/pin-tool-images.mjs --pull</code>. A report that names a tool version
            has to mean it, so an unpinned tool is refused rather than run.
          </p>
        </Notice>
      ) : null}

      <div className="columns" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)' }}>
        <section className="panel">
          <h2>This deployment</h2>
          <table>
            <tbody>
              <tr>
                <th>Egress address</th>
                <td className="mono small">{data.configuration.egressIp || 'not set'}</td>
              </tr>
              <tr>
                <th>Console origin</th>
                <td className="mono small">{data.configuration.consoleOrigin}</td>
              </tr>
              <tr>
                <th>Portal origin</th>
                <td className="mono small">{data.configuration.portalOrigin}</td>
              </tr>
              <tr>
                <th>Evidence bucket</th>
                <td className="mono small">{data.configuration.evidenceBucket}</td>
              </tr>
              <tr>
                <th>Report bucket</th>
                <td className="mono small">{data.configuration.reportBucket}</td>
              </tr>
            </tbody>
          </table>
          <p className="small muted">
            Secrets are not shown here and there is no field to change one. Configuration comes from
            the environment and is validated when the process starts.
          </p>
        </section>

        <section className="panel">
          <h2>Capabilities</h2>
          <table>
            <tbody>
              <tr>
                <th>Denial of service</th>
                <td className="small">
                  {data.capabilities.denialOfService ? 'ENABLED' : 'Not available'}
                </td>
              </tr>
              {Object.entries(data.capabilities.rateCeilings).map(([key, value]) => (
                <tr key={key}>
                  <th>{key}</th>
                  <td className="small">{value}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="small muted">
            The ceilings are hard limits. A policy that asks for more is clamped to these, and there
            is no field anywhere that expresses a load test.
          </p>

          <h3>AI assistance</h3>
          <p className="small">
            {data.configuration.aiEnabled
              ? `Enabled, provider ${data.configuration.aiProvider}, budget $${data.configuration.aiMonthlyBudgetUsd}/month.`
              : 'Off. The platform works fully without it; turning it on is a per-engagement decision.'}
          </p>
          {data.aiUsage.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Purpose</th>
                  <th>Tokens in</th>
                  <th>Tokens out</th>
                  <th>Cost</th>
                </tr>
              </thead>
              <tbody>
                {data.aiUsage.map((row) => (
                  <tr key={`${row.model}-${row.purpose}`}>
                    <td className="small">{row.model}</td>
                    <td className="small">{row.purpose}</td>
                    <td className="small muted">{row.inputTokens}</td>
                    <td className="small muted">{row.outputTokens}</td>
                    <td className="small">${Number(row.cost).toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </section>
      </div>

      <section className="panel" style={{ marginTop: '1.5rem' }}>
        <h2>Tools</h2>
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Image</th>
              <th>Modules</th>
              <th>Purpose</th>
              <th>Digest</th>
            </tr>
          </thead>
          <tbody>
            {data.tools.map((tool) => (
              <tr key={tool.id}>
                <td>{tool.displayName}</td>
                <td className="mono small">{tool.image}</td>
                <td className="small">{tool.modules.join(', ')}</td>
                <td className="small muted">{tool.purpose}</td>
                <td className="mono small">
                  {tool.digest ? `${tool.digest.slice(0, 19)}…` : 'not pinned'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </Shell>
  );
}
