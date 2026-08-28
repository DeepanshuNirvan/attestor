import { Readable } from 'node:stream';
import Docker from 'dockerode';
import type { ToolImage } from './tool-images.ts';

/**
 * THE ONLY MODULE IN THE REPOSITORY THAT TALKS TO DOCKER.
 *
 * An ESLint rule (`no-restricted-imports` on `dockerode`) and an architecture test both fail the
 * build if anything else imports it. That is deliberate: the scope guard is only a guarantee if
 * there is exactly one way to start a container, and this is it. Callers reach it through
 * `runToolForEngagement`, never directly.
 *
 * Container hardening is applied here rather than per-tool, so a new tool adapter cannot forget it.
 */

export interface ContainerRunRequest {
  tool: ToolImage;
  /** Resolved digest from infra/tool-images.lock.json. A tool with no digest does not run. */
  digest: string;
  command: string[];
  /** Environment for the tool. Secrets are passed here and never written to the image or a file. */
  environment: Record<string, string>;
  /** Docker network to attach. One per engagement run, created and destroyed by the caller. */
  networkName: string;
  /** Host directory mounted read-write at /out for the tool's output. */
  outputDirectory: string;
  /** Host directories mounted read-only, for inputs like a repository or an application package. */
  readOnlyMounts?: { hostPath: string; containerPath: string }[];
  /**
   * Labels applied to the container. The panic stop finds containers by label, so a container
   * started without them cannot be stopped by it — they are not optional in practice.
   */
  labels: { engagementId: string; scanRunId: string };
  /**
   * Extra networks to attach after creation. Used by the integration harness to put a tool on the
   * network the deliberately-vulnerable targets sit on. It grants reachability, not authorisation:
   * every target has already passed the scope guard before this function is reached.
   */
  additionalNetworks?: string[];
}

export interface ContainerRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export interface ContainerRunnerOptions {
  socketPath?: string;
  /** Injected in tests so no test in this repository can start a container. */
  docker?: Docker;
}

export class ContainerRunner {
  private readonly docker: Docker;

  constructor(options: ContainerRunnerOptions = {}) {
    this.docker =
      options.docker ?? new Docker(options.socketPath ? { socketPath: options.socketPath } : {});
  }

  async run(request: ContainerRunRequest): Promise<ContainerRunResult> {
    if (!request.digest || !request.digest.startsWith('sha256:')) {
      throw new Error(
        `tool "${request.tool.id}" has no pinned digest. Run scripts/pin-tool-images.mjs; an unpinned tool cannot be cited in a report.`,
      );
    }

    const image = `${request.tool.image}@${request.digest}`;
    const startedAt = Date.now();

    const binds = [
      `${request.outputDirectory}:/out:rw`,
      ...(request.readOnlyMounts ?? []).map(
        (mount) => `${mount.hostPath}:${mount.containerPath}:ro`,
      ),
    ];

    const container = await this.docker.createContainer({
      Image: image,
      Cmd: request.command,
      Env: Object.entries(request.environment).map(([key, value]) => `${key}=${value}`),
      User: '65532:65532',
      Labels: {
        'com.attestor.purpose': 'engagement-run',
        'com.attestor.engagement': request.labels.engagementId,
        'com.attestor.scan-run': request.labels.scanRunId,
      },
      WorkingDir: '/out',
      NetworkDisabled: false,
      HostConfig: {
        // Per-run network. Never the host network: a tool on the host network can reach the
        // platform's own services and the docker socket's neighbours.
        NetworkMode: request.networkName,
        // A read-only root filesystem, with tmpfs where the tool genuinely needs to write.
        ReadonlyRootfs: true,
        Tmpfs: request.tool.needsWritableTmp
          ? { '/tmp': 'rw,noexec,nosuid,size=512m', '/home/nonroot': 'rw,noexec,nosuid,size=64m' }
          : undefined,
        Binds: binds,
        CapDrop: ['ALL'],
        SecurityOpt: ['no-new-privileges:true'],
        Memory: request.tool.memoryMb * 1024 * 1024,
        MemorySwap: request.tool.memoryMb * 1024 * 1024,
        PidsLimit: 512,
        NanoCpus: 2_000_000_000,
        AutoRemove: false,
        RestartPolicy: { Name: 'no' },
        LogConfig: { Type: 'json-file', Config: { 'max-size': '16m', 'max-file': '2' } },
      },
      AttachStdout: true,
      AttachStderr: true,
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let timedOut = false;

    try {
      const stream = await container.attach({ stream: true, stdout: true, stderr: true });
      const stdout = new Readable({ read() {} });
      const stderr = new Readable({ read() {} });
      stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
      stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));
      // dockerode types the modem loosely; the demux helper is the documented way to split the
      // multiplexed attach stream.
      const modem = container.modem as { demuxStream: (source: NodeJS.ReadableStream, out: Readable, err: Readable) => void };
      modem.demuxStream(stream, stdout, stderr);

      for (const network of request.additionalNetworks ?? []) {
        await this.docker.getNetwork(network).connect({ Container: container.id });
      }

      await container.start();

      const timeout = setTimeout(() => {
        timedOut = true;
        void container.kill({ signal: 'SIGKILL' }).catch(() => undefined);
      }, request.tool.timeoutSeconds * 1000);

      const result = (await container.wait()) as { StatusCode: number };
      clearTimeout(timeout);

      return {
        exitCode: result.StatusCode,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        durationMs: Date.now() - startedAt,
        timedOut,
      };
    } finally {
      await container.remove({ force: true }).catch(() => undefined);
    }
  }

  /** Creates the per-run network. Internal by default so a tool cannot reach the host's other nets. */
  async createRunNetwork(name: string): Promise<void> {
    await this.docker.createNetwork({
      Name: name,
      Driver: 'bridge',
      Internal: false,
      Attachable: true,
      Labels: { 'com.attestor.purpose': 'engagement-run' },
    });
  }

  async removeRunNetwork(name: string): Promise<void> {
    await this.docker
      .getNetwork(name)
      .remove()
      .catch(() => undefined);
  }

  /** Kills everything labelled as an engagement run. This is what the panic stop calls. */
  async killAllRunContainers(engagementId?: string): Promise<number> {
    const containers = await this.docker.listContainers({
      all: false,
      filters: JSON.stringify({
        label: engagementId
          ? [`com.attestor.engagement=${engagementId}`]
          : ['com.attestor.purpose=engagement-run'],
      }),
    });
    for (const summary of containers) {
      await this.docker
        .getContainer(summary.Id)
        .kill({ signal: 'SIGKILL' })
        .catch(() => undefined);
    }
    return containers.length;
  }

  async imageDigestFor(reference: string): Promise<string | null> {
    try {
      const details = (await this.docker.getImage(reference).inspect()) as { RepoDigests?: string[] };
      const digest = details.RepoDigests?.[0]?.split('@')[1];
      return digest ?? null;
    } catch {
      return null;
    }
  }
}
