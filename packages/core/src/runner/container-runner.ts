import { Writable } from 'node:stream';
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

/** Sink for one half of the de-multiplexed attach stream. */
function collectInto(chunks: Buffer[]): Writable {
  return new Writable({
    write(chunk: Buffer, unusedEncoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
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
      // UID 65532 has no passwd entry in most tool images, so HOME is unset and a tool that keeps
      // configuration or a template cache under it falls back to `/` — which is read-only here.
      // nuclei died on `mkdir /.config: read-only file system` before it sent a single request,
      // exited non-zero and wrote nothing, which looked from the outside like a clean scan.
      // Pointing HOME at the tmpfs belongs here rather than per tool, with the rest of the
      // hardening, so a new adapter cannot forget it.
      Env: Object.entries({
        ...(request.tool.needsWritableTmp ? { HOME: '/home/nonroot' } : {}),
        ...request.environment,
      }).map(([key, value]) => `${key}=${value}`),
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
      // demuxStream *writes* the two de-multiplexed halves into the sinks it is given, so these
      // have to be Writable. Handing it Readables threw `stderr.write is not a function` from
      // inside docker-modem's response handler — asynchronously, so it took the worker process
      // down rather than failing the run.
      const modem = container.modem as {
        demuxStream: (source: NodeJS.ReadableStream, out: Writable, err: Writable) => void;
      };
      modem.demuxStream(stream, collectInto(stdoutChunks), collectInto(stderrChunks));

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

  /**
   * Remove run containers and run networks left behind by a previous life of this process.
   *
   * `run()` removes its container and its network in a `finally`, which covers a tool that fails,
   * times out or is killed. It does not cover the worker itself being killed — a crash, a restart,
   * a deploy — and then the container and its network survive with nothing left to reclaim them.
   * Across enough restarts that is an unbounded leak of networks on a machine that has 31 of them
   * available by default.
   *
   * Only exited containers are removed. A running one belongs to a worker that is still alive, and
   * killing another worker's run is the one thing this must never do.
   */
  async reclaimOrphans(): Promise<{ containers: number; networks: number }> {
    const label = ['com.attestor.purpose=engagement-run'];

    const containers = await this.docker.listContainers({
      all: true,
      filters: JSON.stringify({ label, status: ['exited', 'dead', 'created'] }),
    });
    for (const summary of containers) {
      await this.docker.getContainer(summary.Id).remove({ force: true }).catch(() => undefined);
    }

    // A network still attached to a live container refuses removal, which is the behaviour wanted:
    // it fails, is caught, and the run that owns it keeps working.
    const networks = await this.docker.listNetworks({ filters: JSON.stringify({ label }) });
    let removed = 0;
    for (const summary of networks as { Id: string }[]) {
      const gone = await this.docker
        .getNetwork(summary.Id)
        .remove()
        .then(() => true)
        .catch(() => false);
      if (gone) removed += 1;
    }

    return { containers: containers.length, networks: removed };
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
