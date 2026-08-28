import {
  DeleteObjectsCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
  type S3ClientConfig,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { maskText, sha256, redactText, type EvidenceKind, type MaskingRule } from '@attestor/shared';

/**
 * Evidence storage.
 *
 * Two rules shape this file and both are worth stating because they are easy to get wrong in the
 * opposite order:
 *
 *   1. Masking happens here, on the way in. Once raw personal data is on disk it is a DPDP problem
 *      regardless of what the report later prints.
 *   2. Redaction of secrets happens here too, for the same reason. A credential in an evidence
 *      object is a credential in a backup.
 *
 * Objects are keyed by engagement so a purge is a prefix operation, and every object carries the
 * sha256 of what was stored so integrity can be shown later.
 */

export interface EvidenceStoreOptions {
  endpoint: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  /** MinIO needs path-style addressing; real S3 does not care. */
  forcePathStyle?: boolean;
}

export interface CaptureInput {
  engagementId: string;
  scanRunId?: string;
  kind: EvidenceKind;
  /** Text evidence: request/response pairs, terminal output, transcripts, logs. */
  text?: string;
  /** Binary evidence: screenshots, downloaded files. Never masked, so never store a raw document. */
  binary?: Buffer;
  contentType?: string;
  filename?: string;
  maskingRules?: MaskingRule[];
  disabledMaskingRuleIds?: string[];
}

export interface StoredEvidence {
  objectKey: string;
  sha256: string;
  byteSize: number;
  contentType: string;
  redactionApplied: string[];
}

function keyFor(engagementId: string, kind: string, filename?: string): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const suffix = filename ? `-${filename.replace(/[^\w.-]/g, '_')}` : '';
  const nonce = Math.random().toString(36).slice(2, 10);
  return `engagements/${engagementId}/${kind}/${stamp}-${nonce}${suffix}`;
}

export class EvidenceStore {
  private readonly client: S3Client;

  private readonly options: EvidenceStoreOptions;

  constructor(options: EvidenceStoreOptions) {
    this.options = options;
    const config: S3ClientConfig = {
      endpoint: options.endpoint,
      region: options.region,
      credentials: {
        accessKeyId: options.accessKeyId,
        secretAccessKey: options.secretAccessKey,
      },
      forcePathStyle: options.forcePathStyle ?? true,
    };
    this.client = new S3Client(config);
  }

  /**
   * Capture a piece of evidence. Text is redacted for secrets and then masked for personal data,
   * in that order: redaction first so a credential that happens to look like an email address is
   * removed as a credential rather than merely masked as an address.
   */
  async capture(input: CaptureInput): Promise<StoredEvidence> {
    if (!input.text && !input.binary) {
      throw new Error('evidence capture needs either text or binary content');
    }
    if (input.text && input.binary) {
      throw new Error('evidence capture takes text or binary, not both');
    }

    let body: Buffer;
    let redactionApplied: string[] = [];
    let contentType = input.contentType ?? 'text/plain; charset=utf-8';

    if (input.text !== undefined) {
      const redacted = redactText(input.text);
      const masked = maskText(redacted, {
        extraRules: input.maskingRules,
        disabledRuleIds: input.disabledMaskingRuleIds,
      });
      body = Buffer.from(masked.text, 'utf8');
      redactionApplied = masked.applied;
    } else {
      body = input.binary as Buffer;
      contentType = input.contentType ?? 'application/octet-stream';
    }

    const objectKey = keyFor(input.engagementId, input.kind, input.filename);
    const digest = sha256(body);

    await this.client.send(
      new PutObjectCommand({
        Bucket: this.options.bucket,
        Key: objectKey,
        Body: body,
        ContentType: contentType,
        // Server-side encryption at rest. MinIO honours this when configured with KMS or SSE-S3.
        ServerSideEncryption: 'AES256',
        Metadata: {
          engagement: input.engagementId,
          kind: input.kind,
          sha256: digest,
          ...(input.scanRunId ? { scanrun: input.scanRunId } : {}),
        },
      }),
    );

    return {
      objectKey,
      sha256: digest,
      byteSize: body.byteLength,
      contentType,
      redactionApplied,
    };
  }

  async read(objectKey: string): Promise<Buffer> {
    const result = await this.client.send(
      new GetObjectCommand({ Bucket: this.options.bucket, Key: objectKey }),
    );
    const chunks: Buffer[] = [];
    const stream = result.Body as AsyncIterable<Uint8Array> | undefined;
    if (!stream) throw new Error(`evidence object ${objectKey} has no body`);
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  }

  /**
   * Short-lived signed URL. Issued only after the API has checked that the requester may see this
   * engagement; the signature is the delivery mechanism, not the authorisation.
   */
  signedUrl(objectKey: string, expiresInSeconds = 300): Promise<string> {
    return getSignedUrl(
      this.client,
      new GetObjectCommand({ Bucket: this.options.bucket, Key: objectKey }),
      { expiresIn: expiresInSeconds },
    );
  }

  /** Purge in batches. Returns how many objects were deleted. */
  async purge(objectKeys: string[]): Promise<number> {
    if (objectKeys.length === 0) return 0;
    let deleted = 0;
    for (let index = 0; index < objectKeys.length; index += 1000) {
      const batch = objectKeys.slice(index, index + 1000);
      const result = await this.client.send(
        new DeleteObjectsCommand({
          Bucket: this.options.bucket,
          Delete: { Objects: batch.map((key) => ({ Key: key })), Quiet: true },
        }),
      );
      deleted += batch.length - (result.Errors?.length ?? 0);
    }
    return deleted;
  }
}

/**
 * Build a request/response evidence pair as text. Kept here rather than in the adapters so every
 * tool produces the same shape and the portal's viewer only has to render one thing.
 */
export function formatHttpExchange(input: {
  method: string;
  url: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  status: number;
  responseHeaders: Record<string, string>;
  responseBody?: string;
  maxBodyBytes?: number;
}): string {
  const limit = input.maxBodyBytes ?? 256 * 1024;
  const truncate = (value: string | undefined): string => {
    if (!value) return '';
    return value.length > limit ? `${value.slice(0, limit)}\n… truncated at ${limit} bytes` : value;
  };

  const requestHeaderLines = Object.entries(input.requestHeaders)
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
  const responseHeaderLines = Object.entries(input.responseHeaders)
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');

  return [
    `${input.method} ${input.url}`,
    requestHeaderLines,
    '',
    truncate(input.requestBody),
    '',
    '--- response ---',
    `HTTP ${input.status}`,
    responseHeaderLines,
    '',
    truncate(input.responseBody),
  ].join('\n');
}
