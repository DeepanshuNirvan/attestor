/**
 * The part of a piece of text evidence that belongs in a printed report.
 *
 * Evidence is stored whole, and the console shows it whole. Printed whole it ran to several pages of
 * tool JSON per finding — template metadata, every response header, base64 source maps — and the
 * line that proves the finding was lost in it. The report prints the proof and says the full record
 * is kept.
 *
 * Nothing here pattern-matches content. A record that parses as JSON is read by key; anything else
 * is cut by lines and characters.
 */

export interface EvidenceExcerpt {
  text: string;
  /** True when anything was left out, so the report can say the full record is kept elsewhere. */
  clipped: boolean;
}

const MAX_LINES = 40;
const MAX_LINE_CHARS = 160;
/** Most lines taken from one multi-line value, such as a raw response. */
const MAX_BLOCK_LINES = 12;
/** Instances printed from a list, such as the places ZAP saw the same alert. */
const MAX_ITEMS = 3;

/**
 * Keys that describe the target's behaviour rather than the tool, in the order they print. Covers
 * the records the adapters store: nuclei (`matched-at`, `request`, `response`), ZAP (`instances`,
 * `uri`, `param`, `evidence`), httpx (`url`, `status_code`, `raw_header`, `body`) and dnsx (`host`,
 * `status_code`, `txt`). A key not listed is tool metadata and is left out.
 */
const PROOF_KEYS = [
  'matched-at',
  'url',
  'uri',
  'method',
  'param',
  'attack',
  'evidence',
  'otherinfo',
  'host',
  'port',
  'service',
  'status_code',
  'content_type',
  'txt',
  'extracted-results',
  'request',
  'raw_header',
  'response',
  'body',
  'curl-command',
  'instances',
];

/** A record at or under this size is already readable and prints as it is. */
const SHORT_RECORD_LINES = 25;

function clipLine(line: string): { line: string; clipped: boolean } {
  return line.length > MAX_LINE_CHARS
    ? { line: `${line.slice(0, MAX_LINE_CHARS)}…`, clipped: true }
    : { line, clipped: false };
}

function linesOf(value: string): string[] {
  return value.replace(/\r\n/g, '\n').split('\n');
}

interface Output {
  lines: string[];
  clipped: boolean;
}

function push(out: Output, line: string): void {
  const result = clipLine(line);
  out.lines.push(result.line);
  if (result.clipped) out.clipped = true;
}

function pushValue(out: Output, key: string, value: unknown, indent: string): void {
  if (value === null || value === undefined || value === '') return;

  if (typeof value === 'string') {
    const lines = linesOf(value.trimEnd());
    if (lines.length <= 1) {
      push(out, `${indent}${key}: ${lines[0] ?? ''}`);
      return;
    }
    push(out, `${indent}${key}:`);
    for (const line of lines.slice(0, MAX_BLOCK_LINES)) push(out, `${indent}  ${line}`);
    if (lines.length > MAX_BLOCK_LINES) {
      push(out, `${indent}  … ${lines.length - MAX_BLOCK_LINES} more lines`);
      out.clipped = true;
    }
    return;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    push(out, `${indent}${key}: ${String(value)}`);
    return;
  }

  if (Array.isArray(value)) {
    const scalars = value.filter((item) => typeof item !== 'object' || item === null);
    if (scalars.length === value.length) {
      if (value.length > 0) push(out, `${indent}${key}: ${value.map(String).join(', ')}`);
      return;
    }
    value.slice(0, MAX_ITEMS).forEach((item, index) => {
      push(out, `${indent}${key} ${index + 1} of ${value.length}:`);
      pushObject(out, item, `${indent}  `);
    });
    if (value.length > MAX_ITEMS) out.clipped = true;
  }
  // Nested objects (header maps, tool metadata) are left out: the raw header and body carry the same
  // facts in the form the reader can reproduce.
}

function pushObject(out: Output, record: unknown, indent: string): boolean {
  if (typeof record !== 'object' || record === null || Array.isArray(record)) return false;
  const entries = record as Record<string, unknown>;
  let found = false;
  for (const key of PROOF_KEYS) {
    if (!(key in entries)) continue;
    const before = out.lines.length;
    pushValue(out, key, entries[key], indent);
    if (out.lines.length > before) found = true;
  }
  return found;
}

function plainExcerpt(text: string): EvidenceExcerpt {
  const out: Output = { lines: [], clipped: false };
  const lines = linesOf(text.trimEnd());
  for (const line of lines.slice(0, MAX_LINES)) push(out, line);
  if (lines.length > MAX_LINES) out.clipped = true;
  return { text: out.lines.join('\n'), clipped: out.clipped };
}

export function evidenceExcerpt(text: string): EvidenceExcerpt {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return plainExcerpt(text);
  }
  if (typeof parsed !== 'object' || parsed === null) return plainExcerpt(text);

  const pretty = JSON.stringify(parsed, null, 2);
  const prettyLines = pretty.split('\n');
  if (
    prettyLines.length <= SHORT_RECORD_LINES &&
    prettyLines.every((line) => line.length <= MAX_LINE_CHARS)
  ) {
    return { text: pretty, clipped: false };
  }

  const out: Output = { lines: [], clipped: true };
  const records = Array.isArray(parsed) ? parsed : [parsed];
  let found = false;
  records.slice(0, MAX_ITEMS).forEach((record, index) => {
    if (records.length > 1) push(out, `record ${index + 1} of ${records.length}:`);
    if (pushObject(out, record, records.length > 1 ? '  ' : '')) found = true;
  });

  if (!found) return plainExcerpt(pretty);
  if (out.lines.length > MAX_LINES) {
    out.lines = [...out.lines.slice(0, MAX_LINES), '…'];
  }
  return { text: out.lines.join('\n'), clipped: true };
}
