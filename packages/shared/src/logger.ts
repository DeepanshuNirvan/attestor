import { redactValue } from './redaction.ts';

/**
 * Structured JSON logging. Every field is routed through the redaction filter before it is
 * written, including the message, because tool output arrives as a message more often than as a
 * field. There is no unredacted sink and no way to opt out.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LogFields {
  [key: string]: unknown;
}

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(fields: LogFields): Logger;
}

export interface LoggerOptions {
  level?: LogLevel;
  service: string;
  /** Overridable so tests can capture output without touching stdout. */
  write?: (line: string) => void;
}

function defaultWrite(line: string): void {
  process.stdout.write(`${line}\n`);
}

export function createLogger(options: LoggerOptions): Logger {
  const minimum = LEVEL_ORDER[options.level ?? 'info'];
  const write = options.write ?? defaultWrite;

  function emit(level: LogLevel, base: LogFields, message: string, fields?: LogFields): void {
    if (LEVEL_ORDER[level] < minimum) return;
    const record = redactValue({
      time: new Date().toISOString(),
      level,
      service: options.service,
      message,
      ...base,
      ...fields,
    });
    write(JSON.stringify(record));
  }

  function build(base: LogFields): Logger {
    return {
      debug: (message, fields) => emit('debug', base, message, fields),
      info: (message, fields) => emit('info', base, message, fields),
      warn: (message, fields) => emit('warn', base, message, fields),
      error: (message, fields) => emit('error', base, message, fields),
      child: (fields) => build({ ...base, ...fields }),
    };
  }

  return build({});
}
