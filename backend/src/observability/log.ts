/**
 * FORENSIQ — Structured logging.
 *
 * JSON lines to stdout in production. In dev (NODE_ENV !== 'production')
 * we render pretty colored output. Every log line carries the request id
 * when one is in scope so you can grep traces across the API + worker
 * + downstream tool runs.
 *
 * Why not pino/winston? They're great but for this codebase a 60-line
 * homegrown logger gives us exactly what we need without a dep. Swap in
 * pino later if you want sampling, transports, redaction etc.
 */

import { AsyncLocalStorage } from 'async_hooks';

type Level = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  requestId?: string;
  userId?: string;
  auditId?: string;
  /** Free-form key-value fields */
  [key: string]: unknown;
}

const als = new AsyncLocalStorage<LogContext>();
const IS_PROD = process.env.NODE_ENV === 'production';
const MIN_LEVEL = (process.env.LOG_LEVEL || (IS_PROD ? 'info' : 'debug')) as Level;
const LEVEL_RANK: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

function emit(level: Level, msg: string, fields?: LogContext): void {
  if (LEVEL_RANK[level] < LEVEL_RANK[MIN_LEVEL]) return;
  const ctx = als.getStore() || {};
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...ctx,
    ...fields,
  };

  if (IS_PROD) {
    // One JSON line per log — friendly to Loki/CloudWatch/Datadog
    process.stdout.write(JSON.stringify(entry) + '\n');
  } else {
    const colors = { debug: '\x1b[90m', info: '\x1b[36m', warn: '\x1b[33m', error: '\x1b[31m' };
    const reset = '\x1b[0m';
    const meta = Object.keys(entry).filter(k => !['ts', 'level', 'msg'].includes(k))
      .map(k => `${k}=${JSON.stringify(entry[k as keyof typeof entry])}`)
      .join(' ');
    process.stdout.write(`${colors[level]}[${level.toUpperCase()}]${reset} ${msg}${meta ? ' ' + meta : ''}\n`);
  }
}

export const log = {
  debug: (msg: string, fields?: LogContext) => emit('debug', msg, fields),
  info:  (msg: string, fields?: LogContext) => emit('info',  msg, fields),
  warn:  (msg: string, fields?: LogContext) => emit('warn',  msg, fields),
  error: (msg: string, fields?: LogContext) => emit('error', msg, fields),
};

/**
 * Run a function with the given context populated for all log calls.
 * Used by the express request middleware to attach request id automatically.
 */
export function withContext<T>(ctx: LogContext, fn: () => T): T {
  const merged = { ...(als.getStore() || {}), ...ctx };
  return als.run(merged, fn);
}

/** Update fields on the current context (for example, after auth resolves the user) */
export function setContext(patch: LogContext): void {
  const store = als.getStore();
  if (store) Object.assign(store, patch);
}
