/**
 * FORENSIQ — Prometheus metrics.
 *
 * Exposes /metrics in the Prometheus text format. We use a tiny
 * homegrown registry instead of prom-client to keep deps minimal.
 * The format is wire-compatible with Prometheus and Grafana.
 *
 * Metrics emitted:
 *   forensiq_http_requests_total{method,path,status}     counter
 *   forensiq_http_request_duration_seconds{method,path}  histogram
 *   forensiq_audits_total{result,trigger}                counter
 *   forensiq_audit_duration_seconds                      histogram
 *   forensiq_engine_runs_total{tool,result}              counter
 *   forensiq_engine_duration_seconds{tool}               histogram
 *   forensiq_queue_jobs{state}                           gauge
 *   forensiq_findings_total{severity,tool_count}         counter
 *
 * Labels are normalized — we don't pass user input (path could be
 * unbounded), so we extract route patterns instead of raw paths.
 */

import { Request, Response, NextFunction } from 'express';

type LabelValues = Record<string, string | number>;

abstract class Metric {
  constructor(public name: string, public help: string, public labelNames: string[] = []) {}
  abstract render(): string;
  protected labelStr(labels: LabelValues): string {
    if (!this.labelNames.length) return '';
    const parts = this.labelNames.map(n => `${n}="${escapeLabel(String(labels[n] ?? ''))}"`);
    return `{${parts.join(',')}}`;
  }
}

function escapeLabel(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function labelsKey(labels: LabelValues, names: string[]): string {
  return names.map(n => labels[n] ?? '').join('|');
}

class Counter extends Metric {
  private values = new Map<string, number>();

  inc(labels: LabelValues = {}, by = 1): void {
    const k = labelsKey(labels, this.labelNames);
    this.values.set(k, (this.values.get(k) || 0) + by);
  }

  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} counter\n`;
    for (const [k, v] of this.values) {
      const labels: LabelValues = {};
      const parts = k.split('|');
      this.labelNames.forEach((n, i) => labels[n] = parts[i]);
      out += `${this.name}${this.labelStr(labels)} ${v}\n`;
    }
    return out;
  }
}

class Gauge extends Metric {
  private values = new Map<string, number>();

  set(labels: LabelValues, val: number): void {
    this.values.set(labelsKey(labels, this.labelNames), val);
  }

  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} gauge\n`;
    for (const [k, v] of this.values) {
      const labels: LabelValues = {};
      const parts = k.split('|');
      this.labelNames.forEach((n, i) => labels[n] = parts[i]);
      out += `${this.name}${this.labelStr(labels)} ${v}\n`;
    }
    return out;
  }
}

class Histogram extends Metric {
  private buckets: number[];
  private observations = new Map<string, { counts: number[]; sum: number; n: number }>();

  constructor(name: string, help: string, labelNames: string[] = [], buckets?: number[]) {
    super(name, help, labelNames);
    this.buckets = buckets || [0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60, 180, 600];
  }

  observe(labels: LabelValues, value: number): void {
    const k = labelsKey(labels, this.labelNames);
    let entry = this.observations.get(k);
    if (!entry) {
      entry = { counts: new Array(this.buckets.length).fill(0), sum: 0, n: 0 };
      this.observations.set(k, entry);
    }
    for (let i = 0; i < this.buckets.length; i++) {
      if (value <= this.buckets[i]) entry.counts[i]++;
    }
    entry.sum += value;
    entry.n++;
  }

  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} histogram\n`;
    for (const [k, entry] of this.observations) {
      const labels: LabelValues = {};
      const parts = k.split('|');
      this.labelNames.forEach((n, i) => labels[n] = parts[i]);
      const baseLabels = { ...labels };
      for (let i = 0; i < this.buckets.length; i++) {
        out += `${this.name}_bucket${this.labelStr({ ...baseLabels, le: this.buckets[i] })} ${entry.counts[i]}\n`;
      }
      out += `${this.name}_bucket${this.labelStr({ ...baseLabels, le: '+Inf' })} ${entry.n}\n`;
      out += `${this.name}_sum${this.labelStr(baseLabels)} ${entry.sum}\n`;
      out += `${this.name}_count${this.labelStr(baseLabels)} ${entry.n}\n`;
    }
    return out;
  }
}

// ─── Registry ────────────────────────────────────────────────────────

const metrics: Metric[] = [];
function register<T extends Metric>(m: T): T { metrics.push(m); return m; }

export const httpRequests = register(new Counter(
  'forensiq_http_requests_total',
  'Total HTTP requests',
  ['method', 'route', 'status']
));

export const httpDuration = register(new Histogram(
  'forensiq_http_request_duration_seconds',
  'HTTP request duration',
  ['method', 'route'],
  [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
));

export const auditsTotal = register(new Counter(
  'forensiq_audits_total',
  'Total audits',
  ['result', 'trigger']
));

export const auditDuration = register(new Histogram(
  'forensiq_audit_duration_seconds',
  'End-to-end audit duration',
  ['trigger'],
  [10, 30, 60, 120, 300, 600, 900]
));

export const engineRuns = register(new Counter(
  'forensiq_engine_runs_total',
  'Tool invocations',
  ['tool', 'result']
));

export const engineDuration = register(new Histogram(
  'forensiq_engine_duration_seconds',
  'Tool invocation duration',
  ['tool'],
  [1, 5, 15, 30, 60, 120, 300, 600]
));

export const queueJobs = register(new Gauge(
  'forensiq_queue_jobs',
  'BullMQ jobs in each state',
  ['state']
));

export const findingsTotal = register(new Counter(
  'forensiq_findings_total',
  'Findings produced (consensus)',
  ['severity', 'tool_count']
));

// ─── Render endpoint ─────────────────────────────────────────────────

export function renderMetrics(): string {
  // Process metrics + custom metrics
  const mem = process.memoryUsage();
  let out = '';
  out += `# HELP forensiq_process_memory_bytes Process memory usage\n# TYPE forensiq_process_memory_bytes gauge\n`;
  out += `forensiq_process_memory_bytes{type="rss"} ${mem.rss}\n`;
  out += `forensiq_process_memory_bytes{type="heap_used"} ${mem.heapUsed}\n`;
  out += `forensiq_process_memory_bytes{type="external"} ${mem.external}\n`;
  out += `# HELP forensiq_process_uptime_seconds Process uptime\n# TYPE forensiq_process_uptime_seconds counter\n`;
  out += `forensiq_process_uptime_seconds ${process.uptime()}\n`;

  for (const m of metrics) out += m.render();
  return out;
}

// ─── HTTP middleware ─────────────────────────────────────────────────

/**
 * Records request count + duration. Uses req.route?.path to label by
 * route pattern (not raw path), so /api/audits/:id rolls up correctly
 * instead of exploding the cardinality.
 */
export function httpMetricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();
  res.on('finish', () => {
    const route = req.route?.path || normalizeRoute(req.path);
    const duration = (Date.now() - start) / 1000;
    httpRequests.inc({ method: req.method, route, status: String(res.statusCode) });
    httpDuration.observe({ method: req.method, route }, duration);
  });
  next();
}

/**
 * Best-effort path → route pattern collapse for handlers we don't have
 * registered via app.use(router).
 */
function normalizeRoute(p: string): string {
  // Collapse UUIDs
  return p.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
          .replace(/0x[a-fA-F0-9]{40}/g, ':address')
          .replace(/\b\d+\b/g, ':n');
}
