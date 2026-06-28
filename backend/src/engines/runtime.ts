/**
 * FORENSIQ — Engine runtime abstraction.
 *
 * In dev (docker-compose), the worker shells out `docker run` against the
 * host daemon. In Kubernetes that's impossible (no Docker socket inside
 * pods, and mounting it would be a sandbox escape).
 *
 * The Runtime interface hides that difference. Pick a backend at startup:
 *   - 'docker'     : local Docker daemon (dev, single-host)
 *   - 'kubernetes' : create a Job per audit step (prod)
 *
 * Both honor the same constraints: read-only filesystem, no network,
 * memory cap, CPU cap, timeout, and a writable scratch tmpfs.
 *
 * Echidna needs a writable corpus dir; we pass writable: true and the
 * runtime allocates an ephemeral writable volume instead of read-only.
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface RunSpec {
  /** Image reference. Always digest-pinned in prod (e.g. forensiq/slither@sha256:...) */
  image: string;
  args: string[];
  /** Input directory on the host (will be mounted at /input) */
  inputDir: string;
  /** Process timeout in ms; runtime kills the container after */
  timeoutMs: number;
  memoryMb?: number;
  cpus?: number;
  /** Allow writes to /input (default false). Echidna needs true for corpus. */
  writable?: boolean;
  /** stdin to feed; rarely used (most engines take a file path arg) */
  stdin?: string;
  /** Extra env vars for the container (e.g. SOLC_VERSION). solc-select's
   *  per-user global version is unreliable for the image's non-root 'auditor'
   *  user, so passing SOLC_VERSION explicitly makes solc resolve. */
  env?: Record<string, string>;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
}

export interface Runtime {
  run(spec: RunSpec): Promise<RunResult>;
  /** Returns a human-readable name for logs/metrics */
  name(): string;
}

// ─── Docker backend (dev / single-host) ──────────────────────────────

class DockerRuntime implements Runtime {
  name() { return 'docker'; }

  /**
   * Detached lifecycle: `docker run -d` (create+start) → `docker wait`
   * (block on exit) → `docker logs` (batch-retrieve output) → `docker rm`.
   *
   * Why not foreground `docker run` with an attached stream? The attach is a
   * hijacked, bidirectional HTTP stream. A locked-down docker-socket-proxy
   * (which only permits discrete create/start/wait/logs/rm calls) can't tunnel
   * it, so foreground runs hang behind the proxy. The detached lifecycle uses
   * only proxy-able calls, letting the worker talk to a restricted proxy
   * instead of mounting the raw host socket — closing the container-escape gap.
   *
   * Bonus: the timeout now kills the *container* (via `docker kill`), not just
   * the local `docker` client, which the old foreground path left racy.
   */
  async run(spec: RunSpec): Promise<RunResult> {
    const mount = spec.writable ? `${spec.inputDir}:/input` : `${spec.inputDir}:/input:ro`;
    // NOTE: no `--rm` — the container must outlive its exit so we can read its
    // logs and exit code; we remove it explicitly in the finally block.
    const runArgs = [
      'run', '-d',
      '--network', 'none',
      ...(spec.writable ? [] : ['--read-only']),
      '--tmpfs', '/tmp:size=256m',
      '--memory', `${spec.memoryMb || 1024}m`,
      '--cpus', String(spec.cpus || 1.5),
      '-v', mount,
      '-w', '/input',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      // Parent the spawned engine container under a host cgroup/slice when
      // configured (ENGINE_CGROUP_PARENT), so it shares the host's resource
      // ceiling instead of running unbounded outside it.
      ...(process.env.ENGINE_CGROUP_PARENT ? ['--cgroup-parent', process.env.ENGINE_CGROUP_PARENT] : []),
      ...Object.entries(spec.env || {}).flatMap(([k, v]) => ['-e', `${k}=${v}`]),
      spec.image,
      ...spec.args,
    ];
    if (spec.stdin) {
      // No caller uses stdin today; detached run can't feed it. Fail loudly
      // rather than silently dropping input if that ever changes.
      throw new Error('DockerRuntime: spec.stdin is not supported in detached mode');
    }

    // 1) Create + start, detached. Fast — returns the container id on stdout.
    const started = await execDocker(runArgs, 60_000);
    if (started.code !== 0) {
      throw new Error(`docker run failed (${started.code}): ${(started.stderr || started.stdout).trim().slice(0, 500)}`);
    }
    const id = started.stdout.trim().split(/\s+/).pop() || '';
    if (!/^[0-9a-f]{12,64}$/i.test(id)) {
      throw new Error(`docker run did not return a container id: ${started.stdout.trim().slice(0, 200)}`);
    }

    try {
      // 2) Block until the container exits, killing it if it overruns.
      const { code, timedOut } = await waitContainer(id, spec.timeoutMs);
      // 3) Batch-retrieve logs. Without a TTY, the CLI demuxes the container's
      //    stdout/stderr onto its own stdout/stderr, so the split is preserved.
      const logs = await execDocker(['logs', id], 30_000);
      if (timedOut) throw new Error(`Tool timed out after ${spec.timeoutMs}ms`);
      return { stdout: logs.stdout, stderr: logs.stderr, code };
    } finally {
      // 4) Remove the container (best-effort; we dropped --rm).
      await execDocker(['rm', '-f', id], 15_000).catch(() => {});
    }
  }
}

/** Spawn `docker <args>`, buffer stdout/stderr, hard-kill after timeoutMs. */
function execDocker(args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', killed = false;
    const timer = setTimeout(() => { killed = true; proc.kill('SIGKILL'); }, timeoutMs);
    proc.stdout!.on('data', d => stdout += d.toString());
    proc.stderr!.on('data', d => stderr += d.toString());
    proc.on('error', err => { clearTimeout(timer); reject(err); });
    proc.on('close', code => {
      clearTimeout(timer);
      if (killed) return reject(new Error(`docker ${args[0]} timed out after ${timeoutMs}ms`));
      resolve({ stdout, stderr, code: code ?? -1 });
    });
  });
}

/**
 * `docker wait <id>` blocks until the container exits and prints its exit code
 * on stdout. We bound it with our own timer; on overrun we `docker kill` the
 * container (which unblocks the wait) and report timedOut. Resolves rather than
 * rejects on timeout so the caller can still read partial logs + clean up.
 */
function waitContainer(id: string, timeoutMs: number): Promise<{ code: number; timedOut: boolean }> {
  return new Promise((resolve, reject) => {
    const proc = spawn('docker', ['wait', id], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      spawn('docker', ['kill', id], { stdio: 'ignore' });  // unblock wait; ignore errors
    }, timeoutMs);
    proc.stdout!.on('data', d => out += d.toString());
    proc.on('error', err => { clearTimeout(timer); reject(err); });
    proc.on('close', () => {
      clearTimeout(timer);
      const code = parseInt(out.trim().split(/\s+/).pop() || '', 10);
      resolve({ code: Number.isFinite(code) ? code : -1, timedOut });
    });
  });
}

// ─── Kubernetes backend (prod) ───────────────────────────────────────

/**
 * Kubernetes Job runtime.
 *
 * Each engine invocation creates a Job in the same namespace as the worker.
 * The Job mounts an ephemeral PVC populated with the input via an initContainer
 * (rsync from the worker pod's local dir through a shared volume claim).
 *
 * Why Jobs and not Pods directly?
 *   - Jobs handle backoff, completion semantics, garbage collection
 *   - Failure mode is well-defined (job.status.failed)
 *   - kubectl logs job/X just works
 *
 * Why no shared PVC for input? We use a different strategy: the worker
 * BASE64-encodes the input source and passes it via an env var to the
 * Job (Kubernetes envs max out at ~1MB; ours are well under that for
 * flattened Solidity files). The Job's entrypoint decodes it on startup.
 *
 * This avoids the complexity of provisioning per-audit volumes while
 * keeping the input ephemeral. For inputs >1MB we fall back to a
 * ConfigMap (~1MiB limit) or S3 object reference; not implemented yet.
 *
 * NOTE: this is the production-shaped scaffold. The actual @kubernetes/client-node
 * call is encapsulated; you can swap in the real client without changing
 * any caller code.
 */
class KubernetesRuntime implements Runtime {
  private namespace: string;
  private serviceAccount: string;

  constructor() {
    this.namespace = process.env.K8S_JOB_NAMESPACE || 'forensiq';
    this.serviceAccount = process.env.K8S_JOB_SERVICE_ACCOUNT || 'forensiq-engine-runner';
  }

  name() { return 'kubernetes'; }

  async run(spec: RunSpec): Promise<RunResult> {
    const { KubeConfig, BatchV1Api, CoreV1Api } = await loadKubernetesClient();

    const kc = new KubeConfig();
    kc.loadFromDefault();
    interface BatchClient {
      createNamespacedJob(ns: string, body: unknown): Promise<unknown>;
      deleteNamespacedJob(name: string, ns: string, ...rest: unknown[]): Promise<unknown>;
    }
    interface CoreClient {
      readNamespacedPodLog(name: string, ns: string, container: string): Promise<{ body: string }>;
      listNamespacedPod(ns: string, ...rest: unknown[]): Promise<{ body: { items: K8sPod[] } }>;
    }
    const batch = kc.makeApiClient(BatchV1Api) as BatchClient;
    const core = kc.makeApiClient(CoreV1Api) as CoreClient;

    const inputArchive = await tarGzipDir(spec.inputDir);
    const inputB64 = inputArchive.toString('base64');
    const jobName = `forensiq-engine-${Math.random().toString(36).slice(2, 12)}`;

    const job = buildJobManifest({
      name: jobName,
      namespace: this.namespace,
      serviceAccount: this.serviceAccount,
      image: spec.image,
      args: spec.args,
      memoryMb: spec.memoryMb || 1024,
      cpus: spec.cpus || 1.5,
      timeoutMs: spec.timeoutMs,
      writable: spec.writable || false,
      inputB64,
    });

    await batch.createNamespacedJob(this.namespace, job);

    try {
      const pod = await waitForPodAndCompletion(batch, core, this.namespace, jobName, spec.timeoutMs);
      // Read logs from the engine container
      const logs = await core.readNamespacedPodLog(
        pod.metadata!.name!, this.namespace, 'engine'
      );
      const status = pod.status?.containerStatuses?.find(c => c.name === 'engine');
      const exitCode = status?.state?.terminated?.exitCode ?? -1;

      return {
        stdout: typeof logs.body === 'string' ? logs.body : '',
        stderr: '',  // K8s merges stdout+stderr into the log stream
        code: exitCode,
      };
    } finally {
      // Best-effort cleanup; the TTL controller will also reap completed jobs
      try {
        await batch.deleteNamespacedJob(jobName, this.namespace, undefined, undefined, 0, undefined, 'Background');
      } catch (e) {
        console.warn(`[k8s-runtime] could not delete job ${jobName}:`, (e as Error).message);
      }
    }
  }
}

// ─── Helper: tar+gzip a directory for transport in env var ───────────

async function tarGzipDir(dir: string): Promise<Buffer> {
  // We avoid pulling tar as a dep by shelling out — same machine has it
  return new Promise((resolve, reject) => {
    const proc = spawn('tar', ['-czf', '-', '-C', dir, '.'], { stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks: Buffer[] = [];
    proc.stdout.on('data', c => chunks.push(c));
    proc.on('error', reject);
    proc.on('close', code => code === 0 ? resolve(Buffer.concat(chunks)) : reject(new Error(`tar failed: ${code}`)));
  });
}

// ─── K8s client lazy loader ──────────────────────────────────────────

interface K8sBindings {
  KubeConfig: new () => {
    loadFromDefault(): void;
    makeApiClient(api: unknown): unknown;
  };
  BatchV1Api: unknown;
  CoreV1Api: unknown;
  V1Job: unknown;
}

let k8sBindings: K8sBindings | null = null;

async function loadKubernetesClient(): Promise<K8sBindings> {
  if (k8sBindings) return k8sBindings;
  try {
    // Dynamic import — @kubernetes/client-node is an optional dep
    const mod = await import('@kubernetes/client-node' as string);
    k8sBindings = mod as unknown as K8sBindings;
    return k8sBindings;
  } catch (e) {
    throw new Error(
      '@kubernetes/client-node is not installed but ENGINE_RUNTIME=kubernetes is set. ' +
      'Install with: npm i @kubernetes/client-node'
    );
  }
}

// ─── Job manifest builder ────────────────────────────────────────────

function buildJobManifest(opts: {
  name: string;
  namespace: string;
  serviceAccount: string;
  image: string;
  args: string[];
  memoryMb: number;
  cpus: number;
  timeoutMs: number;
  writable: boolean;
  inputB64: string;
}): unknown {
  // The Pod has two containers:
  //   - 'unpack' (init): decodes inputB64 from env, writes to /work/input
  //   - 'engine': runs the tool against /work/input
  // /work is an emptyDir, shared between init and main.
  return {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: {
      name: opts.name,
      namespace: opts.namespace,
      labels: { 'app.kubernetes.io/name': 'forensiq-engine', 'app.kubernetes.io/component': 'engine-runner' },
    },
    spec: {
      backoffLimit: 0,
      ttlSecondsAfterFinished: 300,
      activeDeadlineSeconds: Math.ceil(opts.timeoutMs / 1000) + 30,
      template: {
        spec: {
          restartPolicy: 'Never',
          serviceAccountName: opts.serviceAccount,
          // Engine pods should not have access to the K8s API or anything else
          automountServiceAccountToken: false,
          // Hard network isolation: NetworkPolicy denies all egress (configured in k8s/networkpolicy.yaml)
          // The image entrypoint cannot reach the internet to exfiltrate code.
          securityContext: {
            runAsNonRoot: true,
            runAsUser: 1000,
            fsGroup: 1000,
            seccompProfile: { type: 'RuntimeDefault' },
          },
          initContainers: [{
            name: 'unpack',
            image: 'docker.io/busybox:1.36',
            command: ['/bin/sh', '-c'],
            args: [`echo "$INPUT_B64" | base64 -d | tar -xzf - -C /work/input`],
            env: [
              { name: 'INPUT_B64', value: opts.inputB64 },
            ],
            volumeMounts: [{ name: 'work', mountPath: '/work' }],
            securityContext: {
              readOnlyRootFilesystem: true,
              allowPrivilegeEscalation: false,
              capabilities: { drop: ['ALL'] },
            },
          }],
          containers: [{
            name: 'engine',
            image: opts.image,
            args: opts.args,
            workingDir: '/work/input',
            resources: {
              limits: { memory: `${opts.memoryMb}Mi`, cpu: String(opts.cpus) },
              requests: { memory: `${Math.floor(opts.memoryMb / 2)}Mi`, cpu: String(opts.cpus / 2) },
            },
            volumeMounts: [
              {
                name: 'work',
                mountPath: '/work/input',
                readOnly: !opts.writable,
              },
              { name: 'tmp', mountPath: '/tmp' },
            ],
            securityContext: {
              readOnlyRootFilesystem: true,
              allowPrivilegeEscalation: false,
              capabilities: { drop: ['ALL'] },
            },
          }],
          volumes: [
            {
              name: 'work',
              emptyDir: { sizeLimit: '512Mi' },
            },
            {
              name: 'tmp',
              emptyDir: { sizeLimit: '256Mi', medium: 'Memory' },
            },
          ],
        },
      },
    },
  };
}

// ─── K8s polling helper ──────────────────────────────────────────────

interface K8sPod {
  metadata?: { name?: string };
  status?: { containerStatuses?: Array<{ name: string; state?: { terminated?: { exitCode?: number } } }> };
}

async function waitForPodAndCompletion(
  batch: unknown,
  core: unknown,
  ns: string,
  jobName: string,
  timeoutMs: number
): Promise<K8sPod> {
  const deadline = Date.now() + timeoutMs + 60_000;
  const corev1 = core as { listNamespacedPod: (n: string, ..._rest: unknown[]) => Promise<{ body: { items: K8sPod[] } }> };

  // Poll job status; the K8s informer pattern is more efficient at scale,
  // but for a per-audit one-shot the polling cost is negligible.
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 1500));
    const podList = await corev1.listNamespacedPod(
      ns, undefined, undefined, undefined, undefined, `job-name=${jobName}`
    );
    const pods = podList.body.items;
    if (pods.length === 0) continue;
    const pod = pods[0];
    const engineStatus = pod.status?.containerStatuses?.find(c => c.name === 'engine');
    if (engineStatus?.state?.terminated) return pod;
  }
  throw new Error(`K8s job ${jobName} did not complete within deadline`);
}

// ─── Factory ─────────────────────────────────────────────────────────

let _runtime: Runtime | null = null;

export function getRuntime(): Runtime {
  if (_runtime) return _runtime;
  const kind = process.env.ENGINE_RUNTIME || 'docker';
  switch (kind) {
    case 'docker':     _runtime = new DockerRuntime(); break;
    case 'kubernetes': _runtime = new KubernetesRuntime(); break;
    default: throw new Error(`Unknown ENGINE_RUNTIME: ${kind}`);
  }
  console.log(`[runtime] using ${_runtime.name()} engine runtime`);
  return _runtime;
}

// ─── Test helper ─────────────────────────────────────────────────────

/** Override the runtime (used by tests) */
export function _setRuntime(rt: Runtime): void { _runtime = rt; }
