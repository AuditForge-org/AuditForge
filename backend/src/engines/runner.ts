/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Engine Runner
 *
 * Each tool runs in its own Docker container for isolation and reproducibility.
 * The contract source is mounted read-only at /input, output is captured from
 * stdout. We never let tools write to the host filesystem.
 *
 * Containers are built ahead of time (see /docker/*.Dockerfile). Their tags:
 *   - forensiq/slither:0.10.4
 *   - forensiq/mythril:0.24.8
 *   - forensiq/aderyn:0.5.5
 *   - forensiq/semgrep:1.85
 *   - forensiq/solhint:5.0.5
 *
 * All runners share a strict timeout, memory limit, and --network none so
 * the analyzed contract can't make outbound calls (defensive against
 * malicious source code that tries to exploit the analyzer).
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';
import { NormalizedFinding, Tool } from '../types/finding';
import { normalizeSlitherOutput } from '../normalizers/slither';
import { normalizeMythrilOutput } from '../normalizers/mythril';
import { normalizeAderynOutput } from '../normalizers/aderyn';
import { normalizeSemgrepOutput, normalizeSolhintOutput } from '../normalizers/semgrep-solhint';
import { runEchidna, RunEchidnaOptions } from '../fuzz/runner';
import { getRuntime, RunSpec } from './runtime';

interface DockerRunOptions {
  image: string;
  args: string[];
  timeoutMs: number;
  memoryMb?: number;
  workdir?: string;
  writable?: boolean;
  env?: Record<string, string>;
}

/**
 * Run a tool image. Delegates to the configured Runtime (docker locally,
 * Kubernetes Jobs in prod). Kept named `runDocker` for backward-compat
 * with the existing callers; semantically it's "run a containerized tool".
 */
function runDocker(opts: DockerRunOptions, mountDir: string): Promise<{ stdout: string; stderr: string; code: number }> {
  const rt = getRuntime();
  const spec: RunSpec = {
    image: opts.image,
    args: opts.args,
    inputDir: mountDir,
    timeoutMs: opts.timeoutMs,
    memoryMb: opts.memoryMb,
    writable: opts.writable,
    env: opts.env,
  };
  return rt.run(spec);
}

export interface RunResult {
  tool: Tool;
  ok: boolean;
  findings: NormalizedFinding[];
  durationMs: number;
  error?: string;
  rawStdout?: string;
}

/**
 * Prepare a temp directory containing the source. Solidity multi-file
 * contracts are expected to come pre-flattened from the source fetcher.
 */
async function prepareWorkdir(code: string, filename = 'Contract.sol'): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'forensiq-'));
  // mkdtemp creates the dir 0700. Engine containers run as a non-root
  // 'auditor' user whose uid need not match ours, so widen to 0755 (the
  // source file is written world-readable) — otherwise the engine cannot
  // traverse into the bind-mounted /input.
  await fs.chmod(dir, 0o755);
  await fs.writeFile(path.join(dir, filename), code, 'utf8');
  return dir;
}

async function cleanup(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

// ─── SLITHER ─────────────────────────────────────────────────────────────

export async function runSlither(code: string, solcVersion = '0.8.24'): Promise<RunResult> {
  const start = Date.now();
  const dir = await prepareWorkdir(code);
  try {
    const { stdout, code: exitCode } = await runDocker({
      image: 'forensiq/slither:0.10.4',
      // The image ENTRYPOINT is `slither`, so args must NOT repeat it.
      args: [
        'Contract.sol',
        '--json', '-',
        '--solc-disable-warnings',
        '--solc-args', `--allow-paths . --base-path /input`,
      ],
      timeoutMs: 90_000,
      memoryMb: 2048,
      env: { SOLC_VERSION: solcVersion },
    }, dir);

    // Slither exits non-zero when it finds issues — that's expected.
    // Exit code 255 or stdout that isn't JSON indicates a real failure.
    if (!stdout || !stdout.trim().startsWith('{')) {
      throw new Error('Slither produced no JSON output');
    }
    const parsed = JSON.parse(stdout);
    const findings = normalizeSlitherOutput(parsed);
    return { tool: 'slither', ok: true, findings, durationMs: Date.now() - start, rawStdout: stdout };
  } catch (e) {
    return {
      tool: 'slither', ok: false, findings: [],
      durationMs: Date.now() - start,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await cleanup(dir);
  }
}

// ─── MYTHRIL ─────────────────────────────────────────────────────────────

export async function runMythril(code: string, solcVersion = '0.8.24'): Promise<RunResult> {
  const start = Date.now();
  const dir = await prepareWorkdir(code);
  try {
    const { stdout } = await runDocker({
      image: 'forensiq/mythril:0.24.8',
      // The image ENTRYPOINT is `myth`, so args must NOT repeat it.
      args: [
        'analyze', 'Contract.sol',
        '-o', 'jsonv2',
        '--solv', solcVersion,
        '-t', '5',       // transaction depth
        '--execution-timeout', '60',
      ],
      timeoutMs: 180_000,  // Mythril is slow; symbolic execution needs time
      memoryMb: 4096,
      env: { SOLC_VERSION: solcVersion },
    }, dir);

    if (!stdout.trim()) throw new Error('Mythril produced no output');
    const parsed = JSON.parse(stdout);
    const findings = normalizeMythrilOutput(parsed, { 'Contract.sol': code });
    return { tool: 'mythril', ok: true, findings, durationMs: Date.now() - start, rawStdout: stdout };
  } catch (e) {
    return {
      tool: 'mythril', ok: false, findings: [],
      durationMs: Date.now() - start,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await cleanup(dir);
  }
}

// ─── ADERYN ──────────────────────────────────────────────────────────────

export async function runAderyn(code: string): Promise<RunResult> {
  const start = Date.now();
  const dir = await prepareWorkdir(code);
  // Aderyn expects a Foundry/Hardhat project layout; we create a minimal one
  await fs.mkdir(path.join(dir, 'src'), { recursive: true });
  await fs.rename(path.join(dir, 'Contract.sol'), path.join(dir, 'src', 'Contract.sol'));
  await fs.writeFile(path.join(dir, 'foundry.toml'),
    `[profile.default]\nsrc = "src"\nout = "out"\n`, 'utf8');

  try {
    // Aderyn writes its report to a FILE (the .json extension selects JSON);
    // stdout only carries status text. So we mount /input writable, point the
    // output there (host-visible via the bind mount), and read the file back.
    // --skip-update-check avoids a network call (the sandbox is --network none,
    // and the image bakes solc into svm so aderyn never needs the network).
    const { stdout, stderr } = await runDocker({
      image: 'forensiq/aderyn:0.5.5',
      // The image ENTRYPOINT is `aderyn`, so args must NOT repeat it.
      args: ['.', '-o', '/input/aderyn.json', '--no-snippets', '--skip-update-check'],
      timeoutMs: 60_000,
      memoryMb: 1024,
      writable: true,
    }, dir);

    let parsed: unknown;
    try {
      parsed = JSON.parse(await fs.readFile(path.join(dir, 'aderyn.json'), 'utf8'));
    } catch {
      throw new Error(`Aderyn produced no JSON report${stderr ? `: ${stderr.slice(0, 200)}` : ''}`);
    }
    const findings = normalizeAderynOutput(parsed as Parameters<typeof normalizeAderynOutput>[0]);
    return { tool: 'aderyn', ok: true, findings, durationMs: Date.now() - start, rawStdout: stdout };
  } catch (e) {
    return {
      tool: 'aderyn', ok: false, findings: [],
      durationMs: Date.now() - start,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await cleanup(dir);
  }
}

// ─── SEMGREP ─────────────────────────────────────────────────────────────

export async function runSemgrep(code: string): Promise<RunResult> {
  const start = Date.now();
  const dir = await prepareWorkdir(code);
  try {
    const { stdout } = await runDocker({
      image: 'forensiq/semgrep:1.85',
      // The image ENTRYPOINT is `semgrep`, so args must NOT repeat it.
      args: [
        'scan',
        // Ruleset is baked into the image (semgrep.Dockerfile) so this runs
        // under --network none; --metrics=off avoids a telemetry call.
        '--config=/opt/semgrep-rules/smart-contracts.yaml',
        '--metrics=off',
        '--json',
        '--quiet',
        '/input',
      ],
      timeoutMs: 60_000,
      memoryMb: 1024,
      // semgrep writes its settings to ~/.semgrep, but the sandbox rootfs is
      // --read-only; point HOME at the writable /tmp tmpfs.
      env: { HOME: '/tmp' },
    }, dir);

    if (!stdout.trim()) throw new Error('Semgrep produced no output');
    const parsed = JSON.parse(stdout);
    const findings = normalizeSemgrepOutput(parsed);
    return { tool: 'semgrep', ok: true, findings, durationMs: Date.now() - start, rawStdout: stdout };
  } catch (e) {
    return {
      tool: 'semgrep', ok: false, findings: [],
      durationMs: Date.now() - start,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await cleanup(dir);
  }
}

// ─── SOLHINT ─────────────────────────────────────────────────────────────

export async function runSolhint(code: string): Promise<RunResult> {
  const start = Date.now();
  const dir = await prepareWorkdir(code);
  // Solhint needs a config; we ship a security-focused one
  const config = {
    extends: 'solhint:recommended',
    rules: {
      'avoid-tx-origin': 'error',
      'avoid-call-value': 'error',
      'avoid-low-level-calls': 'warn',
      'avoid-suicide': 'error',
      'compiler-version': ['error', '^0.8.0'],
      'no-inline-assembly': 'warn',
      'reentrancy': 'error',
    },
  };
  await fs.writeFile(path.join(dir, '.solhint.json'), JSON.stringify(config), 'utf8');

  try {
    const { stdout } = await runDocker({
      image: 'forensiq/solhint:5.0.5',
      // The image ENTRYPOINT is `solhint`, so args must NOT repeat it.
      args: ['-f', 'json', 'Contract.sol'],
      timeoutMs: 30_000,
      memoryMb: 512,
    }, dir);

    // Solhint exits non-zero when findings exist; empty stdout means clean.
    if (!stdout.trim()) {
      return { tool: 'solhint', ok: true, findings: [], durationMs: Date.now() - start };
    }
    const parsed = JSON.parse(stdout);
    const findings = normalizeSolhintOutput(parsed);
    return { tool: 'solhint', ok: true, findings, durationMs: Date.now() - start, rawStdout: stdout };
  } catch (e) {
    return {
      tool: 'solhint', ok: false, findings: [],
      durationMs: Date.now() - start,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await cleanup(dir);
  }
}

// ─── ORCHESTRATOR ────────────────────────────────────────────────────────

export interface OrchestrationOptions {
  enabledTools?: Tool[];
  solcVersion?: string;
  /** Echidna is opt-in by default — it's slow (minutes) and noisy. */
  enableFuzzing?: boolean;
  fuzzOptions?: RunEchidnaOptions;
}

/**
 * Run all enabled tools in parallel. Each tool gets its own container,
 * isolated. Failures in one tool don't block the others.
 *
 * Echidna is special: it's only run when explicitly enabled because it
 * takes minutes (vs seconds for static tools). When enabled, it still
 * runs in parallel with the others — its results land in the same
 * NormalizedFinding pipeline and feed the consensus engine.
 */
export async function runAllTools(
  code: string,
  opts: OrchestrationOptions = {}
): Promise<RunResult[]> {
  const enabled = opts.enabledTools || ['slither', 'aderyn', 'mythril', 'semgrep', 'solhint'];
  const solcVersion = opts.solcVersion || '0.8.24';

  const tasks: Array<Promise<RunResult>> = [];
  if (enabled.includes('slither')) tasks.push(runSlither(code, solcVersion));
  if (enabled.includes('aderyn'))  tasks.push(runAderyn(code));
  if (enabled.includes('mythril')) tasks.push(runMythril(code, solcVersion));
  if (enabled.includes('semgrep')) tasks.push(runSemgrep(code));
  if (enabled.includes('solhint')) tasks.push(runSolhint(code));

  // Echidna: opt-in, separately controlled because of cost
  if (enabled.includes('echidna') || opts.enableFuzzing) {
    tasks.push(
      runEchidna(code, opts.fuzzOptions).then(r => ({
        tool: 'echidna' as Tool,
        ok: r.ok,
        findings: r.findings,
        durationMs: r.durationMs,
        error: r.error,
      }))
    );
  }

  return Promise.all(tasks);
}
