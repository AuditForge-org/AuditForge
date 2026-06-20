/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Echidna runner.
 *
 * Echidna emits results as a sequence of test outcomes — passing properties,
 * failing properties (with the call sequence that broke the invariant),
 * and coverage data.
 *
 * Property failures are the high-value output: they show a concrete
 * sequence of calls that violates an invariant. These map cleanly to
 * NormalizedFinding[] for the consensus engine, though Echidna findings
 * are *standalone* — no other tool can produce a property-violation
 * counterexample, so they're always single-tool findings of high
 * intrinsic confidence (concrete counterexample = proof, not heuristic).
 *
 * Long-running: a default campaign is 50k test calls = several minutes.
 * Worker timeout for Echidna jobs is configured higher than for other tools.
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';
import { NormalizedFinding, SourceLocation } from '../types/finding';
import {
  parseContract,
  generateHarness,
  writeHarnessProject,
  ParsedContract,
} from './harness';

export interface EchidnaResult {
  ok: boolean;
  findings: NormalizedFinding[];
  durationMs: number;
  error?: string;
  campaignStats?: {
    callsExecuted: number;
    coveragePercent?: number;
    propertiesPassed: number;
    propertiesFailed: number;
  };
  generatedHarness?: string;
}

/**
 * Echidna's JSON output shape (echidna v2.2+).
 * The actual shape varies by mode; this captures the property-test outputs.
 */
interface EchidnaJsonOutput {
  success?: boolean;
  error?: string;
  tests: Array<{
    contract: string;
    name: string;
    status: 'passed' | 'failed' | 'error' | 'gas_info' | 'open';
    transactions?: Array<{
      contractAddr: string;
      src: string;
      gas: number;
      gasprice: number;
      value: string;
      callType: 'call' | 'delegatecall';
      call: { tag: string; contents: unknown };
    }>;
    error?: string;
    gas?: number;
  }>;
  campaign?: {
    callsExecuted?: number;
    coveragePercent?: number;
  };
}

function dockerRun(
  args: string[],
  mountDir: string,
  timeoutMs: number,
  memoryMb = 4096
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const dockerArgs = [
      'run', '--rm',
      '--network', 'none',
      // Echidna writes corpus dirs, so we cannot mount read-only.
      // We mount a *dedicated* writable dir for this run, isolated from anything else.
      '--tmpfs', '/tmp:size=256m',
      '--memory', `${memoryMb}m`,
      '--cpus', '2',
      '-v', `${mountDir}:/input`,
      '-w', '/input',
      ...(process.env.ENGINE_CGROUP_PARENT ? ['--cgroup-parent', process.env.ENGINE_CGROUP_PARENT] : []),
      // solc-select's per-user global version is unreliable for the image's
      // non-root user; pin the compiler so crytic-compile (echidna's backend)
      // can resolve solc deterministically.
      '-e', 'SOLC_VERSION=0.8.24',
      'forensiq/echidna:2.2.4',
      ...args,
    ];
    const proc = spawn('docker', dockerArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      proc.kill('SIGKILL');
    }, timeoutMs);

    proc.stdout.on('data', d => stdout += d.toString());
    proc.stderr.on('data', d => stderr += d.toString());

    proc.on('error', err => {
      clearTimeout(timer);
      reject(err);
    });
    proc.on('close', code => {
      clearTimeout(timer);
      if (killed) reject(new Error(`Echidna timed out after ${timeoutMs}ms`));
      else resolve({ stdout, stderr, code: code ?? -1 });
    });
  });
}

/**
 * Translate an Echidna property failure into a NormalizedFinding.
 *
 * The "call sequence" — the actual transactions that triggered the failure —
 * is the gold of fuzzing. We preserve it as text in the description so
 * developers can reproduce.
 */
function normalizeEchidnaOutput(
  output: EchidnaJsonOutput,
  targetFile: string
): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  let idx = 0;

  for (const test of output.tests || []) {
    if (test.status !== 'failed') continue;

    const callTrace = (test.transactions || [])
      .map((tx, i) => {
        const callType = tx.callType || 'call';
        const callTag = tx.call?.tag || 'unknown';
        return `  ${i + 1}. [${callType}] ${callTag} (gas=${tx.gas}, value=${tx.value})`;
      })
      .join('\n');

    const location: SourceLocation = {
      file: targetFile,
      startLine: 0, // Echidna doesn't report a single line — the failure is
                    // a state arrived at via a sequence of calls
    };

    findings.push({
      id: `echidna_${idx++}`,
      tool: 'echidna',
      detectorId: `property_violation:${test.name}`,
      category: categorizeProperty(test.name),
      // Property violations are critical by default — they prove the
      // invariant can be broken with a concrete sequence
      severity: 'critical',
      // High confidence: counterexample is deterministic, not heuristic
      confidence: 'high',
      title: `Invariant violated: ${humanizeProperty(test.name)}`,
      description: [
        `Echidna fuzzing campaign found a call sequence that violates the property "${test.name}" defined on contract ${test.contract}.`,
        '',
        'Counterexample call sequence:',
        callTrace || '  (no transactions recorded)',
        '',
        test.error ? `Error: ${test.error}` : '',
      ].filter(Boolean).join('\n'),
      location,
      recommendation: `Reproduce the call sequence above against ${test.contract}. The state reached at the end of the sequence violates the invariant; identify which call caused the divergence and patch the corresponding function or invariant logic.`,
      raw: test,
    });
  }

  return findings;
}

function humanizeProperty(name: string): string {
  return name
    .replace(/^echidna_/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

function categorizeProperty(name: string): string {
  if (/balance|supply|sum/i.test(name)) return 'accounting';
  if (/owner|auth|role|access/i.test(name)) return 'access-control';
  if (/pause|emergency/i.test(name)) return 'pausability';
  if (/monotonic|counter|nonce/i.test(name)) return 'state-progression';
  if (/contract_exists|destruct/i.test(name)) return 'lifecycle';
  return 'invariant';
}

export interface RunEchidnaOptions {
  /** Timeout for the whole campaign in seconds (default 300) */
  campaignTimeout?: number;
  /** Number of test calls to attempt (default 50000) */
  testLimit?: number;
  /** Specific target contract name to fuzz (default: auto-detected) */
  targetContract?: string;
  /** Skip auto-generated invariants and only run user-provided ones */
  userPropertiesOnly?: boolean;
}

export async function runEchidna(
  code: string,
  opts: RunEchidnaOptions = {}
): Promise<EchidnaResult> {
  const start = Date.now();
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'forensiq-echidna-'));
  await fs.chmod(dir, 0o755);  // engine runs as non-root; widen for /input read

  try {
    // 1. Parse target contract
    const parsed = parseContract(code, opts.targetContract);

    // 2. Generate harness + config
    const { harness, config } = generateHarness(parsed, code);
    await writeHarnessProject(dir, harness, config);

    // 3. Run Echidna
    const timeout = opts.campaignTimeout || 300;
    const { stdout, stderr, code: exitCode } = await dockerRun(
      [
        // The image ENTRYPOINT is `echidna`, so args must NOT repeat it.
        'src/EchidnaHarness.sol',
        '--contract', `Echidna${parsed.name}`,
        '--config', 'echidna.yaml',
        '--test-limit', String(opts.testLimit || 50_000),
        '--timeout', String(timeout),
        '--format', 'json',
      ],
      dir,
      (timeout + 60) * 1000, // grace period over campaign timeout
      6144,
    );

    // Echidna returns non-zero when it finds violations — expected.
    // Failure to start (compilation error, missing target) is what we care about.
    if (exitCode === 1 && !stdout.trim().startsWith('{')) {
      throw new Error(`Echidna setup failed: ${stderr || 'no output'}`);
    }

    // Parse output
    const jsonStart = stdout.indexOf('{');
    if (jsonStart === -1) {
      // No JSON — likely the campaign passed with no violations
      return {
        ok: true,
        findings: [],
        durationMs: Date.now() - start,
        generatedHarness: harness,
        campaignStats: {
          callsExecuted: 0,
          propertiesPassed: 0,
          propertiesFailed: 0,
        },
      };
    }

    const jsonStr = stdout.slice(jsonStart);
    const parsedOutput: EchidnaJsonOutput = JSON.parse(jsonStr);
    const findings = normalizeEchidnaOutput(parsedOutput, 'Contract.sol');

    const stats = {
      callsExecuted: parsedOutput.campaign?.callsExecuted || 0,
      coveragePercent: parsedOutput.campaign?.coveragePercent,
      propertiesPassed: parsedOutput.tests?.filter(t => t.status === 'passed').length || 0,
      propertiesFailed: parsedOutput.tests?.filter(t => t.status === 'failed').length || 0,
    };

    return {
      ok: true,
      findings,
      durationMs: Date.now() - start,
      campaignStats: stats,
      generatedHarness: harness,
    };
  } catch (e) {
    return {
      ok: false,
      findings: [],
      durationMs: Date.now() - start,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}
