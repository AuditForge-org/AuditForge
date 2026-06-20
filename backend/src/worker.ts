/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Audit Worker
 *
 * Consumes jobs from the BullMQ `audits` queue, runs all configured engines
 * in parallel via the runner, builds consensus, persists the report.
 *
 * Concurrency is set conservatively (2) because each job spins up multiple
 * Docker containers and can consume significant memory. In production tune
 * to your worker host's resources.
 */

import { Worker, Job } from 'bullmq';
import IORedis from 'ioredis';
import { runAllTools } from './engines/runner';
import { buildConsensus, calculateScore } from './consensus/engine';
import { saveReport, getReport } from './db/reports';
import { generateAiBrief } from './ai/brief';
import { AuditReport, Tool } from './types/finding';
import {
  getWatchedProject,
  updateRunStatus,
  getLatestCompletedRun,
} from './db/watched';
import { notifyWatchRun } from './webhooks/notify';
import { fetchGithubSource } from './source/github';
import { fetchEtherscanSource } from './source/etherscan';
import { completeCheckRun, failCheckRun, upsertPrComment } from './github/checks';
import { isConfigured as ghAppConfigured } from './github/auth';
import { archiveAudit } from './storage/s3';
import { log, withContext } from './observability/log';
import { auditsTotal, auditDuration, engineRuns, engineDuration, findingsTotal } from './observability/metrics';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CONCURRENCY = parseInt(process.env.WORKER_CONCURRENCY || '2', 10);
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:3000';

const connection = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });

interface GithubContext {
  installationId: number;
  owner: string;
  repo: string;
  headSha: string;
  checkRunId?: number;
  prNumber?: number;
}

interface AuditJobData {
  auditId: string;
  /** Source code if pre-fetched; if empty, worker will fetch from source.* */
  code: string;
  source: AuditReport['source'];
  tools?: Tool[];
  solcVersion?: string;
  enableFuzzing?: boolean;
  /** Forensiq user id of the submitter (undefined for anonymous) */
  ownerId?: string;
  /** Set when this audit was triggered by a watched-project webhook */
  watchedRunId?: string;
  watchedProjectId?: string;
  /** Set when triggered by the GitHub App (push or PR) */
  github?: GithubContext;
}

const worker = new Worker<AuditJobData>(
  'audits',
  async (job: Job<AuditJobData>) => {
    const start = Date.now();
    const {
      auditId, source, tools, solcVersion, enableFuzzing, ownerId,
      watchedRunId, watchedProjectId, github,
    } = job.data;
    let { code } = job.data;

    if (watchedRunId) {
      await updateRunStatus(watchedRunId, 'running', { auditId });
    }

    try {
      // Lazy fetch when code wasn't provided (webhook trigger)
      if (!code || code.length < 20) {
        await job.updateProgress({ stage: 'fetching', progress: 5 });
        if (source.type === 'github') {
          const fetched = await fetchGithubSource(source.repo!, source.path, source.ref);
          code = fetched.flattenedSource;
        } else if (source.type === 'address') {
          const fetched = await fetchEtherscanSource(source.address!, source.chain!);
          code = fetched.flattenedSource;
        } else {
          throw new Error('Job has no code and source type does not support fetching');
        }
      }

      await job.updateProgress({ stage: 'analyzing', progress: 10 });
      const results = await runAllTools(code, {
        enabledTools: tools, solcVersion, enableFuzzing,
      });

      await job.updateProgress({ stage: 'consensus', progress: 70 });
      const rawFindings = results.flatMap(r => r.findings);
      const toolsRun = results.filter(r => r.ok).map(r => r.tool);
      const toolErrors = results.filter(r => !r.ok).map(r => ({
        tool: r.tool,
        error: r.error || 'unknown',
      }));
      const consensus = buildConsensus(rawFindings);
      const { score, grade } = calculateScore(consensus);

      await job.updateProgress({ stage: 'ai', progress: 85 });
      let aiBrief: string | undefined;
      try { aiBrief = await generateAiBrief(code, consensus); }
      catch (e) { console.warn('[worker] AI brief failed:', e); }

      await job.updateProgress({ stage: 'persisting', progress: 95 });

      const report: AuditReport = {
        id: auditId,
        createdAt: new Date().toISOString(),
        ownerId,
        source,
        contract: { code, lines: code.split('\n').length, solcVersion },
        toolsRun, toolErrors,
        rawFindings,
        consensusFindings: consensus,
        score, grade, aiBrief,
        durationMs: Date.now() - start,
      };

      await saveReport(report);

      // ─── S3 archival (best-effort; no-op if S3_REPORTS_BUCKET unset) ─
      // We don't await this on the critical path. If S3 is down, the
      // audit still completes — Postgres is the source of truth.
      archiveAudit({
        auditId,
        reportJson: report,
        rawByTool: Object.fromEntries(results.map(r => [r.tool, r.findings])),
      }).then(uris => {
        if (Object.keys(uris).length) {
          console.log(`[worker] archived ${auditId} → S3: ${Object.keys(uris).join(', ')}`);
        }
      }).catch(e => {
        console.warn('[worker] S3 archive failed:', (e as Error).message);
      });

      // ─── Metrics ────────────────────────────────────────────────
      const trigger = github ? (github.prNumber ? 'pr' : 'push') : (watchedRunId ? 'watch' : 'manual');
      auditsTotal.inc({ result: 'success', trigger });
      auditDuration.observe({ trigger }, (Date.now() - start) / 1000);
      for (const r of results) {
        engineRuns.inc({ tool: r.tool, result: r.ok ? 'success' : 'error' });
        engineDuration.observe({ tool: r.tool }, r.durationMs / 1000);
      }
      for (const f of consensus) {
        findingsTotal.inc({
          severity: f.severity,
          tool_count: String(Math.min(f.toolCount, 6)),
        });
      }

      // ─── Watched run delta + notify ────────────────────────────────
      let scoreDelta: number | undefined;
      let findingsDelta: number | undefined;
      if (watchedProjectId) {
        try {
          const previous = await getLatestCompletedRun(watchedProjectId);
          if (previous?.auditId) {
            const prev = await getReport(previous.auditId);
            if (prev) {
              scoreDelta = report.score - prev.score;
              findingsDelta = report.consensusFindings.length - prev.consensusFindings.length;
            }
          }
          if (watchedRunId) {
            await updateRunStatus(watchedRunId, 'complete', {
              auditId, scoreDelta, findingsDelta,
            });
          }
          const project = await getWatchedProject(watchedProjectId);
          if (project) {
            await notifyWatchRun(project, {
              id: watchedRunId!, projectId: watchedProjectId, auditId,
              createdAt: new Date().toISOString(),
              commitSha: source.ref || 'unknown',
              scoreDelta, findingsDelta, status: 'complete',
            } as Parameters<typeof notifyWatchRun>[1], report);
          }
        } catch (e) {
          console.warn('[worker] watched run post-processing failed:', e);
        }
      }

      // ─── GitHub App: update check run + PR comment ─────────────────
      if (github && ghAppConfigured()) {
        const detailsUrl = `${PUBLIC_URL}/r/${auditId}`;
        try {
          if (github.checkRunId) {
            await completeCheckRun({
              installationId: github.installationId,
              owner: github.owner,
              repo: github.repo,
              checkRunId: github.checkRunId,
              report,
              detailsUrl,
              scoreDelta,
            });
          }
          if (github.prNumber) {
            await upsertPrComment({
              installationId: github.installationId,
              owner: github.owner,
              repo: github.repo,
              prNumber: github.prNumber,
              report,
              detailsUrl,
              scoreDelta,
            });
          }
        } catch (e) {
          console.warn('[worker] GitHub App update failed:', (e as Error).message);
        }
      }

      await job.updateProgress({ stage: 'complete', progress: 100 });
      return { id: auditId };
    } catch (err) {
      // Failure path: report back to GitHub if we have context
      if (github?.checkRunId && ghAppConfigured()) {
        try {
          await failCheckRun({
            installationId: github.installationId,
            owner: github.owner,
            repo: github.repo,
            checkRunId: github.checkRunId,
            reason: (err as Error).message,
          });
        } catch {}
      }
      throw err;
    }
  },
  {
    connection,
    concurrency: CONCURRENCY,
    lockDuration: 600_000,
  }
);

worker.on('completed', (job, result) => {
  console.log(`[worker] completed ${job.id} → report ${result.id}`);
  const trigger = job.data.watchedRunId ? 'webhook' : 'manual';
  const durSec = ((job.finishedOn || Date.now()) - (job.processedOn || Date.now())) / 1000;
  auditsTotal.inc({ result: 'success', trigger });
  auditDuration.observe({ trigger }, durSec);
});
worker.on('failed', async (job, err) => {
  console.error(`[worker] failed ${job?.id}:`, err.message);
  const trigger = job?.data.watchedRunId ? 'webhook' : 'manual';
  const durSec = ((job?.finishedOn || Date.now()) - (job?.processedOn || Date.now())) / 1000;
  auditsTotal.inc({ result: 'failure', trigger });
  auditDuration.observe({ trigger }, durSec);
  if (job?.data?.watchedRunId) {
    try { await updateRunStatus(job.data.watchedRunId, 'failed'); } catch {}
  }
});

console.log(`[forensiq-worker] consuming queue 'audits' (concurrency=${CONCURRENCY})`);

process.on('SIGTERM', async () => {
  console.log('[forensiq-worker] shutting down');
  await worker.close();
  await connection.quit();
  process.exit(0);
});
