/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * AI auditor brief.
 *
 * Sends the contract source + consensus findings to an LLM acting as a senior
 * auditor: it flags what the static engines may have missed (business-logic
 * bugs, oracle/economic exploits), prioritizes the findings, and calls out
 * likely false positives. The brief is a sidebar to the report, not the report.
 *
 * Provider-agnostic: talks to any OpenAI-compatible /chat/completions endpoint,
 * selected entirely via env vars. Defaults to Groq's free tier. Examples:
 *   Groq:       AI_BASE_URL=https://api.groq.com/openai/v1                 AI_MODEL=llama-3.3-70b-versatile
 *   OpenRouter: AI_BASE_URL=https://openrouter.ai/api/v1                   AI_MODEL=deepseek/deepseek-r1:free
 *   Gemini:     AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai  AI_MODEL=gemini-2.0-flash
 *   Ollama:     AI_BASE_URL=http://host.docker.internal:11434/v1           AI_MODEL=qwen2.5-coder:7b   (AI_API_KEY=ollama)
 *
 * If no AI_API_KEY is configured, generateAiBrief throws and the worker simply
 * skips the brief (the audit still completes — see worker.ts).
 */

import { ConsensusFinding } from '../types/finding';

const BASE_URL = (process.env.AI_BASE_URL || 'https://api.groq.com/openai/v1').replace(/\/+$/, '');
const API_KEY = process.env.AI_API_KEY || process.env.GROQ_API_KEY || '';
const MODEL = process.env.AI_MODEL || 'llama-3.3-70b-versatile';
const TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 45_000);
const MAX_CODE_CHARS = 32_000;

interface ChatCompletion {
  choices?: Array<{ message?: { content?: string } }>;
  error?: { message?: string };
}

function summarizeFinding(c: ConsensusFinding): string {
  const tools = c.tools.join('+');
  const loc = `${c.location.file}:${c.location.startLine}`;
  return `- [${c.severity.toUpperCase()} | ${tools} | ${loc}] ${c.title}`;
}

export async function generateAiBrief(
  code: string,
  consensus: ConsensusFinding[]
): Promise<string> {
  if (!API_KEY) {
    throw new Error('AI brief disabled: no AI_API_KEY configured');
  }

  const findingsList = consensus.length
    ? consensus.map(summarizeFinding).join('\n')
    : '(no consensus findings)';

  const truncatedCode = code.length > MAX_CODE_CHARS
    ? code.slice(0, MAX_CODE_CHARS) + '\n\n// [truncated for brevity]'
    : code;

  const prompt = `You are a senior smart contract security auditor reviewing the output of automated tools. Provide a concise senior-auditor brief.

CONSENSUS FINDINGS FROM AUTOMATED TOOLS (Slither, Aderyn, Mythril, Semgrep, Solhint):
${findingsList}

CONTRACT SOURCE:
\`\`\`solidity
${truncatedCode}
\`\`\`

Write a 4-paragraph brief covering:

1. OVERALL ASSESSMENT — Contract purpose, design pattern, overall risk posture (2-3 sentences).

2. CONSENSUS VALIDATION — Of the findings above, which ones are most likely true positives based on your read of the code, and which might be false positives? Be specific (cite finding numbers or titles).

3. WHAT THE TOOLS MISSED — Identify up to 3 issues the automated tools could not have caught: business logic flaws, oracle/MEV exposure, economic exploits, access-control gaps, upgrade-path risks. Name specific functions and variables.

4. REMEDIATION PRIORITY — The single highest-priority fix, and why it must come first.

Be terse, technical, direct. No markdown headers, no bullet symbols, no preamble like "Here is the brief." Plain prose paragraphs only.`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let data: ChatCompletion;
  try {
    const res = await fetch(`${BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1500,
        temperature: 0.3,
        messages: [{ role: 'user', content: prompt }],
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`AI brief HTTP ${res.status} from ${BASE_URL}: ${detail.slice(0, 300)}`);
    }
    data = (await res.json()) as ChatCompletion;
  } finally {
    clearTimeout(timer);
  }

  const text = (data.choices?.[0]?.message?.content || '').trim();
  return text || '(AI brief unavailable)';
}
