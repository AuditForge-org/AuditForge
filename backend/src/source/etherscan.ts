/**
 * Etherscan-family source fetcher.
 *
 * Verified contracts can be retrieved via the explorer's V2 multichain API
 * (or chain-specific V1). We support several chains; new ones just need
 * an entry in CHAIN_CONFIG.
 *
 * The API returns either a single source file or a "standard JSON input"
 * object containing multiple files. We normalize both to a single
 * flattened string for the analyzers.
 */

interface ChainConfig {
  name: string;
  chainId: number;
  apiKeyEnv: string;
  /** Override base URL for non-Etherscan explorers (e.g. OKLink for ethw). */
  apiUrl?: string;
  /** Header to carry the API key, if the explorer doesn't accept ?apikey=
   *  (OKLink authenticates via the OK-ACCESS-KEY header). */
  authHeader?: string;
}

// Etherscan V2 is a single multichain endpoint: one ETHERSCAN_API_KEY works
// across every supported chain via ?chainid=. (The old per-chain V1 hosts —
// bscscan.com, polygonscan.com, etc. — are deprecated and now reject requests.)
const ETHERSCAN_V2 = 'https://api.etherscan.io/v2/api';

const CHAIN_CONFIG: Record<string, ChainConfig> = {
  ethereum: { name: 'Ethereum',    chainId: 1,     apiKeyEnv: 'ETHERSCAN_API_KEY' },
  bsc:      { name: 'BSC',         chainId: 56,    apiKeyEnv: 'ETHERSCAN_API_KEY' },
  polygon:  { name: 'Polygon',     chainId: 137,   apiKeyEnv: 'ETHERSCAN_API_KEY' },
  arbitrum: { name: 'Arbitrum',    chainId: 42161, apiKeyEnv: 'ETHERSCAN_API_KEY' },
  optimism: { name: 'Optimism',    chainId: 10,    apiKeyEnv: 'ETHERSCAN_API_KEY' },
  base:     { name: 'Base',        chainId: 8453,  apiKeyEnv: 'ETHERSCAN_API_KEY' },
  // EthereumPoW isn't on Etherscan. OKLink exposes an Etherscan-COMPATIBLE
  // endpoint (same getsourcecode dialect + response shape) per chain at
  // /api/v5/explorer/<chainShortName>/api, but authenticates via the
  // OK-ACCESS-KEY header rather than an ?apikey= param. Needs a (free) OKLink key.
  ethw:     { name: 'EthereumPoW', chainId: 10001, apiKeyEnv: 'OKLINK_API_KEY', apiUrl: 'https://www.oklink.com/api/v5/explorer/ethw/api', authHeader: 'OK-ACCESS-KEY' },
};

interface EtherscanSourceResult {
  SourceCode: string;
  ABI: string;
  ContractName: string;
  CompilerVersion: string;
  OptimizationUsed: string;
  Runs: string;
  ConstructorArguments: string;
  EVMVersion: string;
  Library: string;
  LicenseType: string;
  Proxy: string;
  Implementation: string;
  SwarmSource: string;
}

interface EtherscanResponse {
  status: string;
  message: string;
  result: EtherscanSourceResult[] | string;
}

export interface FetchedSource {
  contractName: string;
  compilerVersion: string;
  flattenedSource: string;
  files: Record<string, string>;
  proxyImplementation?: string;
}

/**
 * Some chains return SourceCode as a JSON string wrapped in extra braces,
 * starting with "{{". This is the "standard JSON input" format used when
 * multi-file contracts are verified. Detect and parse accordingly.
 */
function parseSourceCode(raw: string): { files: Record<string, string>; flattened: string } {
  if (!raw) return { files: {}, flattened: '' };

  const trimmed = raw.trim();
  // Standard JSON input format
  if (trimmed.startsWith('{{') && trimmed.endsWith('}}')) {
    const inner = trimmed.slice(1, -1);
    try {
      const parsed = JSON.parse(inner);
      const sources = parsed.sources || {};
      const files: Record<string, string> = {};
      for (const [path, val] of Object.entries(sources)) {
        files[path] = (val as { content: string }).content;
      }
      return { files, flattened: flattenFiles(files) };
    } catch (e) {
      // Fall through to plain
    }
  }
  // Plain JSON sources object (some explorers strip the outer braces)
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.sources) {
        const files: Record<string, string> = {};
        for (const [path, val] of Object.entries(parsed.sources)) {
          files[path] = (val as { content: string }).content;
        }
        return { files, flattened: flattenFiles(files) };
      }
    } catch {}
  }
  // Single-file source
  return {
    files: { 'Contract.sol': raw },
    flattened: raw,
  };
}

/**
 * Flatten multi-file source into a single Solidity file by:
 *   1. Sorting files to put dependencies first (best-effort by path depth)
 *   2. Stripping all `import` statements
 *   3. Deduplicating SPDX + pragma directives (keep first of each)
 *   4. Concatenating with file headers as comments
 *
 * This is the minimal flattener — for production use, hand off to
 * `forge flatten` or `truffle-flattener` which do proper symbol resolution.
 */
function flattenFiles(files: Record<string, string>): string {
  const sorted = Object.keys(files).sort((a, b) =>
    (a.match(/\//g)?.length || 0) - (b.match(/\//g)?.length || 0)
  );

  let spdxSeen = false;
  let pragmaSeen = false;
  const parts: string[] = [];

  for (const path of sorted) {
    let content = files[path];
    // Strip imports
    content = content.replace(/^\s*import\s+[^;]+;[ \t]*\n?/gm, '');
    // Dedupe SPDX
    content = content.replace(/^\s*\/\/\s*SPDX-License-Identifier:[^\n]*\n?/gm, (m) => {
      if (spdxSeen) return '';
      spdxSeen = true;
      return m;
    });
    // Dedupe pragma
    content = content.replace(/^\s*pragma\s+[^;]+;[ \t]*\n?/gm, (m) => {
      if (pragmaSeen) return '';
      pragmaSeen = true;
      return m;
    });
    parts.push(`// ─── ${path} ─────────────────────────────────────\n${content}`);
  }
  return parts.join('\n\n');
}

export async function fetchEtherscanSource(
  address: string,
  chain: string
): Promise<FetchedSource> {
  const cfg = CHAIN_CONFIG[chain];
  if (!cfg) throw new Error(`Unsupported chain: ${chain}`);

  const apiKey = process.env[cfg.apiKeyEnv];
  if (!apiKey) {
    throw new Error(`Missing API key (${cfg.apiKeyEnv}) for ${cfg.name}`);
  }

  const url = new URL(cfg.apiUrl || ETHERSCAN_V2);
  // Etherscan V2 selects the chain via ?chainid=; non-Etherscan explorers don't.
  if (!cfg.apiUrl) url.searchParams.set('chainid', String(cfg.chainId));
  url.searchParams.set('module', 'contract');
  url.searchParams.set('action', 'getsourcecode');
  url.searchParams.set('address', address);

  // Etherscan takes the key as a query param; OKLink wants it in a header.
  const headers: Record<string, string> = { 'User-Agent': 'forensiq/0.1' };
  if (cfg.authHeader) headers[cfg.authHeader] = apiKey;
  else url.searchParams.set('apikey', apiKey);

  const res = await fetch(url.toString(), {
    headers,
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`Explorer API returned ${res.status}`);

  const data = await res.json() as EtherscanResponse;
  if (data.status !== '1' || !Array.isArray(data.result)) {
    throw new Error(`Explorer error: ${data.message || data.result}`);
  }

  const r = data.result[0];
  if (!r.SourceCode) {
    throw new Error(`Contract at ${address} is not verified on ${cfg.name}`);
  }

  const { files, flattened } = parseSourceCode(r.SourceCode);

  return {
    contractName: r.ContractName,
    compilerVersion: r.CompilerVersion,
    flattenedSource: flattened,
    files,
    proxyImplementation: r.Proxy === '1' ? r.Implementation : undefined,
  };
}
