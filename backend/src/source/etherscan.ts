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
  /** Env var holding the API key. Omit for explorers that need no key
   *  (public Blockscout instances are open). */
  apiKeyEnv?: string;
  /** Override base URL for non-Etherscan explorers (e.g. OKLink for ethw). */
  apiUrl?: string;
  /** Header to carry the API key, if the explorer doesn't accept ?apikey=
   *  (OKLink authenticates via the OK-ACCESS-KEY header). */
  authHeader?: string;
  /** Per-chain fetch timeout. Defaults to 15s; raise for slow explorers. */
  timeoutMs?: number;
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
  // Robinhood Chain is an Arbitrum Orbit L2 (chain id 4663, verified via
  // eth_chainId -> 0x1237). It isn't on Etherscan V2, but its Blockscout
  // explorer serves the same getsourcecode dialect and needs NO API key.
  // Blockscout differs in two ways we handle below: multi-file contracts put
  // only the entry file in SourceCode (the rest arrive in AdditionalSources),
  // and proxies are flagged via IsProxy/ImplementationAddress.
  robinhood: { name: 'Robinhood Chain', chainId: 4663, apiUrl: 'https://robinhoodchain.blockscout.com/api', timeoutMs: 45_000 },
};

/** One extra source file in Blockscout's multi-file response. */
/**
 * Human-facing name for a chain slug ("robinhood" -> "Robinhood Chain").
 * Display sites previously derived this from the slug itself, which produced
 * "ROBINHOOD", "Bsc" and "Ethw". Falls back to the slug for unknown values.
 */
export function chainDisplayName(chain: string): string {
  return CHAIN_CONFIG[chain]?.name || chain;
}

interface AdditionalSource {
  Filename: string;
  SourceCode: string;
}

interface EtherscanSourceResult {
  SourceCode: string;
  ABI: string;
  ContractName: string;
  CompilerVersion: string;
  // Etherscan-family fields — absent on Blockscout, so all optional.
  OptimizationUsed?: string;
  Runs?: string;
  ConstructorArguments?: string;
  EVMVersion?: string;
  Library?: string;
  LicenseType?: string;
  Proxy?: string;
  Implementation?: string;
  SwarmSource?: string;
  // Blockscout-only fields.
  /** Remaining files of a multi-file verification (entry file is SourceCode). */
  AdditionalSources?: AdditionalSource[];
  /** Path of the entry file, used as the key for SourceCode when merging. */
  FileName?: string;
  /** Blockscout serialises this as the STRING "true"/"false", not a bool. */
  IsProxy?: boolean | string;
  ImplementationAddress?: string;
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
function parseSourceCode(
  raw: string,
  additional?: AdditionalSource[],
  mainFileName?: string
): { files: Record<string, string>; flattened: string } {
  if (!raw) return { files: {}, flattened: '' };

  // Blockscout dialect: SourceCode carries ONLY the entry file, and every other
  // file of the verification arrives in a sibling AdditionalSources array.
  // Merging is not optional — for UniswapV3Factory on Robinhood Chain the entry
  // file is ~2.8KB of a ~100KB contract, so analyzing SourceCode alone would
  // silently audit ~3% of the code and under-report findings.
  if (additional && additional.length) {
    const files: Record<string, string> = {};
    files[mainFileName || 'Contract.sol'] = raw;
    for (const f of additional) {
      if (f && typeof f.SourceCode === 'string' && f.Filename && !(f.Filename in files)) {
        files[f.Filename] = f.SourceCode;
      }
    }
    return { files, flattened: flattenFiles(files, mainFileName || 'Contract.sol') };
  }

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
function flattenFiles(files: Record<string, string>, mainFile?: string): string {
  const depth = (p: string) => p.match(/\//g)?.length || 0;
  const sorted = Object.keys(files).sort((a, b) => {
    // Emit the entry contract first. The SPDX/pragma dedup below is first-wins,
    // so this makes the *entry's* pragma the surviving one by construction —
    // otherwise the winner is whichever file happens to sit at the shallowest
    // path, and a dependency's narrower pragma can make the whole flattened
    // unit refuse to compile (which fails the entire scan, not one file).
    if (a === mainFile) return -1;
    if (b === mainFile) return 1;
    return depth(a) - depth(b);
  });

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

  // Some explorers (public Blockscout) are keyless; only demand a key when the
  // chain config declares one.
  const apiKey = cfg.apiKeyEnv ? process.env[cfg.apiKeyEnv] : undefined;
  if (cfg.apiKeyEnv && !apiKey) {
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
  if (apiKey) {
    if (cfg.authHeader) headers[cfg.authHeader] = apiKey;
    else url.searchParams.set('apikey', apiKey);
  }

  const res = await fetch(url.toString(), {
    headers,
    // Public Blockscout instances are markedly slower than Etherscan and the
    // latency is uncorrelated with payload size (Robinhood Chain measures a
    // ~13s p90 with spikes past 15s), so a 15s ceiling sat inside the normal
    // distribution and produced intermittent, irreproducible scan failures.
    signal: AbortSignal.timeout(cfg.timeoutMs ?? 15_000),
  });
  if (!res.ok) throw new Error(`Explorer API returned ${res.status}`);

  const data = await res.json() as EtherscanResponse;
  if (data.status !== '1' || !Array.isArray(data.result)) {
    // On a real failure Etherscan puts the useful detail in `result` (a string)
    // and only "NOTOK" in `message`, so prefer the former when present.
    const detail = typeof data.result === 'string' ? data.result : data.message;
    throw new Error(`Explorer error: ${detail}`);
  }

  // NOTE: Blockscout does NOT follow Etherscan's error convention here — for an
  // UNVERIFIED contract it still answers 200 with status "1"/"OK" and a result
  // row containing only an Address. So the empty-source check below is the ONLY
  // reliable "not verified" signal on those chains; do not refactor it into a
  // status check.
  const r = data.result[0];
  if (!r || !r.SourceCode) {
    throw new Error(`Contract at ${address} is not verified on ${cfg.name}`);
  }

  const { files, flattened } = parseSourceCode(r.SourceCode, r.AdditionalSources, r.FileName);

  // Etherscan flags proxies with Proxy: "1" + Implementation; Blockscout uses
  // IsProxy: true + ImplementationAddress.
  const isProxy =
    r.Proxy === '1' || r.IsProxy === true || r.IsProxy === 'true';
  const implementation = r.Implementation || r.ImplementationAddress;

  return {
    contractName: r.ContractName,
    compilerVersion: r.CompilerVersion,
    flattenedSource: flattened,
    files,
    proxyImplementation: isProxy && implementation ? implementation : undefined,
  };
}
