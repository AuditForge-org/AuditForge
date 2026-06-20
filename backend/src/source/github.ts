/**
 * GitHub source fetcher.
 *
 * Two modes:
 *   1. Single file:  repo + path  → fetch via raw.githubusercontent.com
 *   2. Whole repo:   repo only    → walk via GitHub API, collect all .sol,
 *                                   flatten conservatively
 *
 * Uses a GITHUB_TOKEN if available for higher rate limits (5000/hr vs 60).
 */

interface GithubTreeItem {
  path: string;
  mode: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
  url: string;
}

interface GithubTreeResponse {
  sha: string;
  url: string;
  tree: GithubTreeItem[];
  truncated: boolean;
}

export interface FetchedSource {
  contractName?: string;
  compilerVersion?: string;
  flattenedSource: string;
  files: Record<string, string>;
}

function parseRepoSpec(spec: string): { owner: string; repo: string } {
  const urlMatch = spec.match(/github\.com\/([^/]+)\/([^/?#.]+)/);
  if (urlMatch) return { owner: urlMatch[1], repo: urlMatch[2] };
  const parts = spec.split('/');
  if (parts.length >= 2) return { owner: parts[0], repo: parts[1] };
  throw new Error('Repo must be "owner/repo" or full GitHub URL');
}

function authHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN;
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'forensiq/0.1',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function fetchRawFile(owner: string, repo: string, ref: string, path: string): Promise<string> {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`Failed to fetch ${path}: ${res.status}`);
  return res.text();
}

async function fetchTree(owner: string, repo: string, ref: string): Promise<GithubTreeItem[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`;
  const res = await fetch(url, { headers: authHeaders(), signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`GitHub tree fetch failed: ${res.status}`);
  const data = await res.json() as GithubTreeResponse;
  if (data.truncated) {
    console.warn('[github] Tree was truncated; some files may be missing');
  }
  return data.tree;
}

async function resolveRef(owner: string, repo: string, ref?: string): Promise<string> {
  if (ref) return ref;
  // Get default branch
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: authHeaders(),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Repo not found: ${res.status}`);
  const data = await res.json() as { default_branch: string };
  return data.default_branch;
}

function flattenFiles(files: Record<string, string>): string {
  const sorted = Object.keys(files).sort((a, b) =>
    (a.match(/\//g)?.length || 0) - (b.match(/\//g)?.length || 0)
  );
  let spdxSeen = false, pragmaSeen = false;
  const parts: string[] = [];
  for (const path of sorted) {
    let content = files[path];
    content = content.replace(/^\s*import\s+[^;]+;[ \t]*\n?/gm, '');
    content = content.replace(/^\s*\/\/\s*SPDX-License-Identifier:[^\n]*\n?/gm, (m) => {
      if (spdxSeen) return '';
      spdxSeen = true; return m;
    });
    content = content.replace(/^\s*pragma\s+[^;]+;[ \t]*\n?/gm, (m) => {
      if (pragmaSeen) return '';
      pragmaSeen = true; return m;
    });
    parts.push(`// ─── ${path} ─────────────────────────────────────\n${content}`);
  }
  return parts.join('\n\n');
}

export async function fetchGithubSource(
  repoSpec: string,
  path?: string,
  ref?: string
): Promise<FetchedSource> {
  const { owner, repo } = parseRepoSpec(repoSpec);
  const resolvedRef = await resolveRef(owner, repo, ref);

  if (path) {
    // Single file (or single dir if path ends with /)
    if (path.endsWith('.sol')) {
      const content = await fetchRawFile(owner, repo, resolvedRef, path);
      return {
        flattenedSource: content,
        files: { [path]: content },
      };
    }
    // Directory: fetch all .sol under it
    const tree = await fetchTree(owner, repo, resolvedRef);
    const solFiles = tree.filter(t =>
      t.type === 'blob' && t.path.startsWith(path) && t.path.endsWith('.sol')
    );
    if (solFiles.length === 0) throw new Error(`No .sol files found at ${path}`);
    const files: Record<string, string> = {};
    // Limit to 50 files to avoid rate limits / huge contracts
    for (const item of solFiles.slice(0, 50)) {
      files[item.path] = await fetchRawFile(owner, repo, resolvedRef, item.path);
    }
    return { flattenedSource: flattenFiles(files), files };
  }

  // No path: discover .sol files automatically
  const tree = await fetchTree(owner, repo, resolvedRef);
  const solFiles = tree.filter(t =>
    t.type === 'blob' &&
    t.path.endsWith('.sol') &&
    !t.path.includes('/test/') &&
    !t.path.includes('/mock/') &&
    !t.path.includes('node_modules')
  );
  if (solFiles.length === 0) throw new Error('No Solidity files found in repo');
  if (solFiles.length > 50) {
    throw new Error(`Repo has ${solFiles.length} .sol files. Please specify a path to narrow the scope.`);
  }
  const files: Record<string, string> = {};
  for (const item of solFiles) {
    files[item.path] = await fetchRawFile(owner, repo, resolvedRef, item.path);
  }
  return { flattenedSource: flattenFiles(files), files };
}
