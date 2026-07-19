/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Blockscout source-fetch tests (Robinhood Chain).
 *
 * Blockscout speaks the Etherscan `getsourcecode` dialect but differs in two
 * ways that are easy to get silently wrong — and both are high-stakes for a
 * security tool:
 *
 *   1. Multi-file verifications put ONLY the entry file in `SourceCode`; the
 *      rest arrive in a sibling `AdditionalSources` array. Dropping them means
 *      analyzing a fraction of the contract and under-reporting findings.
 *      (Real case: UniswapV3Factory on Robinhood Chain is 2.8KB in SourceCode
 *      and ~148KB once the other 32 files are merged.)
 *   2. Proxies are flagged with `IsProxy` — serialized as the STRING "true" —
 *      plus `ImplementationAddress`, not Etherscan's `Proxy: "1"`/`Implementation`.
 *
 * These tests stub fetch so they stay hermetic (no network in CI).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchEtherscanSource } from '../src/source/etherscan';

function stubExplorer(result: Record<string, unknown>) {
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ status: '1', message: 'OK', result: [result] }),
  })));
}

afterEach(() => { vi.unstubAllGlobals(); });

describe('Blockscout dialect (Robinhood Chain)', () => {
  it('merges AdditionalSources so no source file is lost', async () => {
    stubExplorer({
      SourceCode: 'contract Entry { uint x; }',
      ContractName: 'Entry',
      CompilerVersion: 'v0.8.20+commit.a1b2c3d4',
      FileName: 'src/Entry.sol',
      AdditionalSources: [
        { Filename: 'src/lib/Math.sol', SourceCode: 'library Math { function add() internal {} }' },
        { Filename: 'src/lib/Safe.sol', SourceCode: 'library Safe { function guard() internal {} }' },
      ],
    });

    const r = await fetchEtherscanSource('0xabc', 'robinhood');

    expect(Object.keys(r.files).sort()).toEqual([
      'src/Entry.sol', 'src/lib/Math.sol', 'src/lib/Safe.sol',
    ]);
    // The dependency bodies must actually reach the analyzers.
    expect(r.flattenedSource).toContain('library Math');
    expect(r.flattenedSource).toContain('library Safe');
    expect(r.flattenedSource).toContain('contract Entry');
  });

  it('keys the entry file by FileName, falling back when absent', async () => {
    stubExplorer({
      SourceCode: 'contract Solo {}',
      ContractName: 'Solo',
      CompilerVersion: 'v0.8.20+commit.a1b2c3d4',
      AdditionalSources: [{ Filename: 'B.sol', SourceCode: 'contract B {}' }],
    });
    const r = await fetchEtherscanSource('0xabc', 'robinhood');
    expect(Object.keys(r.files).sort()).toEqual(['B.sol', 'Contract.sol']);
  });

  it('treats IsProxy: "true" (a string) as a proxy', async () => {
    stubExplorer({
      SourceCode: 'contract P {}',
      ContractName: 'TransparentUpgradeableProxy',
      CompilerVersion: 'v0.8.16+commit.07a7930e',
      IsProxy: 'true',
      ImplementationAddress: '0xc6b81b429797e0f555440b70cd99e032d7ae947e',
    });
    const r = await fetchEtherscanSource('0xabc', 'robinhood');
    expect(r.proxyImplementation).toBe('0xc6b81b429797e0f555440b70cd99e032d7ae947e');
  });

  it('does not report a proxy when IsProxy is false', async () => {
    stubExplorer({
      SourceCode: 'contract Plain {}',
      ContractName: 'Plain',
      CompilerVersion: 'v0.7.6+commit.7338295f',
      IsProxy: 'false',
    });
    const r = await fetchEtherscanSource('0xabc', 'robinhood');
    expect(r.proxyImplementation).toBeUndefined();
  });

  it('still honours the Etherscan proxy shape', async () => {
    stubExplorer({
      SourceCode: 'contract P {}',
      ContractName: 'P',
      CompilerVersion: 'v0.8.20+commit.a1b2c3d4',
      Proxy: '1',
      Implementation: '0xdeadbeef',
    });
    const r = await fetchEtherscanSource('0xabc', 'robinhood');
    expect(r.proxyImplementation).toBe('0xdeadbeef');
  });

  it('surfaces a clean error for an unverified contract', async () => {
    stubExplorer({ SourceCode: '', ContractName: '', CompilerVersion: '' });
    await expect(fetchEtherscanSource('0xabc', 'robinhood'))
      .rejects.toThrow(/not verified on Robinhood Chain/);
  });

  it('requires no API key (keyless Blockscout)', async () => {
    const prev = process.env.ETHERSCAN_API_KEY;
    delete process.env.ETHERSCAN_API_KEY;
    stubExplorer({
      SourceCode: 'contract A {}', ContractName: 'A', CompilerVersion: 'v0.8.20+commit.a1b2c3d4',
    });
    await expect(fetchEtherscanSource('0xabc', 'robinhood')).resolves.toBeTruthy();
    // ...and must not append a stray apikey param.
    const url = (globalThis.fetch as unknown as { mock: { calls: string[][] } }).mock.calls[0][0];
    expect(String(url)).not.toContain('apikey');
    expect(String(url)).toContain('robinhoodchain.blockscout.com');
    if (prev !== undefined) process.env.ETHERSCAN_API_KEY = prev;
  });

  it('still demands a key for chains that declare one', async () => {
    const prev = process.env.ETHERSCAN_API_KEY;
    delete process.env.ETHERSCAN_API_KEY;
    await expect(fetchEtherscanSource('0xabc', 'ethereum'))
      .rejects.toThrow(/Missing API key/);
    if (prev !== undefined) process.env.ETHERSCAN_API_KEY = prev;
  });
});
