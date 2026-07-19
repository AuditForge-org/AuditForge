/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Proxy following for address-mode audits.
 *
 * A proxy's own source is upgrade plumbing — OpenZeppelin's ERC1967 /
 * TransparentUpgradeableProxy shell. The logic that actually holds funds lives
 * in the implementation it delegates to. Auditing the shell scores the wrong
 * bytecode and reports essentially nothing, which for a security tool is worse
 * than refusing: the user gets a clean-looking report for an unexamined
 * contract. (Real case: the Robinhood Chain WETH proxy is ~8KB of boilerplate
 * in front of a much larger implementation.)
 *
 * So we follow to the implementation by default — and because the report then
 * describes a DIFFERENT address than the caller typed, it must say so.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchEtherscanSource } from '../src/source/etherscan';

const PROXY = '0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73';
const IMPL = '0xc6b81b429797e0f555440b70cd99e032d7ae947e';
const IMPL2 = '0x1111111111111111111111111111111111111111';

/** Serve a different explorer row per requested address. */
function stubByAddress(rows: Record<string, Record<string, unknown> | null>) {
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const addr = (new URL(url).searchParams.get('address') || '').toLowerCase();
    calls.push(addr);
    const row = rows[addr];
    return {
      ok: true,
      status: 200,
      // A missing row models "unverified": Blockscout still answers 200/"1".
      json: async () => ({ status: '1', message: 'OK', result: [row ?? { Address: addr }] }),
    };
  }));
  return calls;
}

const proxyRow = (impl: string) => ({
  SourceCode: 'contract TransparentUpgradeableProxy { }',
  ContractName: 'TransparentUpgradeableProxy',
  CompilerVersion: 'v0.8.16+commit.07a7930e',
  IsProxy: 'true',
  ImplementationAddress: impl,
});

const logicRow = (name: string) => ({
  SourceCode: `contract ${name} { function withdraw() external {} }`,
  ContractName: name,
  CompilerVersion: 'v0.7.6+commit.7338295f',
});

afterEach(() => { vi.unstubAllGlobals(); });

describe('proxy following', () => {
  it('analyzes the implementation, not the proxy shell', async () => {
    stubByAddress({
      [PROXY.toLowerCase()]: proxyRow(IMPL),
      [IMPL.toLowerCase()]: logicRow('WETH9'),
    });
    const r = await fetchEtherscanSource(PROXY, 'robinhood');
    expect(r.contractName).toBe('WETH9');
    expect(r.flattenedSource).toContain('function withdraw');
    expect(r.flattenedSource).not.toContain('TransparentUpgradeableProxy');
    // The compiler must track the source we ended up with, not the shell's —
    // this is what feeds solc selection.
    expect(r.compilerVersion).toBe('v0.7.6+commit.7338295f');
  });

  it('discloses the swap so the report can name both addresses', async () => {
    stubByAddress({
      [PROXY.toLowerCase()]: proxyRow(IMPL),
      [IMPL.toLowerCase()]: logicRow('WETH9'),
    });
    const r = await fetchEtherscanSource(PROXY, 'robinhood');
    expect(r.proxy).toEqual({
      address: PROXY,
      implementation: IMPL,
      proxyContractName: 'TransparentUpgradeableProxy',
    });
  });

  it('reports the ORIGINAL address across multiple hops', async () => {
    stubByAddress({
      [PROXY.toLowerCase()]: proxyRow(IMPL),
      [IMPL.toLowerCase()]: { ...logicRow('Middle'), IsProxy: 'true', ImplementationAddress: IMPL2 },
      [IMPL2.toLowerCase()]: logicRow('FinalLogic'),
    });
    const r = await fetchEtherscanSource(PROXY, 'robinhood');
    expect(r.contractName).toBe('FinalLogic');
    // Caller asked for PROXY; innermost analyzed is IMPL2 — not the middle hop.
    expect(r.proxy?.address).toBe(PROXY);
    expect(r.proxy?.implementation).toBe(IMPL2);
  });

  it('falls back to the proxy source when the implementation is unverified', async () => {
    stubByAddress({
      [PROXY.toLowerCase()]: proxyRow(IMPL),
      [IMPL.toLowerCase()]: null, // unverified
    });
    const r = await fetchEtherscanSource(PROXY, 'robinhood');
    // Degrade, don't fail the whole scan.
    expect(r.contractName).toBe('TransparentUpgradeableProxy');
    expect(r.proxy).toBeUndefined();
    // Still surfaced, so a reader can see why the report looks thin.
    expect(r.proxyImplementation).toBe(IMPL);
  });

  it('does not loop when a proxy points at itself', async () => {
    const calls = stubByAddress({ [PROXY.toLowerCase()]: proxyRow(PROXY) });
    const r = await fetchEtherscanSource(PROXY, 'robinhood');
    expect(r.contractName).toBe('TransparentUpgradeableProxy');
    expect(calls).toHaveLength(1);
  });

  it('bounds a proxy cycle instead of recursing forever', async () => {
    const calls = stubByAddress({
      [PROXY.toLowerCase()]: proxyRow(IMPL),
      [IMPL.toLowerCase()]: proxyRow(PROXY),
    });
    await fetchEtherscanSource(PROXY, 'robinhood');
    expect(calls.length).toBeLessThanOrEqual(4); // MAX_PROXY_HOPS
  });

  it('ignores a zero-address implementation', async () => {
    const calls = stubByAddress({
      [PROXY.toLowerCase()]: proxyRow('0x0000000000000000000000000000000000000000'),
    });
    const r = await fetchEtherscanSource(PROXY, 'robinhood');
    expect(r.contractName).toBe('TransparentUpgradeableProxy');
    expect(calls).toHaveLength(1);
  });

  it('honours followProxy:false for inspecting the shell itself', async () => {
    stubByAddress({
      [PROXY.toLowerCase()]: proxyRow(IMPL),
      [IMPL.toLowerCase()]: logicRow('WETH9'),
    });
    const r = await fetchEtherscanSource(PROXY, 'robinhood', { followProxy: false });
    expect(r.contractName).toBe('TransparentUpgradeableProxy');
    expect(r.proxy).toBeUndefined();
  });

  it('leaves non-proxy contracts untouched', async () => {
    const calls = stubByAddress({ [IMPL.toLowerCase()]: logicRow('Plain') });
    const r = await fetchEtherscanSource(IMPL, 'robinhood');
    expect(r.proxy).toBeUndefined();
    expect(r.proxyImplementation).toBeUndefined();
    expect(calls).toHaveLength(1);
  });
});
