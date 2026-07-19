/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Compiler selection for verified (address-mode) sources.
 *
 * Explorers report the exact build a contract was verified with. Ignoring it
 * and defaulting to 0.8.24 makes solc reject anything pinned to an older
 * pragma ("Source file requires different compiler version"), which fails the
 * ENTIRE scan — the real case that motivated this is Uniswap V3 (v0.7.6), the
 * most prominent contract set on Robinhood Chain.
 *
 * The guard matters as much as the feature: engine containers run with
 * `--network none`, so solc-select cannot fetch a missing build at scan time.
 * Only versions baked into the images may be requested.
 */

import { describe, expect, it } from 'vitest';
import {
  AVAILABLE_SOLC_VERSIONS,
  DEFAULT_SOLC_VERSION,
  resolveSolcVersion,
} from '../src/engines/runner';

describe('resolveSolcVersion', () => {
  it('normalizes an explorer build string to a bare version', () => {
    expect(resolveSolcVersion('v0.7.6+commit.7338295f')).toBe('0.7.6');
    expect(resolveSolcVersion('v0.8.20+commit.a1b2c3d4')).toBe('0.8.20');
    expect(resolveSolcVersion('0.6.12')).toBe('0.6.12');
  });

  it('refuses versions that are not baked into the engine images', () => {
    // Real builds that exist upstream but not offline in our containers.
    expect(resolveSolcVersion('v0.8.26+commit.8a97fa7a')).toBeUndefined();
    expect(resolveSolcVersion('v0.4.24+commit.e67f0147')).toBeUndefined();
    // 0.8.17 ships in the slither image but NOT mythril; one version is handed
    // to both, so the intersection must exclude it.
    expect(resolveSolcVersion('v0.8.17+commit.8df45f5f')).toBeUndefined();
    expect(AVAILABLE_SOLC_VERSIONS).not.toContain('0.8.17');
  });

  it('ignores non-solc toolchains and junk', () => {
    expect(resolveSolcVersion('vyper:0.3.7')).toBeUndefined();
    expect(resolveSolcVersion('')).toBeUndefined();
    expect(resolveSolcVersion(undefined)).toBeUndefined();
    expect(resolveSolcVersion('unknown')).toBeUndefined();
  });

  it('keeps the default within the available set', () => {
    expect(AVAILABLE_SOLC_VERSIONS).toContain(DEFAULT_SOLC_VERSION);
  });
});
