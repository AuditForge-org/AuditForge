/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Brand attribution shared by the PDF report and the server-rendered pages.
 *
 * Audit Forge is built and operated by Condo (condobase.io). Contributions go
 * to a plain externally-owned account, so any EVM network works. Keep the
 * wallet in sync with frontend/views.js (CONDO) and frontend/index.html.
 */

export const CONDO = {
  name: 'Condo',
  url: 'https://condobase.io',
  productUrl: 'https://condobase.io/home/auditforge',
  /** Contribution address ("support the cause"). EOA - any EVM chain. */
  wallet: '0xEf3E49a3197417ccDbF5F6A60D89f7Fa4823199d',
  poweredBy: 'Powered by Condo',
  supportLead:
    'Audit Forge is free and open source, built and operated by Condo, the onchain treasury protocol. ' +
    'Every scan costs real compute. If this report saved you an audit fee, support the cause with a contribution ' +
    'so the engines stay running and free for the next builder.',
  supportFine:
    'Send ETH or tokens on Ethereum, Base, Arbitrum, Robinhood Chain or any EVM network. ' +
    'Contributions are voluntary and non-refundable.',
} as const;
