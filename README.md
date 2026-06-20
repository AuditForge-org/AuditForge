<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Audit Forge

**Multi-engine smart-contract security analysis.** Audit Forge runs six
independent, industry-standard security engines against your Solidity in
parallel — static analysis, symbolic execution, and property fuzzing — then
reconciles every finding by **consensus** (how many independent tools agree)
and produces a 0–100 score, a ranked findings list, an AI-written brief, and a
shareable report.

🔗 **Live:** https://auditforge.org

> ⚠️ Audit Forge automates the **first pass**. It is **not** a substitute for a
> professional manual audit, and a high score is not a guarantee of safety.
> Always get an independent manual audit before deploying or trusting a contract
> with funds.

---

## Engines

| Engine | Method | Source |
|--------|--------|--------|
| **Slither** | Static analysis | Trail of Bits |
| **Aderyn** | AST analysis | Cyfrin |
| **Mythril** | Symbolic execution | Consensys |
| **Semgrep** | Pattern matching | Semgrep |
| **Solhint** | Linting | Protofire |
| **Echidna** | Property fuzzing (opt-in) | Trail of Bits |

Each engine runs in an isolated, **network-disabled**, resource-capped Docker
sandbox. Findings are normalized to their SWC category and clustered so the
score reflects cross-engine agreement, not any single tool's noise.

## How it works

```
            ┌─────────┐     paste / address / GitHub
  submit ──▶│   API   │──── resolves & flattens source ───┐
            └─────────┘                                    ▼
                                                      ┌─────────┐
            report ◀── consensus + score + AI brief ──│ worker  │
                                                      └────┬────┘
                                                           │ spawns (network-off)
              ┌──────────────────────────────────────────┴──────────────┐
              ▼        ▼        ▼         ▼         ▼          ▼
          slither   aderyn   mythril   semgrep   solhint   echidna
```

- **Frontend** — a dependency-free, hash-routed vanilla-JS SPA (`frontend/`).
- **API + worker** — Node/TypeScript + Express + BullMQ (`backend/`), Postgres,
  Redis. The worker spawns each engine as a sandboxed container via the host
  Docker socket.
- **Sources** — paste, verified contract address (Etherscan V2 multichain), or a
  GitHub repo/path.

## Source by address

Address mode fetches verified source via the **Etherscan V2 multichain** API —
one `ETHERSCAN_API_KEY` covers Ethereum, BSC, Polygon, Arbitrum, Optimism, and
Base. (EthereumPoW has no maintained public source API and is not currently
supported in address mode — use paste mode.)

## Running it

See **[DEPLOY.md](DEPLOY.md)** for the full single-host Docker Compose
deployment. In brief:

```bash
cp .env.production.example .env   # then fill in the values (chmod 600 .env)
docker compose -f docker-compose.prod.yml up -d --build
```

Configuration is environment-driven; see `.env.production.example` and
`backend/.env.example` for every variable (database, Redis, the OpenAI-compatible
AI provider for the brief, explorer keys, GitHub OAuth, rate limits, etc.).

## License

**[AGPL-3.0-or-later](LICENSE).** Because Audit Forge is offered over a network,
the AGPL's §13 applies: if you run a modified version as a service, you must
offer your users the complete corresponding source. See [NOTICE](NOTICE) for
third-party engine attributions (each retains its own license).

Contributions are welcome under the same license.
