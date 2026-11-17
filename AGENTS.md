# Wazuh plugin

`@bitsentry/plugin-wazuh` is a BitSentry code plugin that reads Wazuh alerts and vulnerability findings from a Wazuh indexer. BitSentry loads it through `@bitsentry/plugin-sdk`, so its descriptor and action results are a public contract.

## What we never compromise on

- **Read-only.** Every action is `riskLevel: "read"`. The plugin queries the indexer and never changes Wazuh state. Do not add a write action without a maintainer asking for it.
- **Credentials stay in auth.** `indexUrl`, `indexUsername` and `indexPassword` come from host-managed auth. Never log them, return them in `data`, or put them in error summaries.
- **Correct results.** Users act on these findings. A partial or truncated result must say so; never present it as complete.

## The ways to hurt yourself

1. **Querying a real indexer.** Never run the plugin against a real Wazuh instance unless the developer asks. Tests use fixtures and stubs.
2. **Breaking cursors.** Alert pagination cursors are versioned opaque values that include the sort order. A cursor must be replayed with the same `sortOrder`, and legacy raw-array cursors are rejected on purpose. Changing the cursor format needs a new version, not an in-place edit.
3. **Breaking the contract.** Renaming an action id, field key or result field breaks saved runbooks and hosts. Add, do not rename.

## Actions

`query_issues`, `search_alerts`, `summarize_vulnerabilities` and `list_vulnerabilities`, all read-only. Vulnerability indexes are queried without a timestamp sort.

## Verifying

CI runs these. Run them before you push:

```sh
pnpm install --frozen-lockfile
pnpm run format
pnpm run lint
pnpm test
pnpm run build
pnpm pack --dry-run
pnpm knip
```

Behavior changes ship with a focused test in `src/plugin.spec.ts`. Bug fixes get a failing test first.

## Pull requests

- Never open a PR unless the developer asks. Branch from the latest `origin/main`.
- Titles and every commit subject are lowercase conventional commits: `fix(wazuh): query vulnerability indexes without timestamp sort`. `change-guardrails.yml` checks them.
- Body: `## Problem`, `## Change`, `## Tests`.
- Pushing a `v*` tag publishes a GitHub release. Keep `version` in `package.json` and the descriptor in step.
- Do not add `Co-Authored-By` lines or AI attribution footers.

## Where code lives

- `src/plugin.ts`: descriptor, auth fields, actions and the indexer client.
- `src/plugin.spec.ts`: Vitest tests.
- `scripts/eslint/`: the TypeScript 6 lint bridge.

## Taste

- Honor `operation.signal` and `operation.deadlineAt` from the host.
- Fail loudly and specifically. An empty result must mean "nothing found", not "the request failed".
- Comments say why. Plain language in summaries. No em-dashes.
