# @bitsentry/plugin-wazuh

BitSentry code plugin for Wazuh alerts and index queries.

This package is source for a first-party SuperTerminal plugin. In v1, CI builds the
TypeScript plugin into a single `plugin.js` artifact, uploads that artifact to the
BitSentry Cloudflare R2 bucket, and updates the first-party YAML index.

```sh
pnpm run build
```

Users install the published artifact through the index, not from an npm package or
archive:

```sh
bitsentry plugin install wazuh
```

Alert pagination cursors are versioned opaque values that include the sort
order. A cursor must be replayed with the same `sortOrder` that created it.
Cursors from the legacy raw-array format are deliberately rejected; restart
the query without a cursor to receive a versioned cursor.
