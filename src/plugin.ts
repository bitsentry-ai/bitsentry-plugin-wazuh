import type { DesktopCodePlugin } from "@bitsentry/plugin-sdk";
import { Effect } from "effect";

const WAZUH_REQUEST_TIMEOUT_MS = 30_000;
const MAX_PAGE_SIZE = 100;
const WAZUH_ALERT_SORT = [
  { "@timestamp": "desc" },
  { _index: "desc" },
  { _id: "desc" },
];

type PluginOperationContext = {
  signal?: AbortSignal;
  deadlineAt?: number;
};

function linkAbortSignals(signals: readonly (AbortSignal | undefined)[]) {
  const controller = new AbortController();
  const abort = () => {
    controller.abort();
  };
  const activeSignals = signals.filter(
    (signal): signal is AbortSignal => signal !== undefined && !signal.aborted,
  );

  if (signals.some((signal) => signal?.aborted === true)) {
    abort();
  } else {
    for (const signal of activeSignals) {
      signal.addEventListener("abort", abort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    dispose() {
      for (const signal of activeSignals) {
        signal.removeEventListener("abort", abort);
      }
    },
  };
}

function operationTimeoutMs(operation?: PluginOperationContext): number {
  if (typeof operation?.deadlineAt !== "number") {
    return WAZUH_REQUEST_TIMEOUT_MS;
  }

  return Math.max(
    0,
    Math.min(WAZUH_REQUEST_TIMEOUT_MS, operation.deadlineAt - Date.now()),
  );
}

function readOperationContext(context): PluginOperationContext | undefined {
  return (context as { operation?: PluginOperationContext }).operation;
}

function readErrorCode(value: unknown): string | undefined {
  if (!(value instanceof Error)) {
    return undefined;
  }

  const code = (value as Error & { code?: unknown }).code;
  if (typeof code === "string" && code.length > 0) {
    return code;
  }

  return readErrorCode((value as Error & { cause?: unknown }).cause);
}

function describeRequestFailure(cause: unknown): string {
  const code = readErrorCode(cause);
  const description = (() => {
    switch (code) {
      case "UND_ERR_CONNECT_TIMEOUT":
      case "ETIMEDOUT":
        return "connection timed out";
      case "ECONNREFUSED":
        return "connection refused";
      case "ECONNRESET":
        return "connection reset";
      case "ENOTFOUND":
      case "EAI_AGAIN":
        return "DNS lookup failed";
      case "CERT_HAS_EXPIRED":
      case "DEPTH_ZERO_SELF_SIGNED_CERT":
      case "ERR_TLS_CERT_ALTNAME_INVALID":
      case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
        return "TLS certificate rejected";
      default:
        return cause instanceof Error && cause.message.trim().length > 0
          ? cause.message.trim()
          : "request failed";
    }
  })();

  return code === undefined ? description : `${description} (${code})`;
}

async function runWazuhRequest<T>(
  operation: string,
  parentOperation: PluginOperationContext | undefined,
  execute: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const timeoutMs = operationTimeoutMs(parentOperation);

  return Effect.runPromise(
    Effect.tryPromise({
      try: async (effectSignal) => {
        const linkedSignal = linkAbortSignals([
          parentOperation?.signal,
          effectSignal,
        ]);
        try {
          return await execute(linkedSignal.signal);
        } finally {
          linkedSignal.dispose();
        }
      },
      catch: (cause) => {
        const error = new Error(
          `${operation} failed: ${describeRequestFailure(cause)}`,
        ) as Error & { cause?: unknown };
        error.cause = cause;
        return error;
      },
    }).pipe(
      Effect.timeoutFail({
        duration: timeoutMs,
        onTimeout: () =>
          new Error(`${operation} timed out after ${String(timeoutMs)}ms`),
      }),
    ),
  );
}

function readString(value, fallback = "") {
  if (typeof value === "string") {
    const normalized = value.trim();
    if (normalized.length > 0) {
      return normalized;
    }
  }

  return fallback;
}

function readRecord(value): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  return value;
}

function readRecordOrEmpty(value): Record<string, unknown> {
  return readRecord(value) ?? {};
}

function resolveWazuhIndexUrl(value) {
  const parsed = new URL(requireString(value, "indexUrl"));
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Wazuh index URL must use http:// or https://");
  }

  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
}

function readStringArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((item) => typeof item === "string")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function resolveWazuhErrorSourceSetup(context) {
  const setupValues = readRecordOrEmpty(context.setupValues);
  const indexUrl = readString(setupValues.indexUrl);
  const indexUsername = readString(setupValues.indexUsername);
  const indexPassword = readString(setupValues.indexPassword);
  const indexPatterns = readStringArray(setupValues.indexPatterns);
  const configuration: Record<string, unknown> = {};
  if (indexUrl.length > 0) {
    configuration.baseUrl = indexUrl;
  }
  if (indexUsername.length > 0) {
    configuration.indexUsername = indexUsername;
  }
  if (indexPatterns.length > 0) {
    configuration.indexPatterns = indexPatterns;
  }

  return {
    accessTokenRef: indexPassword.length > 0 ? indexPassword : undefined,
    configuration,
  };
}

function buildWazuhErrorSourceAuthFromParts(accessTokenRef, configuration) {
  const config = readRecordOrEmpty(configuration);
  const auth = { ...config };
  const baseUrl = readString(config.baseUrl);
  if (baseUrl.length > 0) {
    auth.indexUrl = baseUrl;
  }
  const indexUsername = readString(config.indexUsername);
  if (indexUsername.length > 0) {
    auth.indexUsername = indexUsername;
  }
  const indexPassword = readString(accessTokenRef);
  if (indexPassword.length > 0) {
    auth.indexPassword = indexPassword;
  }

  return auth;
}

function buildWazuhErrorSourceAuth(context) {
  const source = readRecordOrEmpty(context.source);
  return buildWazuhErrorSourceAuthFromParts(
    source.accessTokenRef,
    source.configuration,
  );
}

function buildWazuhErrorSourceProbeAuth(context) {
  const persistedSetup = readRecordOrEmpty(context.persistedSetup);
  return buildWazuhErrorSourceAuthFromParts(
    persistedSetup.accessTokenRef,
    persistedSetup.configuration,
  );
}

function readIsoTimestamp(value) {
  const raw = readString(value);
  const parsed = new Date(raw);
  if (Number.isFinite(parsed.getTime())) {
    return parsed.toISOString();
  }

  return new Date().toISOString();
}

function isSearchAfterValue(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return true;
  }

  return typeof value === "number" && Number.isFinite(value);
}

function readSearchAfter(value) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new Error("Wazuh cursor must be an opaque string.");
  }

  try {
    const decoded = Buffer.from(value, "base64url").toString("utf8");
    const parsed = JSON.parse(decoded);
    if (
      !Array.isArray(parsed) ||
      parsed.length !== WAZUH_ALERT_SORT.length ||
      parsed.some((item) => !isSearchAfterValue(item))
    ) {
      throw new Error("invalid cursor shape");
    }

    return parsed;
  } catch {
    throw new Error("Wazuh cursor is invalid.");
  }
}

function encodeSearchAfter(hit) {
  if (
    !Array.isArray(hit?.sort) ||
    hit.sort.length !== WAZUH_ALERT_SORT.length ||
    hit.sort.some((item) => !isSearchAfterValue(item))
  ) {
    throw new Error(
      "Wazuh search response omitted stable sort values required for pagination.",
    );
  }

  return Buffer.from(JSON.stringify(hit.sort), "utf8").toString("base64url");
}

function readPositiveInteger(value, fallback) {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) {
    return value;
  }

  return fallback;
}

function readNonNegativeInteger(value, fallback) {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return value;
  }

  return fallback;
}

function readWazuhSourceRecord(hit) {
  return readRecord(hit?._source);
}

function readWazuhRuleRecord(hit) {
  return readRecord(readWazuhSourceRecord(hit)?.rule);
}

function readWazuhAgentRecord(hit) {
  return readRecord(readWazuhSourceRecord(hit)?.agent);
}

function readWazuhManagerRecord(hit) {
  return readRecord(readWazuhSourceRecord(hit)?.manager);
}

function readWazuhDescription(hit) {
  const ruleDescription = readString(readWazuhRuleRecord(hit)?.description);
  if (ruleDescription.length > 0) {
    return ruleDescription;
  }

  const fullLog = readString(readWazuhSourceRecord(hit)?.full_log);
  if (fullLog.length > 0) {
    return fullLog;
  }

  return "Wazuh alert";
}

function readWazuhLevelText(hit) {
  const rawLevel = Number(readWazuhRuleRecord(hit)?.level);
  if (!Number.isFinite(rawLevel)) {
    return "warning";
  }

  if (rawLevel >= 12) return "fatal";
  if (rawLevel >= 8) return "error";
  if (rawLevel >= 4) return "warning";
  return "info";
}

function buildWazuhTags(hit) {
  const source = readWazuhSourceRecord(hit);
  const rule = readWazuhRuleRecord(hit);
  const agent = readWazuhAgentRecord(hit);
  const manager = readWazuhManagerRecord(hit);
  const decoder = readRecord(source?.decoder);
  const tags: Record<string, unknown> = {};

  const ruleId = readString(rule?.id);
  if (ruleId.length > 0) tags.ruleId = ruleId;
  if (rule?.level !== undefined) tags.ruleLevel = rule.level;
  const ruleDescription = readString(rule?.description);
  if (ruleDescription.length > 0) tags.ruleDescription = ruleDescription;
  const agentId = readString(agent?.id);
  if (agentId.length > 0) tags.agentId = agentId;
  const agentName = readString(agent?.name);
  if (agentName.length > 0) tags.agentName = agentName;
  const managerName = readString(manager?.name);
  if (managerName.length > 0) tags.managerName = managerName;
  const location = readString(source?.location);
  if (location.length > 0) tags.location = location;
  const decoderName = readString(decoder?.name);
  if (decoderName.length > 0) tags.decoderName = decoderName;

  return tags;
}

function mapAlertToIssue(hit) {
  const rawId = readString(hit?._id);
  if (rawId.length === 0) {
    return undefined;
  }
  const index = readString(hit?._index);
  const externalId = index.length > 0 ? `${index}:${rawId}` : rawId;

  const source = readWazuhSourceRecord(hit);
  const rule = readWazuhRuleRecord(hit);
  const agent = readWazuhAgentRecord(hit);
  const manager = readWazuhManagerRecord(hit);
  const timestamp = readIsoTimestamp(source?.["@timestamp"]);
  const title = readWazuhDescription(hit);
  const fullLog = readString(source?.full_log, title);
  const agentName = readString(agent?.name);
  const managerName = readString(manager?.name);

  return {
    id: externalId,
    externalIssueId: externalId,
    latestEventId: externalId,
    title,
    message: fullLog,
    culprit: agentName || readString(source?.location),
    type: readString(rule?.id),
    metadata: rule,
    projectIdentifier: index,
    level: readWazuhLevelText(hit),
    status: "unresolved",
    isUnhandled: true,
    firstSeen: timestamp,
    lastSeen: timestamp,
    timestamp,
    eventCount: 1,
    userCount: null,
    tags: buildWazuhTags(hit),
    environment: managerName,
    platform: "wazuh",
    contexts: source,
    user: agent,
    serverName: agentName || managerName,
    transactionName: readString(source?.location),
    rawAlert: hit,
  };
}

function requireString(value, fieldName) {
  const normalized = readString(value);
  if (normalized.length === 0) {
    throw new Error(`${fieldName} is required`);
  }

  return normalized;
}

function buildQuery(input) {
  const must = [];
  const mustNot = [];
  const query = readString(input.query, "*");
  if (query === "*") {
    must.push({ match_all: {} });
  } else {
    must.push({
      query_string: {
        query,
      },
    });
  }

  const range: Record<string, string> = {};
  const since = readString(input.since);
  const until = readString(input.until);
  if (since.length > 0) {
    range.gte = since;
  }
  if (until.length > 0) {
    range.lte = until;
  }
  if (Object.keys(range).length > 0) {
    must.push({
      range: {
        "@timestamp": range,
      },
    });
  }

  const afterTimestamp = readString(input.afterTimestamp);
  if (afterTimestamp.length > 0) {
    must.push({
      range: {
        "@timestamp": {
          gt: afterTimestamp,
        },
      },
    });
  }

  const include = readString(input.include).toLowerCase();
  if (include.length > 0) {
    must.push({
      wildcard: {
        "agent.name": {
          value: `*${include}*`,
          case_insensitive: true,
        },
      },
    });
  }

  const exclude = readString(input.exclude).toLowerCase();
  if (exclude.length > 0) {
    mustNot.push({
      wildcard: {
        "agent.name": {
          value: `*${exclude}*`,
          case_insensitive: true,
        },
      },
    });
  }

  const bool: Record<string, unknown> = { must };
  if (mustNot.length > 0) {
    bool.must_not = mustNot;
  }

  return {
    bool,
  };
}

function readTotalHits(payload, fallback) {
  const total = payload?.hits?.total;
  if (typeof total === "number") {
    return total;
  }

  if (typeof total?.value === "number") {
    return total.value;
  }

  return fallback;
}

function formatOutput(input) {
  const lines = [
    "Wazuh alerts",
    `Index: ${input.indexPattern}`,
    `Query: ${input.query}`,
    `Results: ${String(input.items.length)}${input.hasMore ? "+" : ""}`,
  ];

  for (const hit of input.items.slice(0, 10)) {
    const source = hit._source;
    const timestamp = readString(source?.["@timestamp"], "unknown time");
    const description =
      readString(source?.rule?.description) ||
      readString(source?.full_log) ||
      "Wazuh alert";
    lines.push(`- ${timestamp} ${description}`);
  }

  if (input.hasMore) {
    lines.push("More results available.");
  }

  return lines.join("\n");
}

async function searchAlerts(context) {
  const { auth, input } = context;
  const indexUrl = resolveWazuhIndexUrl(auth.indexUrl);
  const indexUsername = requireString(auth.indexUsername, "indexUsername");
  const indexPassword = requireString(auth.indexPassword, "indexPassword");
  const configuredPatterns = readStringArray(auth.indexPatterns);
  const indexPattern = readString(
    input.indexPattern,
    configuredPatterns[0] ?? "wazuh-alerts-*",
  );
  const query = readString(input.query, "*");
  const limit = Math.min(readPositiveInteger(input.limit, 20), MAX_PAGE_SIZE);
  const searchAfter = readSearchAfter(input.cursor);
  const hasLegacyOffset = input.offset !== undefined && input.offset !== null;
  const offset =
    searchAfter === undefined && hasLegacyOffset
      ? readNonNegativeInteger(input.offset, 0)
      : undefined;
  const usesCursor = searchAfter !== undefined || !hasLegacyOffset;
  const requestSize = usesCursor ? limit + 1 : limit;
  const credentials = Buffer.from(`${indexUsername}:${indexPassword}`).toString(
    "base64",
  );
  const body: Record<string, unknown> = {
    query: buildQuery(input),
    size: requestSize,
    sort: WAZUH_ALERT_SORT,
  };
  if (searchAfter !== undefined) {
    body.search_after = searchAfter;
  } else if (offset !== undefined) {
    body.from = offset;
  }
  const response = await runWazuhRequest(
    `Wazuh alert search to ${indexUrl}`,
    readOperationContext(context),
    (signal) =>
      fetch(`${indexUrl}/${indexPattern}/_search`, {
        method: "POST",
        redirect: "error",
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
        signal,
      }),
  );

  if (!response.ok) {
    if (response.status === 404) {
      return {
        ok: true,
        status: 200,
        summary: "Fetched 0 Wazuh alerts.",
        data: {
          items: [],
          hasMore: false,
          total: 0,
          nextCursor: undefined,
          output: "Wazuh alerts\nResults: 0",
        },
      };
    }

    const body = await response
      .text()
      .catch(() => "Unable to read error response");
    throw new Error(
      `Wazuh search failed: ${String(response.status)} ${response.statusText} - ${body}`,
    );
  }

  const payload = await response.json();
  const rawItems = Array.isArray(payload?.hits?.hits) ? payload.hits.hits : [];
  const items = usesCursor ? rawItems.slice(0, limit) : rawItems;
  const total = readTotalHits(payload, rawItems.length);
  const hasMore = usesCursor
    ? rawItems.length > limit
    : (offset ?? 0) + items.length < total;
  const nextCursor =
    usesCursor && hasMore ? encodeSearchAfter(items.at(-1)) : undefined;

  return {
    ok: true,
    status: 200,
    summary: `Fetched ${String(items.length)} Wazuh alerts.`,
    data: {
      items,
      hasMore,
      total,
      nextCursor,
      output: formatOutput({
        indexPattern,
        query,
        items,
        hasMore,
      }),
    },
  };
}

async function queryIssues(context) {
  const result = await searchAlerts({
    auth: context.auth,
    input: {
      ...context.input,
    },
    operation: readOperationContext(context),
  });
  const data = readRecord(result.data) ?? {};
  const items = Array.isArray(data.items) ? data.items : [];
  const issues = items
    .map((item) => mapAlertToIssue(item))
    .filter((item) => item !== undefined);
  const hasMore = data.hasMore === true && items.length > 0;
  const nextCursor = readString(data.nextCursor) || undefined;

  return {
    ...result,
    summary: `Fetched ${String(issues.length)} Wazuh issues.`,
    data: {
      issues,
      hasMore,
      nextCursor: hasMore ? nextCursor : undefined,
      total: data.total,
      output: data.output,
    },
  };
}

const plugin: DesktopCodePlugin = {
  type: "data_source",
  id: "wazuh",
  name: "Wazuh",
  version: "0.1.0",
  description: "Queries Wazuh/OpenSearch alert indexes as a local code plugin.",
  metadata: {
    dataSource: {
      sourceType: "wazuh",
      setupFields: [
        {
          key: "indexUrl",
          label: "Wazuh index URL",
          placeholder: "https://wazuh.example.com:9200",
          description: "OpenSearch/Indexer base URL for Wazuh alerts.",
          required: true,
          control: "text",
        },
        {
          key: "indexUsername",
          label: "Wazuh index username",
          placeholder: "wazuh-reader",
          description: "Username for the Wazuh index user.",
          required: true,
          control: "text",
        },
        {
          key: "indexPassword",
          label: "Wazuh index password",
          description: "Password for the Wazuh index user.",
          required: true,
          control: "password",
        },
        {
          key: "indexPatterns",
          label: "Index patterns",
          placeholder: "wazuh-alerts-*",
          description: "Comma or newline separated Wazuh index patterns.",
          required: false,
          control: "multiline_list",
        },
      ],
    },
  },
  dataSource: {
    resolveSetup: resolveWazuhErrorSourceSetup,
    buildAuth: buildWazuhErrorSourceAuth,
    buildProbeAuth: buildWazuhErrorSourceProbeAuth,
  },
  auth: {
    fields: [
      {
        key: "indexUrl",
        label: "Wazuh index URL",
        type: "string",
        required: true,
      },
      {
        key: "indexUsername",
        label: "Wazuh index username",
        type: "string",
        required: true,
      },
      {
        key: "indexPassword",
        label: "Wazuh index password",
        type: "string",
        required: true,
        secret: true,
      },
    ],
  },
  actions: [
    {
      id: "query_issues",
      title: "Query Wazuh issues",
      description:
        "Search Wazuh/OpenSearch alerts and return normalized issue records for sync.",
      riskLevel: "read",
      fields: [
        {
          key: "query",
          label: "Query",
          type: "string",
          required: false,
          defaultValue: "*",
        },
        {
          key: "indexPattern",
          label: "Index pattern",
          type: "string",
          required: false,
          defaultValue: "wazuh-alerts-*",
        },
        {
          key: "limit",
          label: "Limit",
          type: "number",
          required: false,
          defaultValue: 20,
        },
        {
          key: "cursor",
          label: "Cursor",
          type: "string",
          required: false,
        },
        {
          key: "since",
          label: "Since",
          type: "string",
          required: false,
        },
        {
          key: "until",
          label: "Until",
          type: "string",
          required: false,
        },
        {
          key: "include",
          label: "Include agent",
          type: "string",
          required: false,
        },
        {
          key: "exclude",
          label: "Exclude agent",
          type: "string",
          required: false,
        },
        {
          key: "afterTimestamp",
          label: "After timestamp",
          type: "string",
          required: false,
        },
      ],
      execute: queryIssues,
    },
    {
      id: "search_alerts",
      title: "Search Wazuh alerts",
      description: "Search Wazuh/OpenSearch alerts and return raw hits.",
      riskLevel: "read",
      fields: [
        {
          key: "query",
          label: "Query",
          type: "string",
          required: false,
          defaultValue: "*",
        },
        {
          key: "indexPattern",
          label: "Index pattern",
          type: "string",
          required: false,
          defaultValue: "wazuh-alerts-*",
        },
        {
          key: "limit",
          label: "Limit",
          type: "number",
          required: false,
          defaultValue: 20,
        },
        {
          key: "offset",
          label: "Offset",
          type: "number",
          required: false,
          defaultValue: 0,
          description: "Legacy pagination. Use cursor for stable pagination.",
        },
        {
          key: "cursor",
          label: "Cursor",
          type: "string",
          required: false,
        },
        {
          key: "include",
          label: "Include agent",
          type: "string",
          required: false,
        },
        {
          key: "exclude",
          label: "Exclude agent",
          type: "string",
          required: false,
        },
        {
          key: "afterTimestamp",
          label: "After timestamp",
          type: "string",
          required: false,
        },
        {
          key: "since",
          label: "Since",
          type: "string",
          required: false,
        },
        {
          key: "until",
          label: "Until",
          type: "string",
          required: false,
        },
      ],
      execute: searchAlerts,
    },
  ],
};

export { plugin };
export default plugin;
