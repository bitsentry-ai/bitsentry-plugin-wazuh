import { afterEach, describe, expect, it, vi } from "vitest";

import plugin from "./plugin";
import type {
  DesktopPluginCodeActionContext,
  DesktopPluginCodeHostContext,
} from "@bitsentry/plugin-sdk";

const host: DesktopPluginCodeHostContext = {
  pluginRoot: "",
  entryPath: "",
  localPluginDirectories: [],
  reloadPlugins: () => Promise.resolve(),
};

function action(id: string) {
  const match = plugin.actions.find((candidate) => candidate.id === id);
  if (match === undefined) {
    throw new Error(`Missing Wazuh plugin action: ${id}`);
  }
  return match;
}

function context(
  actionId: string,
  input: Record<string, unknown>,
): DesktopPluginCodeActionContext {
  return {
    pluginId: plugin.id,
    actionId,
    auth: {
      indexUrl: "https://wazuh.example.com:9200",
      indexUsername: "wazuh-reader",
      indexPassword: "wazuh-secret",
    },
    input,
    host,
  };
}

describe("Wazuh plugin package", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("declares a typed Wazuh error-source code plugin", () => {
    expect(plugin).toMatchObject({
      id: "wazuh",
      metadata: {
        dataSource: {
          sourceType: "wazuh",
          setupFields: expect.arrayContaining([
            expect.objectContaining({
              key: "indexUrl",
              required: true,
            }),
            expect.objectContaining({
              key: "indexUsername",
              required: true,
            }),
            expect.objectContaining({
              key: "indexPassword",
              required: true,
            }),
          ]),
        },
      },
    });
    expect(plugin.actions.map((candidate) => candidate.id)).toEqual(
      expect.arrayContaining(["query_issues", "search_alerts"]),
    );
  });

  it("round-trips the explicit username through source setup into plugin auth", async () => {
    const persistedSetup = await plugin.dataSource?.resolveSetup?.({
      pluginId: plugin.id,
      setupValues: {
        indexUrl: "https://wazuh.example.com:9200",
        indexUsername: "wazuh-reader",
        indexPassword: "wazuh-secret",
        indexPatterns: ["wazuh-alerts-*"],
      },
      host,
    });

    expect(persistedSetup).toMatchObject({
      accessTokenRef: "wazuh-secret",
      configuration: {
        baseUrl: "https://wazuh.example.com:9200",
        indexUsername: "wazuh-reader",
        indexPatterns: ["wazuh-alerts-*"],
      },
    });

    const auth = await plugin.dataSource?.buildAuth?.({
      pluginId: plugin.id,
      source: {
        sourceType: "wazuh",
        accessTokenRef: persistedSetup?.accessTokenRef,
        configuration: persistedSetup?.configuration ?? {},
      },
      host,
    });

    expect(auth).toMatchObject({
      indexUrl: "https://wazuh.example.com:9200",
      indexUsername: "wazuh-reader",
      indexPassword: "wazuh-secret",
      indexPatterns: ["wazuh-alerts-*"],
    });
  });

  it("executes search_alerts through plugin-owned OpenSearch query code", async () => {
    const fetchMock = vi
      .fn<(url: string, request?: RequestInit) => Promise<Response>>()
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            hits: {
              total: { value: 1, relation: "eq" },
              hits: [
                {
                  _id: "alert-1",
                  _index: "wazuh-alerts-4.x-2026.06.01",
                  _score: 1,
                  _source: {
                    "@timestamp": "2026-06-01T00:05:00.000Z",
                    rule: {
                      id: "5710",
                      level: 10,
                      description: "sshd brute force attempt",
                    },
                    agent: {
                      name: "prod-api-1",
                    },
                  },
                },
              ],
            },
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    const result = await action("search_alerts").execute(
      context("search_alerts", {
        query: "rule.level:>=10",
        indexPattern: "wazuh-alerts-*",
        limit: 2,
        offset: 0,
        since: "2026-06-01T00:00:00.000Z",
        until: "2026-06-01T01:00:00.000Z",
        include: "prod-api",
        exclude: "test-agent",
        afterTimestamp: "2026-05-31T23:00:00.000Z",
      }),
    );

    expect(result).toMatchObject({
      ok: true,
      status: 200,
      summary: "Fetched 1 Wazuh alerts.",
      data: {
        hasMore: false,
        total: 1,
      },
    });

    const [url, request] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe("https://wazuh.example.com:9200/wazuh-alerts-*/_search");
    expect(request).toMatchObject({
      method: "POST",
      redirect: "error",
      headers: {
        Authorization: `Basic ${Buffer.from("wazuh-reader:wazuh-secret").toString("base64")}`,
        "Content-Type": "application/json",
      },
    });

    const body = JSON.parse(
      typeof request?.body === "string" ? request.body : "{}",
    );
    expect(body).toMatchObject({
      size: 2,
      from: 0,
      sort: [{ "@timestamp": "desc" }, { _index: "desc" }, { _id: "desc" }],
      query: {
        bool: {
          must: expect.arrayContaining([
            {
              wildcard: {
                "agent.name": {
                  value: "*prod-api*",
                  case_insensitive: true,
                },
              },
            },
            {
              range: {
                "@timestamp": {
                  gt: "2026-05-31T23:00:00.000Z",
                },
              },
            },
          ]),
          must_not: [
            {
              wildcard: {
                "agent.name": {
                  value: "*test-agent*",
                  case_insensitive: true,
                },
              },
            },
          ],
        },
      },
    });
  });

  it("requires an explicit source username before sending credentials", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      action("search_alerts").execute({
        ...context("search_alerts", { indexPattern: "wazuh-alerts-*" }),
        auth: {
          indexUrl: "https://wazuh.example.com:9200",
          indexPassword: "wazuh-secret",
        },
      }),
    ).rejects.toThrow("indexUsername is required");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses an opaque stable cursor for query_issues pagination", async () => {
    const firstHit = {
      _id: "alert-1",
      _index: "wazuh-alerts-4.x-2026.06.01",
      sort: [
        "2026-06-01T00:05:00.000Z",
        "wazuh-alerts-4.x-2026.06.01",
        "alert-1",
      ],
      _source: {
        "@timestamp": "2026-06-01T00:05:00.000Z",
        rule: { id: "5710", level: 10, description: "first alert" },
        agent: { name: "prod-api-1" },
      },
    };
    const secondHit = {
      _id: "alert-2",
      _index: "wazuh-alerts-4.x-2026.06.01",
      sort: [
        "2026-06-01T00:04:00.000Z",
        "wazuh-alerts-4.x-2026.06.01",
        "alert-2",
      ],
      _source: {
        "@timestamp": "2026-06-01T00:04:00.000Z",
        rule: { id: "5711", level: 5, description: "second alert" },
        agent: { name: "prod-api-2" },
      },
    };
    const response = (hits: unknown[]) =>
      new Response(
        JSON.stringify({
          hits: {
            total: { value: 2, relation: "eq" },
            hits,
          },
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    const fetchMock = vi
      .fn<(url: string, request?: RequestInit) => Promise<Response>>()
      .mockResolvedValueOnce(response([firstHit, secondHit]))
      .mockResolvedValueOnce(response([secondHit]));
    vi.stubGlobal("fetch", fetchMock);

    const firstResult = await action("query_issues").execute(
      context("query_issues", { indexPattern: "wazuh-alerts-*", limit: 1 }),
    );
    const firstData = firstResult.data as Record<string, unknown>;
    const nextCursor = firstData.nextCursor as string;

    expect(firstData).toMatchObject({
      hasMore: true,
      nextCursor: expect.any(String),
      issues: [
        expect.objectContaining({
          externalIssueId: expect.stringContaining("alert-1"),
        }),
      ],
    });

    const firstRequest = fetchMock.mock.calls[0]?.[1];
    const firstBody = JSON.parse(
      typeof firstRequest?.body === "string" ? firstRequest.body : "{}",
    );
    expect(firstBody).toMatchObject({
      size: 2,
      sort: [{ "@timestamp": "desc" }, { _index: "desc" }, { _id: "desc" }],
    });
    expect(firstBody).not.toHaveProperty("from");
    expect(firstBody).not.toHaveProperty("search_after");

    const secondResult = await action("query_issues").execute(
      context("query_issues", {
        indexPattern: "wazuh-alerts-*",
        limit: 1,
        cursor: nextCursor,
      }),
    );
    const secondData = secondResult.data as Record<string, unknown>;
    const secondRequest = fetchMock.mock.calls[1]?.[1];
    const secondBody = JSON.parse(
      typeof secondRequest?.body === "string" ? secondRequest.body : "{}",
    );

    expect(secondData).toMatchObject({
      hasMore: false,
      issues: [
        expect.objectContaining({
          externalIssueId: expect.stringContaining("alert-2"),
        }),
      ],
    });
    expect(secondData.nextCursor).toBeUndefined();
    expect(secondBody).toMatchObject({
      size: 2,
      search_after: firstHit.sort,
    });
    expect(secondBody).not.toHaveProperty("from");
  });

  it("aborts an in-flight alert search when the parent operation is cancelled", async () => {
    const controller = new AbortController();
    let requestSignal: AbortSignal | undefined;
    const fetchMock = vi.fn(
      (_url: string, request?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          requestSignal = request?.signal ?? undefined;
          requestSignal?.addEventListener(
            "abort",
            () => {
              reject(new Error("aborted"));
            },
            {
              once: true,
            },
          );
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = action("search_alerts").execute({
      ...context("search_alerts", { indexPattern: "wazuh-alerts-*" }),
      operation: { signal: controller.signal },
    } as DesktopPluginCodeActionContext);

    await vi.waitFor(() => {
      expect(requestSignal).toBeDefined();
    });
    controller.abort();

    await expect(result).rejects.toThrow();
    expect(requestSignal?.aborted).toBe(true);
  });

  it("reports a safe actionable error when the Wazuh index cannot be reached", async () => {
    const connectError = Object.assign(new Error("Connect Timeout Error"), {
      code: "UND_ERR_CONNECT_TIMEOUT",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(
        new TypeError("fetch failed", {
          cause: connectError,
        }),
      ),
    );

    await expect(
      action("search_alerts").execute(
        context("search_alerts", {
          indexPattern: "wazuh-alerts-*",
        }),
      ),
    ).rejects.toThrow(
      "Wazuh alert search to https://wazuh.example.com:9200 failed: connection timed out (UND_ERR_CONNECT_TIMEOUT)",
    );
  });

  it("rejects non-HTTP Wazuh index URLs before sending basic credentials", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      action("search_alerts").execute({
        ...context("search_alerts", {
          indexPattern: "wazuh-alerts-*",
        }),
        auth: {
          indexUrl: "file:///tmp/wazuh",
          indexUsername: "wazuh-reader",
          indexPassword: "wazuh-secret",
        },
      }),
    ).rejects.toThrow("Wazuh index URL must use http:// or https://");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
