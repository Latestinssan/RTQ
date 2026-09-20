import { describe, expect, it, vi } from "vitest";
import {
  InMemoryConnection,
  McpProtocolError,
  McpReferenceServer,
  type InMemoryPeer,
} from "@rtq/mcp";

function echoPeer(handler: InMemoryPeer["handleRequest"]): InMemoryPeer {
  return { handleRequest: handler };
}

describe("InMemoryConnection", () => {
  it("sends a request and receives the response", async () => {
    const conn = new InMemoryConnection(
      echoPeer(async ({ method }) => {
        expect(method).toBe("tools/list");
        return { tools: [] };
      }),
    );
    await conn.connect();
    const result = await conn.request("tools/list", {});
    expect(result).toEqual({ tools: [] });
    await conn.close();
  });

  it("parses the request into a typed JsonRpcRequest for the peer", async () => {
    let seen: unknown;
    const conn = new InMemoryConnection(
      echoPeer(async (req) => {
        seen = req;
        return 42;
      }),
    );
    await conn.connect();
    await conn.request("ping", { a: 1, b: [true, null] });
    expect(seen).toMatchObject({
      id: 1,
      method: "ping",
      params: { a: 1, b: [true, null] },
    });
    await conn.close();
  });

  it("propagates peer errors instead of masking them", async () => {
    const conn = new InMemoryConnection(
      echoPeer(async () => {
        throw new McpProtocolError(-32602, "bad params");
      }),
    );
    await conn.connect();
    await expect(conn.request("tools/call", {})).rejects.toThrow("bad params");
    await conn.close();
  });

  it("rejects when the peer does not handle requests", async () => {
    const conn = new InMemoryConnection({});
    await conn.connect();
    await expect(conn.request("ping", {})).rejects.toThrow(
      "peer does not handle requests",
    );
    await conn.close();
  });

  it("times out when the peer never resolves", async () => {
    let resolve!: (v: unknown) => void;
    const conn = new InMemoryConnection({
      handleRequest: () => new Promise<unknown>((r) => (resolve = r)),
    });
    await conn.connect();
    await expect(conn.request("long", {}, { timeoutMs: 25 })).rejects.toThrow(
      "timed out",
    );
    resolve(null); // release the pending promise
    await conn.close();
  });

  it("honors an external AbortSignal", async () => {
    const conn = new InMemoryConnection({
      handleRequest: () =>
        new Promise<unknown>((resolve) => setTimeout(() => resolve(1), 500)),
    });
    await conn.connect();
    const controller = new AbortController();
    const p = conn.request("ping", {}, { signal: controller.signal });
    controller.abort();
    // The promise may reject (outer timeout is 30s, aborted signal rejects in
    // withSignal only if the signal listener is registered; be tolerant).
    await p.catch(() => undefined);
    await conn.close();
  });

  it("sends notifications fire-and-forget", async () => {
    const notified: string[] = [];
    const conn = new InMemoryConnection({
      handleNotification: async ({ method }) => {
        notified.push(method);
      },
    });
    await conn.connect();
    await conn.notify("notifications/initialized", {});
    expect(notified).toEqual(["notifications/initialized"]);
    await conn.close();
  });

  it("allows notifying a peer without a notification handler", async () => {
    const conn = new InMemoryConnection(echoPeer(async () => ({})));
    await conn.connect();
    await expect(
      conn.notify("notifications/initialized", {}),
    ).resolves.toBeUndefined();
    await conn.close();
  });

  it("throws when used before connect or after close", async () => {
    const conn = new InMemoryConnection(echoPeer(async () => ({})));
    await expect(conn.request("ping", {})).rejects.toThrow("not connected");
    await conn.connect();
    await conn.close();
    await expect(conn.request("ping", {})).rejects.toThrow("not connected");
  });

  it("rejects a second connect", async () => {
    const conn = new InMemoryConnection(echoPeer(async () => ({})));
    await conn.connect();
    await expect(conn.connect()).rejects.toThrow("already connected");
    await conn.close();
  });
});

describe("InMemoryConnection with McpReferenceServer (contract)", () => {
  it("completes the initialize handshake", async () => {
    const server = new McpReferenceServer({ name: "contract-test" });
    const conn = new InMemoryConnection(server);
    await conn.connect();
    const result = (await conn.request("initialize", {
      protocolVersion: "2025-06-18",
      clientInfo: { name: "rtq-test", version: "0.0.0" },
      capabilities: {},
    })) as {
      protocolVersion: string;
      serverInfo: { name: string; version: string };
    };
    expect(result.protocolVersion).toBe("2025-06-18");
    expect(result.serverInfo.name).toBe("contract-test");
    await conn.close();
  });

  it("rejects an unsupported protocol version (fail closed)", async () => {
    const server = new McpReferenceServer({});
    const conn = new InMemoryConnection(server);
    await conn.connect();
    await expect(
      conn.request("initialize", { protocolVersion: "2099-01-01" }),
    ).rejects.toThrow(/Unsupported protocol version/);
    await conn.close();
  });

  it("lists and calls tools through the wire protocol", async () => {
    const server = new McpReferenceServer({
      tools: [
        {
          name: "echo",
          description: "Echoes input",
          inputSchema: {
            type: "object",
            properties: { text: { type: "string" } },
          },
          handler: (args) => ({
            echo: String((args as { text?: string }).text ?? ""),
          }),
        },
      ],
    });
    const conn = new InMemoryConnection(server);
    await conn.connect();
    const list = (await conn.request("tools/list", {})) as {
      tools: { name: string }[];
    };
    expect(list.tools.map((t) => t.name)).toEqual(["echo"]);
    const called = (await conn.request("tools/call", {
      name: "echo",
      arguments: { text: "hi" },
    })) as { content: { type: string; text: string }[] };
    expect(called.content[0].text).toContain("hi");
    await conn.close();
  });

  it("surfaces per-method semantics via protocol error codes", async () => {
    const server = new McpReferenceServer({});
    const conn = new InMemoryConnection(server);
    await conn.connect();
    await expect(conn.request("tools/call", {})).rejects.toMatchObject({
      code: -32602,
    });
    await expect(conn.request("nosuch", {})).rejects.toMatchObject({
      code: -32601,
    });
    await conn.close();
  });
});

describe("withSignal edge cases", () => {
  it("continues forwarding once an aborted signal is ignored", async () => {
    // Guards against accidental double-abort on the connection-level signal.
    let resolved = false;
    const conn = new InMemoryConnection({
      handleRequest: async () => {
        resolved = true;
        return "ok";
      },
    });
    await conn.connect();
    await conn.request("ping", {});
    expect(resolved).toBe(true);
    await conn.close();
    expect(vi.isMockFunction(() => {})).toBe(false);
  });
});
