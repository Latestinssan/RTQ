import path from "node:path";
import { describe, expect, it } from "vitest";
import { StdioConnection } from "@rtq/mcp";

const fixture = path.resolve(__dirname, "../helpers/stdio-fixture.mjs");

describe("StdioConnection (local MCP process via stdin/stdout)", () => {
  it("performs initialize + ping round trips over stdio", async () => {
    const conn = new StdioConnection(process.execPath, [fixture]);
    await conn.connect();
    const init = (await conn.request("initialize", {
      protocolVersion: "2025-06-18",
      clientInfo: { name: "rtq-test", version: "0.0.0" },
      capabilities: {},
    })) as { serverInfo: { name: string }; protocolVersion: string };
    expect(init.serverInfo.name).toBe("stdio-fixture");
    expect(init.protocolVersion).toBe("2025-06-18");
    await expect(conn.request("ping", {})).resolves.toEqual({});
    await conn.close();
  });

  it("lists and calls tools", async () => {
    const conn = new StdioConnection(process.execPath, [fixture]);
    await conn.connect();
    const list = (await conn.request("tools/list", {})) as {
      tools: { name: string }[];
    };
    expect(list.tools.map((t) => t.name)).toEqual(["echo"]);
    const call = (await conn.request("tools/call", {
      name: "echo",
      arguments: { text: "abc" },
    })) as { content: { type: string; text: string }[] };
    expect(call.content[0].text).toBe("echoed:abc");
    await conn.close();
  });

  it("surfaces JSON-RPC error responses from the process", async () => {
    const conn = new StdioConnection(process.execPath, [fixture]);
    await conn.connect();
    await expect(conn.request("no/method", {})).rejects.toMatchObject({
      code: -32601,
    });
    await conn.close();
  });

  it("times out when the server takes too long", async () => {
    const conn = new StdioConnection(process.execPath, [fixture]);
    await conn.connect();
    await expect(conn.request("slow", {}, { timeoutMs: 30 })).rejects.toThrow(
      /timed out/,
    );
    await conn.close();
  });

  it("rejects requests after close", async () => {
    const conn = new StdioConnection(process.execPath, [fixture]);
    await conn.connect();
    await conn.close();
    await expect(conn.request("ping", {})).rejects.toThrow(/not connected/);
  });

  it("does not require a sandbox spec to run (as local process)", async () => {
    const conn = new StdioConnection(process.execPath, [fixture]);
    await conn.connect();
    expect(conn.enforcement).toBeUndefined();
    await conn.close();
  });
});
