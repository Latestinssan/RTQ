import { describe, expect, it, vi } from "vitest";
import {
  JSONRPC_ERRORS,
  McpProtocolError,
  McpReferenceServer,
  makeRequest,
  type ReferenceTool,
} from "@rtq/mcp";

const textTool: ReferenceTool = {
  name: "reverse",
  description: "Reverses a string",
  inputSchema: {
    type: "object",
    properties: { input: { type: "string" } },
    required: ["input"],
  },
  handler: (args) => String(args.input).split("").reverse().join(""),
};

const resource = {
  uri: "memory://status",
  name: "Status",
  description: "Sample resource",
  mimeType: "application/json",
  content: { state: "ok" },
};

describe("McpReferenceServer (reference/mock host)", () => {
  it("serves initialize with negotiated protocol version", async () => {
    const server = new McpReferenceServer({ name: "ref", version: "1.2.3" });
    const result = (await server.handleRequest({
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" },
    })) as {
      protocolVersion: string;
      serverInfo: { name: string; version: string };
      capabilities: { tools: { listChanged: boolean } };
    };
    expect(result.protocolVersion).toBe("2024-11-05");
    expect(result.serverInfo).toEqual({ name: "ref", version: "1.2.3" });
    expect(result.capabilities.tools.listChanged).toBe(false);
  });

  it("fails closed on unknown protocol versions", async () => {
    const server = new McpReferenceServer({});
    await expect(
      server.handleRequest({
        id: 1,
        method: "initialize",
        params: { protocolVersion: "1.0" },
      }),
    ).rejects.toThrow(McpProtocolError);
  });

  it("rejects a protocol version the server does not support", async () => {
    const server = new McpReferenceServer({
      supportedProtocolVersions: ["2024-11-05"],
    });
    await expect(
      server.handleRequest({
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      }),
    ).rejects.toThrow("not supported by this server");
  });

  it("answers ping", async () => {
    const server = new McpReferenceServer({});
    await expect(
      server.handleRequest({ id: 1, method: "ping", params: {} }),
    ).resolves.toEqual({});
  });

  it("handles tools/list and tools/call", async () => {
    const server = new McpReferenceServer({ tools: [textTool] });
    const list = (await server.handleRequest({
      id: 1,
      method: "tools/list",
      params: {},
    })) as {
      tools: {
        name: string;
        description: string;
        inputSchema: Record<string, unknown>;
      }[];
    };
    expect(list.tools).toHaveLength(1);
    expect(list.tools[0].name).toBe("reverse");
    // The reference server serializes args through the declared schema contract.
    const call = (await server.handleRequest({
      id: 2,
      method: "tools/call",
      params: { name: "reverse", arguments: { input: "abc" } },
    })) as { content: { type: string; text: string }[]; isError: boolean };
    expect(call.isError).toBe(false);
    expect(call.content[0].type).toBe("text");
    expect(String(call.content[0].text)).toContain("cba");
  });

  it("calls a tool with no handler (returns null content)", async () => {
    const server = new McpReferenceServer({
      tools: [
        { name: "noop", inputSchema: { type: "object", properties: {} } },
      ],
    });
    const call = (await server.handleRequest({
      id: 1,
      method: "tools/call",
      params: { name: "noop", arguments: {} },
    })) as { content: { type: string; text: string }[] };
    expect(call.content[0].text).toBe("null");
  });

  it("returns methodNotFound for unknown tools and methods", async () => {
    const server = new McpReferenceServer({ tools: [textTool] });
    await expect(
      server.handleRequest({
        id: 1,
        method: "tools/call",
        params: { name: "nope" },
      }),
    ).rejects.toMatchObject({ code: JSONRPC_ERRORS.methodNotFound.code });
    await expect(
      server.handleRequest({
        id: 1,
        method: "definitely/not-a-method",
        params: {},
      }),
    ).rejects.toMatchObject({ code: JSONRPC_ERRORS.methodNotFound.code });
  });

  it("returns invalidParams when tools/call lacks a name", async () => {
    const server = new McpReferenceServer({ tools: [textTool] });
    await expect(
      server.handleRequest({ id: 1, method: "tools/call", params: {} }),
    ).rejects.toMatchObject({ code: JSONRPC_ERRORS.invalidParams.code });
  });

  it("services resources/list and resources/read", async () => {
    const server = new McpReferenceServer({ resources: [resource] });
    const list = (await server.handleRequest({
      id: 1,
      method: "resources/list",
      params: {},
    })) as { resources: { uri: string; name?: string }[] };
    expect(list.resources[0].uri).toBe("memory://status");
    const read = (await server.handleRequest({
      id: 2,
      method: "resources/read",
      params: { uri: "memory://status" },
    })) as { contents: { uri: string; text: string }[] };
    expect(JSON.parse(read.contents[0].text)).toEqual({ state: "ok" });
    // The server exposes prompt-like instructions as untrusted content, never
    // as instructions to the runtime.
  });

  it("returns templates list and rejects unknown resource reads", async () => {
    const server = new McpReferenceServer({ resources: [resource] });
    const templates = (await server.handleRequest({
      id: 1,
      method: "resources/templates/list",
      params: {},
    })) as { resourceTemplates: unknown[] };
    expect(templates.resourceTemplates).toEqual([]);
    await expect(
      server.handleRequest({
        id: 2,
        method: "resources/read",
        params: { uri: "nope" },
      }),
    ).rejects.toMatchObject({ code: JSONRPC_ERRORS.methodNotFound.code });
  });

  it("services prompts/list and prompts/get", async () => {
    const server = new McpReferenceServer({
      prompts: [
        {
          name: "translate",
          description: "Translate",
          arguments: [{ name: "target", required: true }],
          messages: (args) => [
            {
              role: "user",
              content: {
                type: "text",
                text: `Translate to ${String(args.target)}`,
              },
            },
          ],
        },
      ],
    });
    const list = (await server.handleRequest({
      id: 1,
      method: "prompts/list",
      params: {},
    })) as { prompts: { name: string }[] };
    expect(list.prompts[0].name).toBe("translate");
    const get = (await server.handleRequest({
      id: 2,
      method: "prompts/get",
      params: { name: "translate", arguments: { target: "fr" } },
    })) as { messages: { role: string }[] };
    expect(get.messages[0].role).toBe("user");
  });

  it("treats notifications as side-effect free", async () => {
    const server = new McpReferenceServer({});
    await expect(
      server.handleNotification({
        method: "notifications/initialized",
        params: {},
      }),
    ).resolves.toBeUndefined();
    await expect(
      server.handleNotification({
        method: "notifications/cancelled",
        params: {},
      }),
    ).resolves.toBeUndefined();
  });

  it("supports dynamic tool replacement via setTools (schema-change simulation)", async () => {
    const server = new McpReferenceServer({ tools: [textTool] });
    const handler = vi.fn(async (args) => args);
    server.setTools([
      { name: "new", inputSchema: { type: "object", properties: {} }, handler },
    ]);
    const list = (await server.handleRequest({
      id: 1,
      method: "tools/list",
      params: {},
    })) as { tools: { name: string }[] };
    expect(list.tools.map((t) => t.name)).toEqual(["new"]);
    await server.handleRequest({
      id: 2,
      method: "tools/call",
      params: { name: "new", arguments: {} },
    });
    expect(handler).toHaveBeenCalledOnce();
  });

  it("exposes setTools registration through constructor options", async () => {
    const setter = vi.fn();
    const server = new McpReferenceServer({
      setTools: (set) => setter.mockImplementation(set),
    });
    // The registered setter mutates the instance.
    setter([
      { name: "via-option", inputSchema: { type: "object", properties: {} } },
    ] as never);
    const list = (await server.handleRequest({
      id: 1,
      method: "tools/list",
      params: {},
    })) as { tools: { name: string }[] };
    expect(list.tools.map((t) => t.name)).toEqual(["via-option"]);
  });

  it("processes wire requests (server-side fixture for JSON-RPC tests)", async () => {
    const server = new McpReferenceServer({ tools: [textTool] });
    const wire = makeRequest(5, "ping", {});
    const response = await server.handleWireRequest(wire);
    const parsed = JSON.parse(response) as {
      jsonrpc: string;
      id: number;
      result: unknown;
    };
    expect(parsed.jsonrpc).toBe("2.0");
    expect(parsed.id).toBe(5);
    expect(parsed.result).toEqual({});
  });

  it("returns internal error responses for unexpected handler failures", async () => {
    const server = new McpReferenceServer({
      tools: [
        {
          name: "boom",
          inputSchema: { type: "object", properties: {} },
          handler: () => {
            throw new Error("kaboom");
          },
        },
      ],
    });
    const response = await server.handleWireRequest(
      makeRequest(1, "tools/call", { name: "boom", arguments: {} }),
    );
    const parsed = JSON.parse(response) as {
      error: { code: number; message: string };
    };
    expect(parsed.error.code).toBe(JSONRPC_ERRORS.internalError.code);
  });
});
