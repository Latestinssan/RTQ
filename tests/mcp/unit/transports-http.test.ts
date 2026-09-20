import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  HttpConnection,
  makeSuccessResponse,
  makeErrorResponse,
} from "@rtq/mcp";

/**
 * Contract tests for the streamable-HTTP transport against a local mock MCP
 * endpoint. Localhost is treated as an untrusted peer (spec 46.13); these
 * tests exercise the wire behavior only, never authorization.
 */

let server: Server;
let baseUrl: string;

function jsonResponse(
  res: ServerResponse<IncomingMessage>,
  status: number,
  body: string,
  contentType = "application/json",
) {
  res.writeHead(status, {
    "content-type": contentType,
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

beforeEach(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => (body += chunk.toString()));
    req.on("end", () => {
      let parsed: { id?: number | string; method?: string };
      try {
        parsed = JSON.parse(body);
      } catch {
        jsonResponse(res, 400, makeErrorResponse(0, -32700, "Parse error"));
        return;
      }
      const id = parsed.id ?? 0;
      if (parsed.method === "initialize") {
        jsonResponse(
          res,
          200,
          makeSuccessResponse(id, {
            protocolVersion: "2025-06-18",
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "mock", version: "0.0.0" },
          }),
        );
        return;
      }
      if (parsed.method === "ping") {
        jsonResponse(res, 200, makeSuccessResponse(id, {}));
        return;
      }
      if (parsed.method === "tools/list") {
        jsonResponse(res, 200, makeSuccessResponse(id, { tools: [] }));
        return;
      }
      jsonResponse(res, 200, makeErrorResponse(id, -32601, "Method not found"));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}/mcp`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("HttpConnection (mock streamable-HTTP MCP endpoint)", () => {
  it("runs a request/response round trip", async () => {
    const conn = new HttpConnection(baseUrl);
    await conn.connect();
    const result = await conn.request("ping", {});
    expect(result).toEqual({});
    await conn.close();
  });

  it("sends initialize with protocol params", async () => {
    const conn = new HttpConnection(baseUrl);
    await conn.connect();
    const result = (await conn.request("initialize", {
      protocolVersion: "2025-06-18",
      clientInfo: { name: "rtq-test" },
      capabilities: {},
    })) as { protocolVersion: string; serverInfo: { name: string } };
    expect(result.protocolVersion).toBe("2025-06-18");
    expect(result.serverInfo.name).toBe("mock");
    await conn.close();
  });

  it("rejects non-JSON/HTTP responses", async () => {
    const oneShot = createServer((_req, res) => {
      jsonResponse(res, 500, "boom");
    });
    await new Promise<void>((resolve) =>
      oneShot.listen(0, "127.0.0.1", resolve),
    );
    const { port } = oneShot.address() as AddressInfo;
    try {
      const conn = new HttpConnection(`http://127.0.0.1:${port}/`);
      await conn.connect();
      await expect(conn.request("ping", {})).rejects.toThrow(/HTTP 500/);
      await conn.close();
    } finally {
      await new Promise<void>((resolve) => oneShot.close(() => resolve()));
    }
  });

  it("enforces request timeouts", async () => {
    const slow = createServer((_req, res) => {
      // Never respond — let the client timeout.
      void res;
    });
    await new Promise<void>((resolve) => slow.listen(0, "127.0.0.1", resolve));
    const { port } = slow.address() as AddressInfo;
    try {
      const conn = new HttpConnection(`http://127.0.0.1:${port}/`);
      await conn.connect();
      await expect(conn.request("ping", {}, { timeoutMs: 60 })).rejects.toThrow(
        /timed out/,
      );
      await conn.close();
    } finally {
      await new Promise<void>((resolve) => slow.close(() => resolve()));
    }
  });

  it("throws for unsupported URL schemes at connect time", async () => {
    const conn = new HttpConnection("ftp://example.com/mcp");
    await expect(conn.connect()).rejects.toThrow(/unsupported HTTP transport/);
  });

  it("surfaces JSON-RPC error responses", async () => {
    const conn = new HttpConnection(baseUrl);
    await conn.connect();
    await expect(conn.request("no/method", {})).rejects.toMatchObject({
      code: -32601,
    });
    await conn.close();
  });

  it("parses SSE-encoded responses", async () => {
    const sse = createServer((req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        const id = parsed.id ?? 0;
        const payload = makeSuccessResponse(id, { via: "sse" });
        jsonResponse(res, 200, `data: ${payload}\n\n`, "text/event-stream");
      });
    });
    await new Promise<void>((resolve) => sse.listen(0, "127.0.0.1", resolve));
    const { port } = sse.address() as AddressInfo;
    try {
      const conn = new HttpConnection(`http://127.0.0.1:${port}/`);
      await conn.connect();
      const result = await conn.request("ping", {});
      expect(result).toEqual({ via: "sse" });
      await conn.close();
    } finally {
      await new Promise<void>((resolve) => sse.close(() => resolve()));
    }
  });

  it("sends custom headers (auth header contract)", async () => {
    let sawAuth: string | undefined;
    const capturing = createServer((req, res) => {
      sawAuth = req.headers["authorization"] as string | undefined;
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        jsonResponse(res, 200, makeSuccessResponse(parsed.id ?? 0, {}));
      });
    });
    await new Promise<void>((resolve) =>
      capturing.listen(0, "127.0.0.1", resolve),
    );
    const { port } = capturing.address() as AddressInfo;
    try {
      const conn = new HttpConnection(`http://127.0.0.1:${port}/`, {
        headers: { authorization: "Bearer test-only-token" },
      });
      await conn.connect();
      await conn.request("ping", {});
      expect(sawAuth).toBe("Bearer test-only-token");
      await conn.close();
    } finally {
      await new Promise<void>((resolve) => capturing.close(() => resolve()));
    }
  });
});
