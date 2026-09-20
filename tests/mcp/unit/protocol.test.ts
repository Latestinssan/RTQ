import { describe, expect, it } from "vitest";
import {
  DEFAULT_PROTOCOL_LIMITS,
  isKnownProtocolVersion,
  JSONRPC_ERRORS,
  MCP_LATEST_PROTOCOL_VERSION,
  MCP_SUPPORTED_PROTOCOL_VERSIONS,
  makeErrorResponse,
  makeNotification,
  makeRequest,
  makeSuccessResponse,
  negotiateProtocolVersion,
  parseJsonRpcMessage,
} from "@rtq/mcp";

describe("parseJsonRpcMessage", () => {
  it("parses a valid request with params", () => {
    const wire =
      '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":1}}';
    const parsed = parseJsonRpcMessage(wire);
    expect(parsed.kind).toBe("request");
    if (parsed.kind === "request") {
      expect(parsed.request.id).toBe(1);
      expect(parsed.request.method).toBe("tools/list");
      expect(parsed.request.params).toEqual({ x: 1 });
      expect(parsed.raw).toBe(wire);
    }
  });

  it("parses a request without params", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":"a","method":"ping"}',
    );
    expect(parsed.kind).toBe("request");
    if (parsed.kind === "request") {
      expect(parsed.request.id).toBe("a");
      expect(parsed.request.params).toBeUndefined();
    }
  });

  it("parses a notification (no id)", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    );
    expect(parsed.kind).toBe("notification");
    if (parsed.kind === "notification") {
      expect(parsed.notification.method).toBe("notifications/initialized");
    }
  });

  it("parses a success response", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":2,"result":{"ok":true}}',
    );
    expect(parsed.kind).toBe("response");
    if (parsed.kind === "response" && "result" in parsed.response) {
      expect(parsed.response.id).toBe(2);
      expect(parsed.response.result).toEqual({ ok: true });
    }
  });

  it("parses an error response", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}',
    );
    expect(parsed.kind).toBe("response");
    if (parsed.kind === "response" && "error" in parsed.response) {
      expect(parsed.response.error.code).toBe(-32601);
      expect(parsed.response.error.message).toBe("Method not found");
    }
  });

  it("rejects invalid JSON with a parse error", () => {
    const parsed = parseJsonRpcMessage("{not json");
    expect(parsed.kind).toBe("error");
    if (parsed.kind === "error") {
      expect(parsed.code).toBe(JSONRPC_ERRORS.parseError.code);
    }
  });

  it("rejects oversized messages before parsing", () => {
    const big = `{"jsonrpc":"2.0","id":1,"method":"x","params":{"blob":"${"a".repeat(2000)}"}}`;
    const parsed = parseJsonRpcMessage(big, {
      limits: { maxMessageBytes: 100 },
    });
    expect(parsed.kind).toBe("error");
    if (parsed.kind === "error") {
      expect(parsed.reason).toContain("maxMessageBytes");
    }
  });

  it("rejects non-object top-level messages", () => {
    expect(parseJsonRpcMessage("42").kind).toBe("error");
    expect(parseJsonRpcMessage("null").kind).toBe("error");
    expect(parseJsonRpcMessage("[1,2]").kind).toBe("error");
  });

  it("rejects unknown envelope fields in strict mode (default)", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":1,"method":"ping","evil":"x"}',
    );
    expect(parsed.kind).toBe("error");
    if (parsed.kind === "error") expect(parsed.reason).toContain("evil");
  });

  it("allows unknown envelope fields in non-strict mode", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":1,"method":"ping","evil":"x"}',
      { limits: { strictEnvelope: false } },
    );
    expect(parsed.kind).toBe("request");
  });

  it("rejects wrong jsonrpc version", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"1.0","id":1,"method":"ping"}',
    );
    expect(parsed.kind).toBe("error");
  });

  it("rejects invalid request ids (fraction, empty string)", () => {
    expect(
      parseJsonRpcMessage('{"jsonrpc":"2.0","id":1.5,"method":"ping"}').kind,
    ).toBe("error");
    expect(
      parseJsonRpcMessage('{"jsonrpc":"2.0","id":"","method":"ping"}').kind,
    ).toBe("error");
  });

  it("rejects a request that carries result or error", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}',
    );
    expect(parsed.kind).toBe("error");
  });

  it("rejects a response missing an id", () => {
    const parsed = parseJsonRpcMessage('{"jsonrpc":"2.0","result":{}}');
    expect(parsed.kind).toBe("error");
  });

  it("rejects a response with both result and error", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}',
    );
    expect(parsed.kind).toBe("error");
  });

  it("rejects a malformed error object", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":1,"error":"nope"}',
    );
    expect(parsed.kind).toBe("error");
  });

  it("rejects params that are not an object", () => {
    const parsed = parseJsonRpcMessage(
      '{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}',
    );
    expect(parsed.kind).toBe("error");
  });

  it("honors a custom maxMessageBytes from ProtocolLimits", () => {
    const message = makeRequest(1, "ping");
    const parsed = parseJsonRpcMessage(message, {
      limits: { maxMessageBytes: DEFAULT_PROTOCOL_LIMITS.maxMessageBytes },
    });
    expect(parsed.kind).toBe("request");
  });
});

describe("message builders", () => {
  it("makeRequest round-trips", () => {
    const parsed = parseJsonRpcMessage(
      makeRequest(7, "tools/call", { name: "x" }),
    );
    expect(parsed.kind).toBe("request");
    if (parsed.kind === "request") {
      expect(parsed.request.id).toBe(7);
      expect(parsed.request.params).toEqual({ name: "x" });
    }
  });

  it("makeNotification round-trips", () => {
    const parsed = parseJsonRpcMessage(
      makeNotification("notifications/cancelled", { requestId: 3 }),
    );
    expect(parsed.kind).toBe("notification");
  });

  it("makeSuccessResponse round-trips", () => {
    const parsed = parseJsonRpcMessage(makeSuccessResponse(1, { ok: true }));
    expect(parsed.kind).toBe("response");
    if (parsed.kind === "response" && "result" in parsed.response)
      expect(parsed.response.result).toEqual({ ok: true });
  });

  it("makeErrorResponse round-trips", () => {
    const parsed = parseJsonRpcMessage(
      makeErrorResponse(1, -32602, "bad", { why: "x" }),
    );
    expect(parsed.kind).toBe("response");
    if (parsed.kind === "response" && "error" in parsed.response) {
      expect(parsed.response.error.code).toBe(-32602);
      expect(parsed.response.error.data).toEqual({ why: "x" });
    }
  });
});

describe("negotiateProtocolVersion", () => {
  it("selects the highest mutually supported version", () => {
    expect(
      negotiateProtocolVersion(MCP_SUPPORTED_PROTOCOL_VERSIONS, ["2025-06-18"]),
    ).toBe("2025-06-18");
    expect(
      negotiateProtocolVersion(MCP_SUPPORTED_PROTOCOL_VERSIONS, [
        "2024-11-05",
        "2025-06-18",
      ]),
    ).toBe("2025-06-18");
  });

  it("falls back to the oldest client version when server declares none", () => {
    expect(
      negotiateProtocolVersion(MCP_SUPPORTED_PROTOCOL_VERSIONS, undefined),
    ).toBe("2024-11-05");
    expect(negotiateProtocolVersion(MCP_SUPPORTED_PROTOCOL_VERSIONS, [])).toBe(
      "2024-11-05",
    );
  });

  it("returns null when there is no overlap (caller must fail closed)", () => {
    expect(
      negotiateProtocolVersion(MCP_SUPPORTED_PROTOCOL_VERSIONS, ["2099-01-01"]),
    ).toBe(null);
  });
});

describe("isKnownProtocolVersion", () => {
  it("accepts known versions only", () => {
    expect(isKnownProtocolVersion(MCP_LATEST_PROTOCOL_VERSION)).toBe(true);
    expect(isKnownProtocolVersion("2024-11-05")).toBe(true);
    expect(isKnownProtocolVersion("garbage")).toBe(false);
    expect(isKnownProtocolVersion(42)).toBe(false);
    expect(isKnownProtocolVersion(undefined)).toBe(false);
  });
});
