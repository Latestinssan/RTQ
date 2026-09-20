/**
 * Minimal MCP protocol layer (JSON-RPC 2.0 over structured transports).
 *
 * Implemented directly against the MCP wire protocol so RTQ's security model
 * is never coupled to one MCP SDK (spec 46.28). SDK behavior is not RTQ
 * authorization; this client only speaks the protocol.
 *
 * Honest scope (spec 46.29): protocol versions 2024-11-05 and 2025-06-18 are
 * implemented and exercised by the in-memory/stdio/http transports against the
 * reference server in this package, plus adversarial malformed-message tests.
 * This is NOT a claim of universal MCP compliance.
 */

/** Protocol versions this client can announce / accept. */
export const MCP_SUPPORTED_PROTOCOL_VERSIONS = [
  "2024-11-05",
  "2025-06-18",
] as const;
export const MCP_LATEST_PROTOCOL_VERSION = "2025-06-18";

export const MCP_METHODS = {
  initialize: "initialize",
  initialized: "notifications/initialized",
  ping: "ping",
  toolsList: "tools/list",
  toolsCall: "tools/call",
  resourcesList: "resources/list",
  resourcesTemplatesList: "resources/templates/list",
  resourcesRead: "resources/read",
  promptsList: "prompts/list",
  promptsGet: "prompts/get",
  cancelled: "notifications/cancelled",
} as const;

export interface ProtocolLimits {
  /** Maximum accepted message byte size. */
  maxMessageBytes?: number;
  /** Reject unknown top-level envelope fields (default true for security). */
  strictEnvelope?: boolean;
}

export const DEFAULT_PROTOCOL_LIMITS: Required<
  Pick<ProtocolLimits, "maxMessageBytes" | "strictEnvelope">
> = {
  maxMessageBytes: 1 * 1024 * 1024,
  strictEnvelope: true,
};

const ENVELOPE_KEYS = new Set([
  "jsonrpc",
  "id",
  "method",
  "params",
  "result",
  "error",
]);

export class McpProtocolError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "McpProtocolError";
    this.code = code;
    this.data = data;
  }
}

/** JSON-RPC error codes (MCP section 6.1). */
export const JSONRPC_ERRORS = {
  parseError: { code: -32700, message: "Parse error" },
  invalidRequest: { code: -32600, message: "Invalid request" },
  methodNotFound: { code: -32601, message: "Method not found" },
  invalidParams: { code: -32602, message: "Invalid params" },
  internalError: { code: -32603, message: "Internal error" },
} as const;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface JsonRpcResponseOk {
  jsonrpc: "2.0";
  id: number | string;
  result: unknown;
}

export interface JsonRpcResponseError {
  jsonrpc: "2.0";
  id: number | string;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcResponseOk | JsonRpcResponseError;

export type ParsedMessage =
  | { kind: "request"; request: JsonRpcRequest; raw: string }
  | { kind: "notification"; notification: JsonRpcNotification; raw: string }
  | { kind: "response"; response: JsonRpcResponse; raw: string }
  | { kind: "error"; reason: string; code: number; raw: string };

export interface ParseOptions {
  limits?: ProtocolLimits;
}

function isJsonRpcVersion(v: unknown): v is "2.0" {
  return v === "2.0";
}

function isValidId(id: unknown): id is number | string {
  return (
    (typeof id === "number" && Number.isInteger(id)) ||
    (typeof id === "string" && id.length > 0)
  );
}

/**
 * Parse a single JSON-RPC message from wire text. SAFE by construction:
 *  - byte size limits are enforced before JSON parsing
 *  - non-object / wrong-version / structurally invalid messages produce a typed
 *    error result instead of throwing into the caller
 *  - strictly unknown envelope fields are rejected when strictEnvelope (default)
 */
export function parseJsonRpcMessage(
  wire: string,
  options: ParseOptions = {},
): ParsedMessage {
  const limits = { ...DEFAULT_PROTOCOL_LIMITS, ...options.limits };
  if (wire.length > limits.maxMessageBytes) {
    return {
      kind: "error",
      reason: `message exceeds maxMessageBytes (${limits.maxMessageBytes})`,
      code: JSONRPC_ERRORS.parseError.code,
      raw: wire,
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(wire);
  } catch {
    return {
      kind: "error",
      reason: "invalid JSON",
      code: JSONRPC_ERRORS.parseError.code,
      raw: wire,
    };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      kind: "error",
      reason: "message must be a JSON object",
      code: JSONRPC_ERRORS.invalidRequest.code,
      raw: wire,
    };
  }
  const msg = parsed as Record<string, unknown>;
  if (limits.strictEnvelope) {
    for (const key of Object.keys(msg)) {
      if (!ENVELOPE_KEYS.has(key)) {
        return {
          kind: "error",
          reason: `unknown envelope field "${key}"`,
          code: JSONRPC_ERRORS.invalidRequest.code,
          raw: wire,
        };
      }
    }
  }
  if (!isJsonRpcVersion(msg["jsonrpc"])) {
    return {
      kind: "error",
      reason: 'jsonrpc must be "2.0"',
      code: JSONRPC_ERRORS.invalidRequest.code,
      raw: wire,
    };
  }

  const hasId = "id" in msg;
  const hasMethod = "method" in msg;
  const hasResult = "result" in msg;
  const hasError = "error" in msg;

  if (hasMethod) {
    if (typeof msg["method"] !== "string" || msg["method"].length === 0) {
      return {
        kind: "error",
        reason: "method must be a non-empty string",
        code: JSONRPC_ERRORS.invalidRequest.code,
        raw: wire,
      };
    }
    if (
      msg["params"] !== undefined &&
      (msg["params"] === null ||
        typeof msg["params"] !== "object" ||
        Array.isArray(msg["params"]))
    ) {
      return {
        kind: "error",
        reason: "params must be an object when present",
        code: JSONRPC_ERRORS.invalidRequest.code,
        raw: wire,
      };
    }
    // A message with method but no id is a notification; with an id it is a request.
    if (!hasId) {
      return {
        kind: "notification",
        notification: {
          jsonrpc: "2.0",
          method: msg["method"] as string,
          ...(msg["params"] !== undefined ? { params: msg["params"] } : {}),
        },
        raw: wire,
      };
    }
    if (!isValidId(msg["id"])) {
      return {
        kind: "error",
        reason: "invalid request id",
        code: JSONRPC_ERRORS.invalidRequest.code,
        raw: wire,
      };
    }
    if (hasResult || hasError) {
      return {
        kind: "error",
        reason: "request must not carry result or error",
        code: JSONRPC_ERRORS.invalidRequest.code,
        raw: wire,
      };
    }
    return {
      kind: "request",
      request: {
        jsonrpc: "2.0",
        id: msg["id"] as number | string,
        method: msg["method"] as string,
        ...(msg["params"] !== undefined ? { params: msg["params"] } : {}),
      },
      raw: wire,
    };
  }

  // Response: requires id and exactly one of result/error.
  if (!hasId || !isValidId(msg["id"])) {
    return {
      kind: "error",
      reason: "response missing a valid id",
      code: JSONRPC_ERRORS.invalidRequest.code,
      raw: wire,
    };
  }
  if (hasResult === hasError) {
    return {
      kind: "error",
      reason: "response must carry exactly one of result or error",
      code: JSONRPC_ERRORS.invalidRequest.code,
      raw: wire,
    };
  }
  const id = msg["id"] as number | string;
  if (hasResult) {
    return {
      kind: "response",
      response: { jsonrpc: "2.0", id, result: msg["result"] },
      raw: wire,
    };
  }
  const err = msg["error"] as {
    code?: unknown;
    message?: unknown;
    data?: unknown;
  };
  if (
    err === null ||
    typeof err !== "object" ||
    typeof err["code"] !== "number" ||
    typeof err["message"] !== "string"
  ) {
    return {
      kind: "error",
      reason: "malformed error object",
      code: JSONRPC_ERRORS.internalError.code,
      raw: wire,
    };
  }
  return {
    kind: "response",
    response: {
      jsonrpc: "2.0",
      id,
      error: {
        code: err["code"],
        message: err["message"],
        ...(err["data"] !== undefined ? { data: err["data"] } : {}),
      },
    },
    raw: wire,
  };
}

export function makeRequest(
  id: number | string,
  method: string,
  params?: unknown,
): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    method,
    ...(params !== undefined ? { params } : {}),
  });
}

export function makeNotification(method: string, params?: unknown): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    method,
    ...(params !== undefined ? { params } : {}),
  });
}

export function makeSuccessResponse(
  id: number | string,
  result: unknown,
): string {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

export function makeErrorResponse(
  id: number | string,
  code: number,
  message: string,
  data?: unknown,
): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    error: { code, message, ...(data !== undefined ? { data } : {}) },
  });
}

/**
 * Negotiate the protocol version: highest version supported by both sides.
 * Returns null when there is no overlap (the caller must fail closed).
 */
export function negotiateProtocolVersion(
  clientSupported: readonly string[],
  serverSupported: readonly string[] | undefined,
): string | null {
  if (!serverSupported || serverSupported.length === 0) {
    // No declared support: assume the oldest version we know how to speak
    // (MCP_SUPPORTED_PROTOCOL_VERSIONS is ordered oldest -> newest).
    return clientSupported[0] as string;
  }
  // Highest mutually supported version: scan newest -> oldest.
  for (let i = clientSupported.length - 1; i >= 0; i--) {
    const version = clientSupported[i] as string;
    if (serverSupported.includes(version)) return version;
  }
  return null;
}

/** Validate a protocol version string (defense against junk announcements). */
export function isKnownProtocolVersion(version: unknown): version is string {
  return (
    typeof version === "string" &&
    (MCP_SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(version)
  );
}
