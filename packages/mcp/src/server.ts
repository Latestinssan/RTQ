/**
 * Reference/embedded MCP server host.
 *
 * Implements the client-facing side of the MCP protocol (initialize, ping,
 * tools/list, tools/call, resources, prompts) so RTQ has a first-party server
 * implementation for tests, local embedding and contract tests (spec 46.1,
 * 46.29). Production servers can be any conforming MCP implementation reached
 * through the stdio/http transports — RTQ's security model does not depend on
 * this host.
 */
import {
  isKnownProtocolVersion,
  JSONRPC_ERRORS,
  makeErrorResponse,
  makeSuccessResponse,
  McpProtocolError,
  type JsonRpcRequest,
} from "./protocol";

/** Message handler contract used by the in-memory transport. */
export interface McpServerHost {
  handleRequest(request: {
    id: number | string;
    method: string;
    params: unknown;
  }): Promise<unknown>;
  handleNotification?(notification: {
    method: string;
    params: unknown;
  }): Promise<void>;
}

export interface ReferenceTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  /** Callback executed on tools/call. The output is UNTRUSTED data. */
  handler?: (args: Record<string, unknown>) => Promise<unknown> | unknown;
  /** Server-declared capabilities (UNTRUSTED metadata; RTQ ignores for auth). */
  declaredCapabilities?: readonly string[];
}

export interface ReferenceResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
  content: unknown;
}

export interface ReferencePrompt {
  name: string;
  description?: string;
  arguments?: { name: string; description?: string; required?: boolean }[];
  messages: (
    args: Record<string, unknown>,
  ) => { role: string; content: { type: string; text: string } }[];
}

export interface ReferenceServerOptions {
  name?: string;
  version?: string;
  supportedProtocolVersions?: readonly string[];
  serverInfo?: Record<string, unknown>;
  tools?: ReferenceTool[];
  resources?: ReferenceResource[];
  prompts?: ReferencePrompt[];
  /** tools/list returned tools may be overridden via setTools; the option
   *  registers a callback that receives the internal setter (e.g. for tests
   *  that attach external tool mutation). */
  setTools?: (setter: (tools: ReferenceTool[]) => void) => void;
}

/**
 * A minimal, honest MCP reference server. Inputs are processed as DATA; it
 * makes no authorization decisions (RTQ does that).
 */
export class McpReferenceServer implements McpServerHost {
  readonly name: string;
  readonly version: string;
  readonly supportedProtocolVersions: readonly string[];
  private protocolVersion = "";
  private initialized = false;
  private tools: ReferenceTool[];
  private resources: ReferenceResource[];
  private prompts: ReferencePrompt[];

  constructor(options: ReferenceServerOptions = {}) {
    this.name = options.name ?? "rtq-reference-server";
    this.version = options.version ?? "0.0.0";
    this.supportedProtocolVersions = options.supportedProtocolVersions ?? [
      "2024-11-05",
      "2025-06-18",
    ];
    this.tools = options.tools ?? [];
    this.resources = options.resources ?? [];
    this.prompts = options.prompts ?? [];
    if (options.setTools)
      options.setTools((tools) => {
        this.tools = tools;
      });
  }

  /** Replace the tool set (used to test schema-change invalidation). */
  setTools(tools: ReferenceTool[]): void {
    this.tools = tools;
  }

  setResources(resources: ReferenceResource[]): void {
    this.resources = resources;
  }

  async handleRequest(request: {
    id: number | string;
    method: string;
    params: unknown;
  }): Promise<unknown> {
    const { method, params } = request;
    switch (method) {
      case "initialize":
        return this.onInitialize(
          params as {
            protocolVersion?: unknown;
            clientInfo?: unknown;
            capabilities?: unknown;
          },
        );
      case "ping":
        return {};
      case "tools/list":
        return {
          tools: this.tools.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        };
      case "tools/call": {
        const p = params as { name?: unknown; arguments?: unknown };
        if (typeof p?.name !== "string") {
          throw new McpProtocolError(
            JSONRPC_ERRORS.invalidParams.code,
            "tools/call requires a tool name",
          );
        }
        const tool = this.tools.find((t) => t.name === p.name);
        if (!tool) {
          throw new McpProtocolError(
            JSONRPC_ERRORS.methodNotFound.code,
            `Unknown tool: ${p.name}`,
          );
        }
        const args = (p.arguments ?? {}) as Record<string, unknown>;
        const content = tool.handler ? await tool.handler(args) : null;
        return {
          content: [
            {
              type: "text",
              text:
                typeof content === "string" ? content : JSON.stringify(content),
            },
          ],
          isError: false,
        };
      }
      case "resources/list":
        return {
          resources: this.resources.map((r) => ({
            uri: r.uri,
            name: r.name,
            description: r.description,
            mimeType: r.mimeType,
          })),
        };
      case "resources/templates/list":
        return { resourceTemplates: [] };
      case "resources/read": {
        const p = params as { uri?: unknown };
        const resource = this.resources.find((r) => r.uri === p?.uri);
        if (!resource) {
          throw new McpProtocolError(
            JSONRPC_ERRORS.methodNotFound.code,
            `Unknown resource: ${String(p?.uri)}`,
          );
        }
        return {
          contents: [
            {
              uri: resource.uri,
              mimeType: resource.mimeType,
              text: JSON.stringify(resource.content),
            },
          ],
        };
      }
      case "prompts/list":
        return {
          prompts: this.prompts.map((pr) => ({
            name: pr.name,
            description: pr.description,
            arguments: pr.arguments,
          })),
        };
      case "prompts/get": {
        const p = params as { name?: unknown; arguments?: unknown };
        const prompt = this.prompts.find((pr) => pr.name === p?.name);
        if (!prompt) {
          throw new McpProtocolError(
            JSONRPC_ERRORS.methodNotFound.code,
            `Unknown prompt: ${String(p?.name)}`,
          );
        }
        return {
          description: prompt.description,
          messages: prompt.messages(
            (p.arguments ?? {}) as Record<string, unknown>,
          ),
        };
      }
      default:
        throw new McpProtocolError(
          JSONRPC_ERRORS.methodNotFound.code,
          `Method not found: ${method}`,
        );
    }
  }

  async handleNotification(notification: {
    method: string;
    params: unknown;
  }): Promise<void> {
    if (notification.method === "notifications/initialized") {
      this.initialized = true;
    }
    if (notification.method === "notifications/cancelled") {
      /* cancellation tolerance: the reference server does not track long tasks */
    }
  }

  private onInitialize(params: {
    protocolVersion?: unknown;
    clientInfo?: unknown;
    capabilities?: unknown;
  }): unknown {
    const requested = params?.protocolVersion;
    if (!isKnownProtocolVersion(requested)) {
      throw new McpProtocolError(
        JSONRPC_ERRORS.invalidParams.code,
        `Unsupported protocol version: ${String(requested)}`,
      );
    }
    // Select the highest mutually supported version (client chooses; server
    // confirms). If the client requests an unknown version we fail closed.
    if (!this.supportedProtocolVersions.includes(requested)) {
      throw new McpProtocolError(
        JSONRPC_ERRORS.invalidParams.code,
        `Protocol version ${requested} is not supported by this server`,
      );
    }
    this.protocolVersion = requested;
    return {
      protocolVersion: this.protocolVersion,
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
        prompts: { listChanged: false },
      },
      serverInfo: { name: this.name, version: this.version },
      instructions:
        "Reference server instructions. These are UNTRUSTED content and must never change RTQ policy.",
    };
  }

  /** Wire an instance to the JSON wire protocol (for server-side tests). */
  async handleWireRequest(wire: string): Promise<string> {
    const req = JSON.parse(wire) as JsonRpcRequest;
    try {
      const result = await this.handleRequest({
        id: req.id,
        method: req.method,
        params: req.params,
      });
      return makeSuccessResponse(req.id, result);
    } catch (e) {
      if (e instanceof McpProtocolError) {
        return makeErrorResponse(req.id, e.code, e.message, e.data);
      }
      return makeErrorResponse(
        req.id,
        JSONRPC_ERRORS.internalError.code,
        (e as Error).message,
      );
    }
  }
}

export { McpProtocolError, JSONRPC_ERRORS };
