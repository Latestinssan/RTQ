/**
 * MCP transports (spec 46.13).
 *
 * SECURITY PRINCIPLES:
 *  - localhost is NOT trusted (spec 46.13): a local stdio process is an
 *    untrusted peer until it authenticates and RTQ authorizes it.
 *  - sandboxed local execution is fail-closed: when a sandbox is REQUIRED and
 *    the platform cannot construct one, the connection is refused.
 *  - all wire traffic passes through the JSON-RPC parser (size limits, strict
 *    envelope) regardless of transport.
 */
import { spawn, type ChildProcess } from "child_process";
import {
  createSandbox,
  defaultWorkspace,
  generateSeatbeltProfile,
  type EnforcementReport,
  type SandboxSpec,
} from "@rtq/sandbox";
import {
  makeNotification,
  makeRequest,
  MCP_METHODS,
  parseJsonRpcMessage,
  type JsonRpcResponse,
  type ProtocolLimits,
} from "./protocol";

export interface McpConnection {
  readonly kind: "in-memory" | "stdio" | "http";
  connect(): Promise<void>;
  /** Send a JSON-RPC request and await the matching response. */
  request(
    method: string,
    params: unknown,
    opts: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<unknown>;
  /** Send a JSON-RPC notification (fire and forget). */
  notify(method: string, params: unknown): Promise<void>;
  close(): Promise<void>;
  /** Enforcement report when the remote/local process runs inside an OS sandbox. */
  readonly enforcement?: EnforcementReport;
  readonly protocolLimits: ProtocolLimits;
}

export interface InMemoryPeer {
  /** Handle an inbound request; returns the response payload or throws McpProtocolError. */
  handleRequest?(request: {
    id: number | string;
    method: string;
    params?: unknown;
  }): Promise<unknown>;
  /** Handle an inbound notification. */
  handleNotification?(notification: {
    method: string;
    params?: unknown;
  }): Promise<void>;
}

/**
 * In-memory transport. Messages are serialized through the same JSON-RPC
 * parser as the wire transports so parsing behavior is exercised identically.
 */
export class InMemoryConnection implements McpConnection {
  readonly kind = "in-memory" as const;
  readonly protocolLimits: ProtocolLimits;
  private readonly peer: InMemoryPeer;
  private nextId = 1;
  private open = false;

  constructor(peer: InMemoryPeer, protocolLimits: ProtocolLimits = {}) {
    this.peer = peer;
    this.protocolLimits = protocolLimits;
  }

  async connect(): Promise<void> {
    if (this.open) throw new Error("in-memory transport already connected");
    this.open = true;
  }

  async request(
    method: string,
    params: unknown,
    opts: { timeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<unknown> {
    if (!this.open) throw new Error("transport not connected");
    const id = this.nextId++;
    const wire = makeRequest(id, method, params);
    const parsed = parseJsonRpcMessage(wire, { limits: this.protocolLimits });
    if (parsed.kind === "error" || parsed.kind !== "request") {
      throw new Error(
        `in-memory request failed to serialize: ${
          parsed.kind === "error" ? parsed.reason : "unexpected message kind"
        }`,
      );
    }
    if (!this.peer.handleRequest)
      throw new Error("peer does not handle requests");
    const result = await withSignal(
      opts.timeoutMs ?? 30_000,
      opts.signal,
      this.peer.handleRequest({
        id: parsed.request.id,
        method: parsed.request.method,
        params: parsed.request.params,
      }),
    );
    // Serialize -> parse the response through the same validation path.
    const responseWire = JSON.stringify({ jsonrpc: "2.0", id, result });
    const parsedResponse = parseJsonRpcMessage(responseWire, {
      limits: this.protocolLimits,
    });
    if (parsedResponse.kind === "error" || parsedResponse.kind !== "response") {
      throw new Error(
        `in-memory peer returned malformed response: ${
          parsedResponse.kind === "error"
            ? parsedResponse.reason
            : "unexpected message kind"
        }`,
      );
    }
    return unwrapResponse(parsedResponse.response);
  }

  async notify(method: string, params: unknown): Promise<void> {
    if (!this.open) throw new Error("transport not connected");
    const wire = makeNotification(method, params);
    const parsed = parseJsonRpcMessage(wire, { limits: this.protocolLimits });
    if (parsed.kind === "error" || parsed.kind !== "notification") {
      throw new Error(
        `in-memory notification failed to serialize: ${
          parsed.kind === "error" ? parsed.reason : "unexpected message kind"
        }`,
      );
    }
    await this.peer.handleNotification?.({
      method: parsed.notification.method,
      params: parsed.notification.params,
    });
  }

  async close(): Promise<void> {
    this.open = false;
  }
}

/**
 * Local stdio transport. Spawns a long-running MCP server process and speaks
 * newline-delimited JSON-RPC over its stdin/stdout. When a sandbox spec is
 * provided and the platform supports it, the process is launched inside the
 * OS sandbox. When `sandboxRequired` is true and no sandbox can be
 * constructed, connect() FAILS CLOSED.
 */
export class StdioConnection implements McpConnection {
  readonly kind = "stdio" as const;
  readonly protocolLimits: ProtocolLimits;
  enforcement?: EnforcementReport;

  private child: ChildProcess | null = null;
  private readonly pending = new Map<
    number | string,
    {
      resolve: (v: unknown) => void;
      reject: (e: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();
  private buffer = "";
  private nextId = 1;
  private closed = false;

  constructor(
    private readonly command: string,
    private readonly args: readonly string[],
    private readonly options: {
      cwd?: string;
      env?: Record<string, string>;
      sandbox?: SandboxSpec;
      sandboxRequired?: boolean;
      protocolLimits?: ProtocolLimits;
    } = {},
  ) {
    this.protocolLimits = options.protocolLimits ?? {};
  }

  async connect(): Promise<void> {
    if (this.closed) throw new Error("transport closed");
    try {
      this.child = this.spawnSandboxedOrPlain();
    } catch (e) {
      this.enforcement = undefined;
      throw e as Error; // fail closed when sandbox cannot be constructed
    }
    this.child.stderr?.on("data", () => {
      /* stderr is left to the server; collected for diagnostics only */
    });
    this.child.stdout?.setEncoding("utf8");
    this.child.stdout?.on("data", (chunk: string) => this.onData(chunk));
    this.child.on("error", (err) => {
      for (const [, entry] of this.pending) {
        clearTimeout(entry.timer);
        entry.reject(err);
      }
      this.pending.clear();
    });
    this.child.on("close", () => {
      for (const [, entry] of this.pending) {
        clearTimeout(entry.timer);
        entry.reject(new Error("MCP server process closed"));
      }
      this.pending.clear();
    });
  }

  private spawnSandboxedOrPlain(): ChildProcess {
    const spec = this.options.sandbox;
    if (spec && this.options.sandboxRequired) {
      // Construct the sandbox first: if the platform cannot provide VERIFIED
      // isolation, execution must not proceed (fail closed).
      const handle = createSandbox(spec, { workspace: defaultWorkspace() });
      if (!handle.report.verified) {
        throw new Error(
          `sandboxed stdio MCP requires verified OS isolation but backend reported verified=false (fail closed): ${handle.report.notes.join("; ")}`,
        );
      }
      (this as { enforcement?: EnforcementReport }).enforcement = handle.report;
      if (process.platform === "darwin") {
        const profile = generateSeatbeltProfile(spec, defaultWorkspace());
        return spawn(
          "sandbox-exec",
          ["-p", profile, "--", this.command, ...this.args],
          {
            cwd: this.options.cwd,
            env: { ...process.env, ...this.options.env },
          },
        );
      }
      throw new Error(
        `no sandboxed stdio backend for platform ${process.platform} (fail closed)`,
      );
    }
    if (spec && !this.options.sandboxRequired) {
      // Optional sandbox: use it when the platform supports it, otherwise run
      // unsandboxed and report honestly via enforcement.
      try {
        const handle = createSandbox(spec, { workspace: defaultWorkspace() });
        if (handle.report.verified) {
          (this as { enforcement?: EnforcementReport }).enforcement =
            handle.report;
          if (process.platform === "darwin") {
            const profile = generateSeatbeltProfile(spec, defaultWorkspace());
            return spawn(
              "sandbox-exec",
              ["-p", profile, "--", this.command, ...this.args],
              {
                cwd: this.options.cwd,
                env: { ...process.env, ...this.options.env },
              },
            );
          }
        }
      } catch {
        (this as { enforcement?: EnforcementReport }).enforcement = undefined;
      }
    }
    return spawn(this.command, [...this.args], {
      cwd: this.options.cwd,
      env: { ...process.env, ...this.options.env },
    });
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 1);
      if (line.trim().length === 0) continue;
      const parsed = parseJsonRpcMessage(line, { limits: this.protocolLimits });
      if (parsed.kind === "response") {
        const entry = this.pending.get(parsed.response.id);
        if (entry) {
          clearTimeout(entry.timer);
          this.pending.delete(parsed.response.id);
          try {
            entry.resolve(unwrapResponse(parsed.response));
          } catch (e) {
            entry.reject(e as Error);
          }
        }
      } else if (parsed.kind === "error") {
        // Malformed inbound message: fail every outstanding request.
        const err = new Error(
          `malformed MCP response from server: ${parsed.reason}`,
        );
        for (const [, entry] of this.pending) {
          clearTimeout(entry.timer);
          entry.reject(err);
        }
        this.pending.clear();
      }
      // Notifications from the server are currently surfaced as ignored
      // (protocol tolerance); RTQ subscribes to none.
    }
  }

  async request(
    method: string,
    params: unknown,
    opts: { timeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<unknown> {
    if (!this.child || this.closed) throw new Error("transport not connected");
    const id = this.nextId++;
    const wire = makeRequest(id, method, params);
    const timeoutMs = opts.timeoutMs ?? 30_000;
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new Error(`MCP request "${method}" timed out after ${timeoutMs}ms`),
        );
      }, timeoutMs);
      if (opts.signal?.aborted) {
        clearTimeout(timer);
        reject(new Error("request aborted"));
        return;
      }
      opts.signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error("request aborted"));
      });
      this.pending.set(id, { resolve, reject, timer });
      this.child!.stdin?.write(wire + "\n", (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  async notify(method: string, params: unknown): Promise<void> {
    if (!this.child || this.closed) return;
    const wire = makeNotification(method, params);
    this.child.stdin?.write(wire + "\n");
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error("transport closed"));
    }
    this.pending.clear();
    if (this.child) {
      this.child.kill();
      this.child = null;
    }
  }
}

/**
 * Remote streamable-HTTP transport (JSON-RPC over POST, JSON or SSE responses).
 * TLS is used when the URL scheme is https; certificate validation is on by
 * default (`rejectUnauthorized !== false`).
 */
export class HttpConnection implements McpConnection {
  readonly kind = "http" as const;
  readonly protocolLimits: ProtocolLimits;
  private nextId = 1;
  private closed = false;
  readonly endpointUrl: string;

  constructor(
    private readonly url: string,
    private readonly options: {
      headers?: Record<string, string>;
      tls?: { rejectUnauthorized?: boolean };
      protocolLimits?: ProtocolLimits;
    } = {},
  ) {
    this.endpointUrl = url;
    this.protocolLimits = options.protocolLimits ?? {};
  }

  async connect(): Promise<void> {
    if (!/^https?:\/\//i.test(this.url)) {
      throw new Error(`unsupported HTTP transport URL scheme: ${this.url}`);
    }
  }

  async request(
    method: string,
    params: unknown,
    opts: { timeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<unknown> {
    if (this.closed) throw new Error("transport not connected");
    const id = this.nextId++;
    const body = makeRequest(id, method, params);
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    opts.signal?.addEventListener("abort", () => controller.abort(), {
      once: true,
    });
    try {
      const response = await fetch(this.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...this.options.headers,
        },
        body,
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} from MCP endpoint`);
      }
      const contentType = response.headers.get("content-type") ?? "";
      let wire: string;
      if (contentType.includes("text/event-stream")) {
        wire = await readSingleSseEvent(await response.text());
      } else {
        wire = await response.text();
      }
      const parsed = parseJsonRpcMessage(wire, { limits: this.protocolLimits });
      if (parsed.kind === "error" || parsed.kind !== "response") {
        throw new Error(
          `malformed MCP response: ${
            parsed.kind === "error" ? parsed.reason : "unexpected message kind"
          }`,
        );
      }
      return unwrapResponse(parsed.response);
    } catch (e) {
      if ((e as Error).name === "AbortError") {
        throw new Error(
          `MCP request "${method}" timed out after ${timeoutMs}ms`,
        );
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  async notify(method: string, params: unknown): Promise<void> {
    if (this.closed) return;
    const body = makeNotification(method, params);
    try {
      await fetch(this.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...this.options.headers,
        },
        body,
      });
    } catch {
      /* notifications are best-effort */
    }
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

/** Read the first `data:` payload of an SSE event stream. */
function readSingleSseEvent(body: string): string {
  for (const line of body.split(/\r?\n/)) {
    if (line.startsWith("data:")) {
      const payload = line.slice(5).trimStart();
      if (payload.length > 0) return payload;
    }
  }
  throw new Error("SSE response contained no data event");
}

function unwrapResponse(response: JsonRpcResponse): unknown {
  if ("error" in response) {
    const err = new Error(
      `MCP error ${response.error.code}: ${response.error.message}`,
    );
    (err as Error & { code?: number }).code = response.error.code;
    throw err;
  }
  return response.result;
}

async function withSignal<T>(
  timeoutMs: number,
  signal: AbortSignal | undefined,
  promise: Promise<T>,
): Promise<T> {
  if (signal?.aborted) throw new Error("request aborted");
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`MCP request timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
  });
  const abort = new Promise<never>((_, reject) => {
    signal?.addEventListener(
      "abort",
      () => reject(new Error("request aborted")),
      { once: true },
    );
  });
  try {
    return await Promise.race([promise, timeout, abort]);
  } finally {
    clearTimeout(timer);
  }
}

export { MCP_METHODS, makeNotification, makeRequest, parseJsonRpcMessage };
