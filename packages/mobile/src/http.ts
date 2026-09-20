/**
 * HTTP transport for the mobile approval service.
 *
 * IMPORTANT: this transport is NOT the security boundary. `rtq-approval-v1`
 * assumes the channel between host and device is untrusted: a challenge is
 * host-signed and an approval is device-signed, so a man-in-the-middle can
 * delay, drop or replay bytes but cannot forge consent. Do not treat
 * "localhost" or "HTTPS" as if it replaced those checks — it does not.
 *
 * The transport therefore stays deliberately small: strict method/route
 * handling, a hard body-size limit, `Cache-Control: no-store`, and no secret
 * material in responses or logs.
 */

import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "http";
import type { MobileApprovalService } from "./service";

export interface HttpTransportOptions {
  /** Maximum accepted request body. Default 64 KiB. */
  maxBodyBytes?: number;
  /**
   * Optional bearer token required on pairing endpoints. This is a convenience
   * for the host UI, NOT an authorization mechanism for approvals.
   */
  pairingToken?: string;
  onAudit?: (event: string, detail: Record<string, unknown>) => void;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
  });
  res.end(text);
}

function readBody(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > limit) {
        tooLarge = true;
        reject(new BodyTooLargeError());
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

class BodyTooLargeError extends Error {}

/**
 * Read and cap the body. On overflow, answer 413 and drain the request so the
 * client sees a clean response instead of a reset socket.
 */
async function tryReadBody(
  req: IncomingMessage,
  res: ServerResponse,
  limit: number,
): Promise<string | null> {
  try {
    return await readBody(req, limit);
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      json(res, 413, { ok: false, code: "transport.body_too_large" });
      req.resume();
      return null;
    }
    throw error;
  }
}

function methodNotAllowed(res: ServerResponse, allow: string): void {
  res.writeHead(405, { allow, "content-type": "application/json" });
  res.end(JSON.stringify({ ok: false, code: "transport.method_not_allowed" }));
}

/**
 * Build a Node HTTP server exposing the mobile approval endpoints.
 * Routes:
 *   GET  /health         — liveness + protocol version
 *   POST /pair/start      — host creates a pairing challenge for the host UI
 *   POST /pair/complete   — device submits a signed pairing response
 *   POST /approve         — device submits a signed approval
 */
export function createMobileApprovalServer(
  service: MobileApprovalService,
  options: HttpTransportOptions = {},
): Server {
  const maxBodyBytes = options.maxBodyBytes ?? 64 * 1024;

  return createServer((req, res) => {
    void handle(req, res).catch(() => {
      options.onAudit?.("TRANSPORT_ERROR", { url: req.url });
      if (!res.headersSent) {
        json(res, 500, { ok: false, code: "transport.error" });
      } else {
        res.end();
      }
    });
  });

  async function handle(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const url = (req.url ?? "/").split("?")[0];
    options.onAudit?.("TRANSPORT_REQUEST", {
      method: req.method,
      url,
    });

    if (url === "/health") {
      if (req.method !== "GET") return methodNotAllowed(res, "GET");
      return json(res, 200, { ok: true, protocol: "rtq-approval-v1" });
    }

    if (url === "/pair/start") {
      if (req.method !== "POST") return methodNotAllowed(res, "POST");
      if (!authorized(req, options)) {
        return json(res, 401, { ok: false, code: "transport.unauthorized" });
      }
      const created = service.startPairing();
      return json(res, 200, {
        ok: true,
        payload: created.payload,
        pairingId: created.challenge.pairingId,
        expiresAt: created.challenge.expiresAt,
      });
    }

    if (url === "/pair/complete") {
      if (req.method !== "POST") return methodNotAllowed(res, "POST");
      if (!authorized(req, options)) {
        return json(res, 401, { ok: false, code: "transport.unauthorized" });
      }
      const body = await tryReadBody(req, res, maxBodyBytes);
      if (body === null) return;
      const result = await service.completePairingText(body);
      if (result.ok) {
        return json(res, 200, {
          ok: true,
          deviceId: result.device.deviceId,
          name: result.device.name,
        });
      }
      return json(res, 400, {
        ok: false,
        code: result.code,
        reason: result.reason,
      });
    }

    if (url === "/approve") {
      if (req.method !== "POST") return methodNotAllowed(res, "POST");
      const body = await tryReadBody(req, res, maxBodyBytes);
      if (body === null) return;
      const result = service.submitApproval(body);
      if (result.ok) {
        return json(res, 200, {
          ok: true,
          challengeId: result.challengeId,
          capability: result.capability,
          deviceId: result.deviceId,
        });
      }
      return json(res, 400, {
        ok: false,
        code: result.code,
        reason: result.reason,
      });
    }

    return json(res, 404, { ok: false, code: "transport.not_found" });
  }
}

/** Enforce the optional pairing bearer token. */
function authorized(
  req: IncomingMessage,
  options: HttpTransportOptions,
): boolean {
  if (!options.pairingToken) return true;
  const header = req.headers.authorization;
  return header === `Bearer ${options.pairingToken}`;
}

export interface StartedServer {
  server: Server;
  url: string;
  port: number;
  close: () => Promise<void>;
}

/** Start the server on an ephemeral (or fixed) port and resolve once listening. */
export function startMobileApprovalServer(
  service: MobileApprovalService,
  options: HttpTransportOptions & { port?: number; host?: string } = {},
): Promise<StartedServer> {
  const server = createMobileApprovalServer(service, options);
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const address = server.address();
      const boundPort =
        typeof address === "object" && address !== null ? address.port : port;
      resolve({
        server,
        port: boundPort,
        url: `http://${host}:${boundPort}`,
        close: () =>
          new Promise<void>((done, fail) =>
            server.close((error) => (error ? fail(error) : done())),
          ),
      });
    });
  });
}
