/**
 * RTQ MCP integration layer public API.
 *
 * MCP is an integration/protocol layer, NEVER an authorization boundary
 * (spec 46.31). Everything exported here that originates from an MCP server
 * (tool metadata, schemas, descriptions, resources, prompts, results) is
 * UNTRUSTED data; RTQ treats it as data and never lets it change policy or
 * authorization state.
 *
 * Security invariants maintained by this package:
 *  - JSON-RPC messages are parsed defensively (size limits, strict envelope).
 *  - Server-declared tool schemas are normalized/hardened; unsupported
 *    constructs mark the tool incomplete so it fails closed on registration.
 *  - Results are normalized with size/depth limits, secret redaction and
 *    advisory injection-like flags (flags never authorize anything).
 *  - Local stdio servers are sandboxed when configured; sandboxRequired
 *    connections FAIL CLOSED when verified OS isolation is impossible.
 */
export * from "./types";
export * from "./protocol";
export * from "./transports";
export * from "./server";
export * from "./schemas";
export * from "./results";
export * from "./registry";
export * from "./risk";
export * from "./policy";
export * from "./credentials";
export * from "./contract";
export * from "./gateway";
