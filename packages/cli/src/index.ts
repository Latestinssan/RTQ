/**
 * RTQ CLI — actionable security tooling.
 *
 *   rtq capabilities [--config <file>]            list the executable surface
 *   rtq policy check <command.json> [--config <f>][--origin <o>][--resource <p>]
 *                                                 evaluate policy for a command
 *   rtq sandbox test                              platform sandbox smoke test
 *   rtq verify signature --ticket <ticket.json>   verify a ticket's HMAC signature
 *   rtq diagnostics                               runtime/platform diagnostics
 */

import fs from "fs";
import path from "path";
import { createRTQ, type CapabilityDef, type Origin } from "@rtq/security";
import { ticketBody, type AuthorizationTicket } from "@rtq/core";
import { signCanonical, timingSafeEqualHex } from "@rtq/crypto";
import { createSandbox } from "@rtq/sandbox";
import type { PolicyRule } from "@rtq/policy";
import type { ClarificationRule } from "@rtq/clarification";
import { runMcpCli } from "./mcp";

interface ConfigModule {
  capabilities?: CapabilityDef[];
  policy?: PolicyRule[];
  clarifications?: ClarificationRule[];
}

function loadConfig(configPath?: string): ConfigModule {
  if (!configPath) return {};
  const abs = path.resolve(configPath);
  if (!fs.existsSync(abs)) {
    throw new Error(`config not found: ${abs}`);
  }
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require(abs);
  const cfg = mod.default ?? mod;
  if (typeof cfg !== "object" || cfg === null) {
    throw new Error(`config ${abs} must export an object`);
  }
  return cfg as ConfigModule;
}

function signingKey(): string {
  const key = process.env.RTQ_SIGNING_KEY;
  if (!key) {
    throw new Error("RTQ_SIGNING_KEY environment variable is required");
  }
  return key;
}

function printTable(rows: string[][]): void {
  const widths = rows[0]!.map((_, i) =>
    Math.max(...rows.map((r) => r[i]!.length)),
  );
  for (const row of rows) {
    process.stdout.write(
      row
        .map((c, i) => c.padEnd(widths[i]! + 2))
        .join("")
        .trimEnd() + "\n",
    );
  }
}

export async function runCli(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "capabilities":
      return cmdCapabilities(rest);
    case "policy":
      return cmdPolicy(rest);
    case "sandbox":
      return cmdSandbox(rest);
    case "verify":
      return cmdVerify(rest);
    case "mcp":
      return runMcpCli(rest);
    case "diagnostics":
      return cmdDiagnostics(rest);
    case "help":
    case "--help":
    case "-h":
    case undefined:
      printUsage();
      return 0;
    default:
      process.stderr.write(`Unknown command: ${command}\n\n`);
      printUsage();
      return 2;
  }
}

function printUsage(): void {
  process.stdout.write(`RTQ CLI
Usage: rtq <command> [options]

Commands:
  capabilities [--config <file>]            List the registered capability surface.
  policy check <command.json> [--config <f>]
      [--origin <origin>] [--resource <path>]
                                            Evaluate policy for a structured command.
  mcp <subcommand>                         MCP admin commands (servers/tools/contracts/revoke/metrics).
  sandbox test [--workspace <dir>]          Run the platform sandbox smoke test.
  verify signature --ticket <ticket.json>   Verify a ticket's HMAC signature using RTQ_SIGNING_KEY.
  diagnostics                               Print runtime/platform diagnostics.
  help                                      Show this help.
`);
}

function optValue(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1]!;
}

const ORIGINS: ReadonlySet<string> = new Set([
  "local",
  "remote",
  "mobile",
  "plugin",
  "agent",
  "automation",
  "unknown",
]);

/** Parse --origin strictly; an unrecognized value fails the check. */
function parseOrigin(raw: string | undefined): Origin {
  if (raw === undefined) return "local";
  if (ORIGINS.has(raw)) return raw as Origin;
  throw new Error(
    `invalid --origin "${raw}" (expected one of: ${[...ORIGINS].join(", ")})`,
  );
}

async function cmdCapabilities(args: string[]): Promise<number> {
  try {
    const cfg = loadConfig(optValue(args, "--config"));
    const rtq = createRTQ({ signingKey: signingKey() });
    for (const c of cfg.capabilities ?? []) rtq.registerCapability(c);
    const list = rtq.capabilities.getRegisteredCapabilities();
    if (list.length === 0) {
      process.stdout.write(
        "No capabilities registered (and none loaded from config).\n",
      );
      return 0;
    }
    printTable([
      ["NAME", "VERSION", "BASE RISK", "APPROVAL", "SANDBOX"],
      ...list.map((c) => [
        c.name,
        String(c.version),
        c.baseRisk,
        c.approvalStrategy,
        c.sandboxRequirement,
      ]),
    ]);
    return 0;
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 1;
  }
}

async function cmdPolicy(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  if (sub !== "check") {
    process.stderr.write("usage: rtq policy check <command.json> [options]\n");
    return 2;
  }
  const commandPath = rest.find((a) => !a.startsWith("--"));
  if (!commandPath) {
    process.stderr.write("usage: rtq policy check <command.json> [options]\n");
    return 2;
  }
  try {
    const cfg = loadConfig(optValue(rest, "--config"));
    const rtq = createRTQ({ signingKey: signingKey() });
    for (const c of cfg.capabilities ?? []) rtq.registerCapability(c);
    for (const r of cfg.policy ?? []) rtq.registerPolicy(r);

    const raw = JSON.parse(fs.readFileSync(path.resolve(commandPath), "utf8"));
    const origin = parseOrigin(optValue(rest, "--origin"));
    const resource = optValue(rest, "--resource");
    const result = await rtq.authorize(
      {
        capability: String(raw.capability ?? ""),
        version: Number(raw.version ?? 1),
        input: (raw.input ?? {}) as Record<string, unknown>,
        ...(origin !== "local" ? { origin } : {}),
      },
      { resource },
    );
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    // 0 when the decision would allow or needs approval; 3 when policy
    // decisively denies.
    return result.decision === "denied" ? 3 : 0;
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 1;
  }
}

async function cmdSandbox(args: string[]): Promise<number> {
  const workspace = optValue(args, "--workspace");
  try {
    const handle = createSandbox(
      {
        filesystem: {
          read: [process.cwd()],
          write: workspace ? [workspace] : [],
        },
        network: "none",
        environment: { allow: ["PATH"] },
      },
      { workspace },
    );
    process.stdout.write(
      `backend: ${handle.report.backend}  verified: ${handle.report.verified}\n` +
        `isolation: filesystem=${handle.report.isolation.filesystem} network=${handle.report.isolation.network} ` +
        `process=${handle.report.isolation.process} environment=${handle.report.isolation.environment}\n`,
    );
    for (const note of handle.report.notes)
      process.stdout.write(`note: ${note}\n`);

    const probe = process.platform === "win32" ? "cmd" : "/usr/bin/true";
    const result = await handle.execute(probe, [], { timeoutMs: 15_000 });
    process.stdout.write(
      `probe: exit=${result.exitCode} sandboxed=${result.sandboxed} ${result.error ? `error=${result.error}` : ""}\n`,
    );
    if (result.sandboxed && result.exitCode === 0) return 0;
    process.stderr.write("sandbox test FAILED\n");
    return 1;
  } catch (e) {
    process.stderr.write(`sandbox test failed: ${(e as Error).message}\n`);
    return 1;
  }
}

async function cmdVerify(args: string[]): Promise<number> {
  const ticketPath = optValue(args, "--ticket");
  if (!ticketPath) {
    process.stderr.write(
      "usage: rtq verify signature --ticket <ticket.json>\n",
    );
    return 2;
  }
  try {
    const ticket = JSON.parse(
      fs.readFileSync(path.resolve(ticketPath), "utf8"),
    ) as AuthorizationTicket;
    const key = signingKey();
    const expected = signCanonical(key, ticketBody(ticket));
    const valid = timingSafeEqualHex(ticket.signature, expected);
    process.stdout.write(
      `ticket: ${ticket.id}\ncapability: ${ticket.capability} v${ticket.capabilityVersion}\n` +
        `risk: ${ticket.risk}\nsignature: ${valid ? "VALID" : "INVALID"}\n`,
    );
    return valid ? 0 : 4;
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 1;
  }
}

async function cmdDiagnostics(_args: string[]): Promise<number> {
  const info: Record<string, unknown> = {
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    signingKeyConfigured: Boolean(process.env.RTQ_SIGNING_KEY),
    sandboxExec: fs.existsSync("/usr/bin/sandbox-exec"),
    bwrap: hasBinary("bwrap"),
    powershell: hasBinary("powershell.exe") || hasBinary("pwsh"),
    env: {
      hostSecretVars: Object.keys(process.env).filter((k) =>
        /(?:key|secret|token|password|credential)/i.test(k),
      ),
    },
  };
  process.stdout.write(JSON.stringify(info, null, 2) + "\n");
  return 0;
}

function hasBinary(name: string): boolean {
  const { spawnSync } = require("child_process");
  const r = spawnSync(
    process.platform === "win32" ? "where" : "which",
    [name],
    { encoding: "utf8" },
  );
  return r.status === 0;
}
