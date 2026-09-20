/**
 * RTQ CLI — `rtq mcp` admin subcommands.
 *
 *   rtq mcp servers                           List registered MCP servers.
 *   rtq mcp tools [--server <id>]             List discovered MCP tools.
 *   rtq mcp contracts [--server <id>]         Run contract checks on tools.
 *   rtq mcp revoke <serverId>                 Revoke an MCP server and its tools.
 *   rtq mcp metrics                           Show MCP gateway metrics.
 */

import {
  McpRegistry,
  McpPolicyEngine,
  McpRiskAdvisor,
  McpGateway,
  runContractChecksForAll,
  type McpServerConfig,
} from "@rtq/mcp";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function optValue(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1]!;
}

function hasFlag(args: string[], name: string): boolean {
  return args.includes(name);
}

function printTable(rows: string[][]): void {
  if (rows.length === 0) {
    process.stdout.write("(empty)\n");
    return;
  }
  const widths = rows[0]!.map((_, i) =>
    Math.max(...rows.map((r) => r[i]!.length)),
  );
  for (const row of rows) {
    process.stdout.write(
      row.map((c, i) => c.padEnd(widths[i]! + 2)).join("").trimEnd() + "\n",
    );
  }
}

/**
 * Build a minimal McpGateway from environment/defaults for CLI use.
 * In production, this would load from a config file.
 */
function buildCliGateway(): McpGateway {
  const registry = new McpRegistry();
  const policy = new McpPolicyEngine();
  const riskAdvisor = new McpRiskAdvisor();
  return new McpGateway({
    registry,
    policy,
    riskAdvisor,
    authorize: async () => ({
      ticketId: `cli_${Date.now().toString(36)}`,
    }),
    execute: async (ticketId) => ({ result: null }),
    tickets: {
      peek: () => undefined,
      park: () => {},
    },
    onAudit: (event, data) => {
      if (hasFlag(process.argv, "--verbose")) {
        process.stderr.write(`[audit] ${event} ${JSON.stringify(data)}\n`);
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

export async function runMcpCli(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  switch (sub) {
    case "servers":
      return cmdServers(rest);
    case "tools":
      return cmdTools(rest);
    case "contracts":
      return cmdContracts(rest);
    case "revoke":
      return cmdRevoke(rest);
    case "metrics":
      return cmdMetrics(rest);
    case "help":
    case "--help":
    case "-h":
    case undefined:
      printMcpUsage();
      return 0;
    default:
      process.stderr.write(`Unknown mcp subcommand: ${sub}\n\n`);
      printMcpUsage();
      return 2;
  }
}

function printMcpUsage(): void {
  process.stdout.write(`RTQ MCP Admin Commands

Usage: rtq mcp <subcommand> [options]

Subcommands:
  rtq mcp servers                          List registered MCP servers.
  rtq mcp tools [--server <id>]            List discovered MCP tools.
  rtq mcp contracts [--server <id>]        Run contract checks on all tools.
  rtq mcp revoke <serverId>                Revoke an MCP server and its tools.
  rtq mcp metrics                          Show MCP gateway metrics.
  rtq mcp help                             Show this help.

Options:
  --verbose                                Enable audit event logging to stderr.
  --server <id>                            Filter by server ID.
  --json                                   Output as JSON instead of a table.
`);
}

/**
 * `rtq mcp servers` — List all registered servers.
 *
 * NOTE: In a persistent deployment, the registry would be backed by storage.
 * For the CLI, we create a fresh in-memory registry (empty by default).
 * To inspect a running system, the operator should pipe a serialized registry
 * snapshot into this command or use the gateway's admin API directly.
 */
async function cmdServers(args: string[]): Promise<number> {
  const gateway = buildCliGateway();
  const sessions = gateway.listSessions();

  if (hasFlag(args, "--json")) {
    process.stdout.write(
      JSON.stringify(
        sessions.map((s) => ({
          sessionId: s.sessionId,
          serverId: s.serverId,
          protocolVersion: s.protocolVersion,
          connectedAt: s.connectedAt,
          toolCount: s.tools.length,
        })),
        null,
        2,
      ) + "\n",
    );
    return 0;
  }

  printTable([
    ["SESSION", "SERVER", "PROTOCOL", "TOOLS", "CONNECTED"],
    ...sessions.map((s) => [
      s.sessionId,
      s.serverId,
      s.protocolVersion,
      String(s.tools.length),
      new Date(s.connectedAt).toISOString(),
    ]),
  ]);
  return 0;
}

/**
 * `rtq mcp tools` — List discovered tools, optionally filtered by server.
 */
async function cmdTools(args: string[]): Promise<number> {
  const gateway = buildCliGateway();
  const serverFilter = optValue(args, "--server");
  const sessions = gateway.listSessions();

  const tools: Array<{
    serverId: string;
    name: string;
    description: string;
    severity: string;
    capabilityName: string;
    incomplete: boolean;
  }> = [];

  for (const session of sessions) {
    if (serverFilter && session.serverId !== serverFilter) continue;
    for (const tool of session.tools) {
      tools.push({
        serverId: tool.serverId,
        name: tool.name,
        description: tool.description,
        severity: tool.severity,
        capabilityName: tool.capabilityName,
        incomplete: tool.incomplete,
      });
    }
  }

  if (hasFlag(args, "--json")) {
    process.stdout.write(JSON.stringify(tools, null, 2) + "\n");
    return 0;
  }

  printTable([
    ["SERVER", "TOOL", "SEVERITY", "CAPABILITY", "INCOMPLETE"],
    ...tools.map((t) => [
      t.serverId,
      t.name,
      t.severity,
      t.capabilityName,
      t.incomplete ? "YES" : "",
    ]),
  ]);
  return 0;
}

/**
 * `rtq mcp contracts` — Run contract checks and report results.
 */
async function cmdContracts(args: string[]): Promise<number> {
  const gateway = buildCliGateway();
  const reports = runContractChecksForAll(gateway["config"].registry);

  if (reports.length === 0) {
    process.stdout.write("No tools registered — nothing to check.\n");
    return 0;
  }

  if (hasFlag(args, "--json")) {
    process.stdout.write(JSON.stringify(reports, null, 2) + "\n");
    return reports.every((r) => r.passed) ? 0 : 1;
  }

  let failures = 0;
  for (const report of reports) {
    const status = report.passed ? "PASS" : "FAIL";
    process.stdout.write(
      `[${status}] ${report.serverId}/${report.toolName} (${report.schemaHash})\n`,
    );
    for (const check of report.checks) {
      const icon = check.passed ? "  ✓" : "  ✗";
      process.stdout.write(`${icon} ${check.description}\n`);
      if (!check.passed && check.reason) {
        process.stdout.write(`    → ${check.reason}\n`);
        failures++;
      }
    }
    process.stdout.write("\n");
  }

  if (failures > 0) {
    process.stderr.write(`${failures} contract check(s) failed.\n`);
  }
  return failures > 0 ? 1 : 0;
}

/**
 * `rtq mcp revoke <serverId>` — Revoke a server.
 */
async function cmdRevoke(args: string[]): Promise<number> {
  const serverId = args.find((a) => !a.startsWith("--"));
  if (!serverId) {
    process.stderr.write("usage: rtq mcp revoke <serverId>\n");
    return 2;
  }

  const gateway = buildCliGateway();
  const toolsRevoked = gateway.revokeServer(serverId);
  process.stdout.write(
    `Server "${serverId}" revoked. ${toolsRevoked} tool(s) invalidated.\n`,
  );
  return 0;
}

/**
 * `rtq mcp metrics` — Show gateway metrics.
 */
async function cmdMetrics(_args: string[]): Promise<number> {
  const gateway = buildCliGateway();
  const metrics = gateway.getMetrics();

  if (hasFlag(_args, "--json")) {
    process.stdout.write(JSON.stringify(metrics, null, 2) + "\n");
    return 0;
  }

  process.stdout.write(
    `Connected sessions: ${metrics.connectedSessions}\n` +
      `Registered servers: ${metrics.registeredServers}\n` +
      `Registered tools:   ${metrics.registeredTools}\n` +
      `Registry epoch:     ${metrics.epoch}\n`,
  );
  return 0;
}
