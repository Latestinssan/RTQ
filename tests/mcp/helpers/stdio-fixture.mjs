/**
 * Minimal MCP stdio server fixture used by the stdio transport contract tests.
 *
 * Reads newline-delimited JSON-RPC from stdin and writes responses on stdout.
 * This is a TEST FIXTURE for validating the stdio transport (framing, request
 * IDs, notifications); it is not part of the RTQ runtime.
 */
import readline from "node:readline";

const rl = readline.createInterface({ input: process.stdin });

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}

function error(id, code, message) {
  process.stdout.write(
    JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n",
  );
}

rl.on("line", (line) => {
  if (line.trim().length === 0) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    error(0, -32700, "Parse error");
    return;
  }
  if (msg.id === undefined) return; // notifications are ignored by the fixture
  const { id, method, params } = msg;
  switch (method) {
    case "initialize":
      respond(id, {
        protocolVersion: "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "stdio-fixture", version: "0.0.0" },
        instructions: "Fixture instructions (untrusted content).",
      });
      break;
    case "ping":
      respond(id, {});
      break;
    case "tools/list":
      respond(id, {
        tools: [
          {
            name: "echo",
            description: "Echo fixture",
            inputSchema: {
              type: "object",
              properties: { text: { type: "string" } },
            },
          },
        ],
      });
      break;
    case "tools/call":
      respond(id, {
        content: [
          {
            type: "text",
            text: `echoed:${params?.arguments?.text ?? ""}`,
          },
        ],
        isError: false,
      });
      break;
    case "slow":
      // Deliberately never respond; used to exercise the client timeout.
      break;
    default:
      error(id, -32601, `Method not found: ${method}`);
  }
});
