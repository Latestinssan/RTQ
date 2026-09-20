/**
 * Minimal RTQ agent: register one capability + one policy, authorize,
 * execute. This is the exact public surface an agent uses.
 *
 * Run:
 *   export RTQ_SIGNING_KEY="$(openssl rand -hex 32)"
 *   npx tsx examples/agent.ts
 *
 * Depends only on the released packages (no exported internals).
 */
import { createRTQ } from "@rtq/security";

const rtq = createRTQ({
  signingKey: process.env.RTQ_SIGNING_KEY ?? "example-key-not-for-prod",
});

// 1. The ONLY executable surface. Unregistered names get denied at step 3.
rtq.registerCapability({
  name: "files.read",
  version: 1,
  description: "Read a file inside the workspace",
  inputSchema: {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
    additionalProperties: false,
  },
  risk: { base: "low" },
  execute: async (ctx, input) => ({
    ok: true,
    data: { path: input.path, ticket: ctx.ticketId },
  }),
});

// 2. Explicit policy rule. Missing rule ≠ allow.
rtq.registerPolicy({ kind: "allow", capability: "files.read", reason: "demo" });

async function main() {
  const auth = await rtq.authorize({
    capability: "files.read",
    version: 1,
    input: { path: "/workspace/notes.md" },
  });

  switch (auth.decision) {
    case "allowed":
      const executed = await rtq.execute(auth.ticketId);
      console.log("executed:", JSON.stringify(executed));
      break;
    case "denied":
      console.log("denied:", auth.reason);
      break;
    case "approval_required":
      console.log("approval required (strategy:", auth.strategy, ")");
      break;
    case "clarification_required":
      console.log("clarification needed:", auth.reason);
      break;
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
