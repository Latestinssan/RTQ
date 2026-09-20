import { defineConfig } from "vitest/config";
import path from "path";

const alias = {
  "@rtq/core": path.resolve(__dirname, "packages/core/src/index.ts"),
  "@rtq/crypto": path.resolve(__dirname, "packages/crypto/src/index.ts"),
  "@rtq/audit": path.resolve(__dirname, "packages/audit/src/index.ts"),
  "@rtq/mcp": path.resolve(__dirname, "packages/mcp/src/index.ts"),
  "@rtq/risk": path.resolve(__dirname, "packages/risk/src/index.ts"),
  "@rtq/policy": path.resolve(__dirname, "packages/policy/src/index.ts"),
  "@rtq/clarification": path.resolve(
    __dirname,
    "packages/clarification/src/index.ts",
  ),
  "@rtq/approval": path.resolve(__dirname, "packages/approval/src/index.ts"),
  "@rtq/mobile": path.resolve(__dirname, "packages/mobile/src/index.ts"),
  "@rtq/sandbox": path.resolve(__dirname, "packages/sandbox/src/index.ts"),
  "@rtq/security": path.resolve(__dirname, "packages/security/src/index.ts"),
  "@rtq/cli": path.resolve(__dirname, "packages/cli/src/index.ts"),
};

export default defineConfig({
  resolve: { alias },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
