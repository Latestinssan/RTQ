import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  buildBubblewrapArgs,
  canonicalizePath,
  checkBwrapCapability,
} from "@rtq/sandbox";

const workspace = path.join(os.tmpdir(), `rtq-linux-arg-test-${process.pid}`);

beforeAll(() => {
  fs.mkdirSync(workspace, { recursive: true });
});

afterAll(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

describe("buildBubblewrapArgs (Linux)", () => {
  const spec = {
    filesystem: {
      read: ["/usr", "/etc"],
      write: [workspace],
    },
    network: "none" as const,
    processes: { spawn: false },
    environment: { allow: ["PATH", "HOME"] },
  };

  it("assembles a bwrap argv in a new namespace with ro/rw bind mounts and no network", () => {
    const args = buildBubblewrapArgs("/bin/true", [], spec, workspace);
    expect(args[0]).toBe("--unshare-pid");
    expect(args.join(" ")).toContain("--unshare-net");
    expect(args.join(" ")).toContain("--unshare-user");
    expect(args.join(" ")).toContain("--new-session");
    // system dirs ro, allowlisted read dirs ro
    const roIdx = args.indexOf("--ro-bind");
    expect(roIdx).toBeGreaterThan(-1);
    expect(args[roIdx + 1]).toBe("/usr");
    // writable dir binds read-write
    const bindIdx = args.indexOf("--bind");
    expect(bindIdx).toBeGreaterThan(-1);
    expect(args[bindIdx + 1]).toBe(canonicalizePath(workspace).canonical);
    // private /tmp and /proc, no shared network
    expect(args).toContain("--tmpfs");
    expect(args).toContain("--proc");
    expect(args.join(" ")).not.toContain("--share-net");
    // command is appended last
    expect(args[args.length - 1]).toBe("/bin/true");
  });

  it("refuses network allowlists it cannot enforce (fail-closed)", () => {
    expect(() =>
      buildBubblewrapArgs(
        "/bin/true",
        [],
        {
          filesystem: { read: ["/usr"] },
          network: { allow: ["example.com"] },
          environment: { allow: [] },
        },
        "/workspace",
      ),
    ).toThrow(/network/);
  });

  it("does not share the host /dev and gives the process its own /tmp", () => {
    const args = buildBubblewrapArgs("/bin/true", [], spec, workspace);
    expect(args.join(" ")).not.toContain("--bind /dev");
    // /dev is mounted empty, /tmp is a private tmpfs
    expect(args.join(" ")).toContain("--dev /dev");
    expect(args.join(" ")).toContain("--tmpfs /tmp");
  });
});

describe("checkBwrapCapability", () => {
  it("returns a boolean availability probe without throwing", () => {
    const result = checkBwrapCapability("bwrap");
    expect(typeof result).toBe("boolean");
  });
});
