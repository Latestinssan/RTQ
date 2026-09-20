import { describe, expect, it, beforeAll, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  isPathAllowed,
  canonicalizePath,
  flattenAllowlist,
  type AllowlistEntry,
} from "@rtq/sandbox";

function tempTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rtq-fs-test-"));
  fs.mkdirSync(path.join(root, "sub"), { recursive: true });
  fs.writeFileSync(path.join(root, "sub", "inner.txt"), "x");
  fs.writeFileSync(path.join(root, "top.txt"), "x");
  // Symlink inside the allowlist pointing OUTSIDE of it.
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rtq-fs-outside-"));
  fs.writeFileSync(path.join(outside, "secret.txt"), "secret");
  try {
    fs.symlinkSync(outside, path.join(root, "escape"));
  } catch {
    // platform without symlink privilege: record and skip those cases
  }
  return { root, outside };
}

describe("isPathAllowed (filesystem policy layer)", () => {
  let tree: { root: string; outside: string };
  let allowlist: AllowlistEntry[];

  beforeAll(() => {
    tree = tempTree();
    allowlist = [
      { path: tree.root, access: ["read", "write"], recursive: true },
    ];
  });

  afterAll(() => {
    fs.rmSync(tree.root, { recursive: true, force: true });
    fs.rmSync(tree.outside, { recursive: true, force: true });
  });

  it("allows reads inside the allowlist", () => {
    const r = isPathAllowed(
      path.join(tree.root, "sub", "inner.txt"),
      allowlist,
      "read",
    );
    expect(r.allowed).toBe(true);
    expect(r.matchedEntry?.path).toBe(tree.root);
  });

  it("denies paths outside the allowlist", () => {
    const r = isPathAllowed("/etc/passwd", allowlist, "read");
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/not authorized/);
  });

  it("boundary is separator-aware: /workspace does not allow /workspace-evil", () => {
    const evil = tree.root + "-evil/file";
    expect(isPathAllowed(evil, allowlist, "read").allowed).toBe(false);
  });

  it("denies path traversal outside the boundary", () => {
    const r = isPathAllowed(
      path.join(tree.root, "..", "etc", "passwd"),
      allowlist,
      "read",
    );
    expect(r.allowed).toBe(false);
    // canonicalization must resolve .. away from the boundary
    expect(r.canonical).not.toBe(tree.root + "/etc/passwd");
  });

  it("denies symlinks that escape the allowlist", () => {
    const escapePath = path.join(tree.root, "escape", "secret.txt");
    const escaped = fs.existsSync(escapePath);
    if (!escaped) return; // symlinks unavailable on this platform
    const r = isPathAllowed(escapePath, allowlist, "read");
    // canonical path resolves to the OUTSIDE directory, so it must be denied
    expect(r.allowed).toBe(false);
    // (macOS resolves /var -> /private/var; compare against the canonical form)
    expect(
      r.canonical.startsWith(canonicalizePath(tree.outside).canonical),
    ).toBe(true);
  });

  it("keeps read, write and delete separate", () => {
    const readOnly: AllowlistEntry[] = [
      { path: tree.root, access: "read", recursive: true },
    ];
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), readOnly, "read").allowed,
    ).toBe(true);
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), readOnly, "write").allowed,
    ).toBe(false);
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), readOnly, "delete")
        .allowed,
    ).toBe(false);
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), readOnly, "execute")
        .allowed,
    ).toBe(false);

    const writeOnly: AllowlistEntry[] = [
      { path: tree.root, access: "write", recursive: true },
    ];
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), writeOnly, "write")
        .allowed,
    ).toBe(true);
    // a write grant does NOT imply delete
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), writeOnly, "delete")
        .allowed,
    ).toBe(false);
  });

  it("rejects empty allowlists (default deny)", () => {
    expect(isPathAllowed(tree.root, [], "read").allowed).toBe(false);
  });

  it("non-recursive entries only grant direct children", () => {
    const shallow: AllowlistEntry[] = [
      { path: tree.root, access: "read", recursive: false },
    ];
    expect(
      isPathAllowed(path.join(tree.root, "top.txt"), shallow, "read").allowed,
    ).toBe(true);
    expect(
      isPathAllowed(path.join(tree.root, "sub", "inner.txt"), shallow, "read")
        .allowed,
    ).toBe(false);
  });

  it("flattenAllowlist separates op sets", () => {
    const flat = flattenAllowlist([
      { path: tree.root, access: ["read", "write"] },
      { path: tree.outside, access: "delete" },
    ]);
    expect(flat.read).toContain(canonicalizePath(tree.root).canonical);
    expect(flat.write).toContain(canonicalizePath(tree.root).canonical);
    expect(flat.delete).toContain(canonicalizePath(tree.outside).canonical);
    expect(flat.execute).toHaveLength(0);
  });

  it("canonicalizePath expands ~", () => {
    const c = canonicalizePath("~/nonexistent-rtq-file");
    expect(c.canonical.startsWith(os.homedir())).toBe(true);
  });
});
