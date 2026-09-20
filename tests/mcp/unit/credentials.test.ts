import { describe, expect, it } from "vitest";
import { InMemoryCredentialVault, type McpCredentialRecord } from "@rtq/mcp";

function vault(): InMemoryCredentialVault {
  return new InMemoryCredentialVault();
}

describe("InMemoryCredentialVault", () => {
  it("store and retrieve a credential", () => {
    const v = vault();
    const record = v.store({
      credential: "secret-key-123",
      credentialClass: "read",
      serverId: "srv1",
      agentId: "agent-1",
    });
    expect(record.id).toBeTruthy();
    expect(record.credential).toBe("secret-key-123");

    const retrieved = v.retrieve({
      serverId: "srv1",
      agentId: "agent-1",
    });
    expect(retrieved).toBeDefined();
    expect(retrieved!.credential).toBe("secret-key-123");
  });

  it("retrieve returns undefined for no match", () => {
    const v = vault();
    v.store({
      credential: "key",
      credentialClass: "read",
      serverId: "srv1",
    });
    expect(v.retrieve({ serverId: "srv2" })).toBeUndefined();
  });

  it("revoke removes a credential by id", () => {
    const v = vault();
    const rec = v.store({
      credential: "key",
      credentialClass: "read",
      serverId: "srv1",
    });
    v.revoke(rec.id);
    expect(v.retrieve({ serverId: "srv1" })).toBeUndefined();
  });

  it("revokeServer removes all credentials for a server", () => {
    const v = vault();
    v.store({ credential: "k1", credentialClass: "read", serverId: "srv1" });
    v.store({ credential: "k2", credentialClass: "write", serverId: "srv1" });
    v.store({ credential: "k3", credentialClass: "read", serverId: "srv2" });

    const revoked = v.revokeServer("srv1");
    expect(revoked).toBe(2);
    expect(v.retrieve({ serverId: "srv1" })).toBeUndefined();
    expect(v.retrieve({ serverId: "srv2" })).toBeDefined();
  });

  it("revokeScope removes matching scoped credentials", () => {
    const v = vault();
    v.store({
      credential: "k1",
      credentialClass: "read",
      serverId: "srv1",
      toolName: "toolA",
    });
    v.store({
      credential: "k2",
      credentialClass: "read",
      serverId: "srv1",
      toolName: "toolB",
    });

    const revoked = v.revokeScope({ serverId: "srv1", toolName: "toolA" });
    expect(revoked).toBe(1);
  });

  it("list returns all credentials", () => {
    const v = vault();
    v.store({ credential: "k1", credentialClass: "read", serverId: "srv1" });
    v.store({ credential: "k2", credentialClass: "write", serverId: "srv2" });
    expect(v.list()).toHaveLength(2);
  });

  it("count tracks stored credentials", () => {
    const v = vault();
    expect(v.count()).toBe(0);
    v.store({ credential: "k1", credentialClass: "read", serverId: "srv1" });
    expect(v.count()).toBe(1);
  });

  it("onUse callback fires on retrieve", () => {
    let used = false;
    const v = new InMemoryCredentialVault();
    v.onUse(() => {
      used = true;
    });
    v.store({ credential: "k1", credentialClass: "read", serverId: "srv1" });
    v.retrieve({ serverId: "srv1" });
    expect(used).toBe(true);
  });

  it("onRevoke callback fires on revoke", () => {
    let revokedCb: McpCredentialRecord | undefined;
    const v = new InMemoryCredentialVault();
    v.onRevoke((r) => {
      revokedCb = r;
    });
    const rec = v.store({
      credential: "k1",
      credentialClass: "read",
      serverId: "srv1",
    });
    v.revoke(rec.id);
    expect(revokedCb).toBeDefined();
    expect(revokedCb!.id).toBe(rec.id);
  });

  it("purgeExpired removes expired credentials", () => {
    const v = vault();
    v.store({
      credential: "k1",
      credentialClass: "read",
      serverId: "srv1",
      toolName: "toolA",
      expiresAt: Date.now() - 10000,
    });
    v.store({
      credential: "k2",
      credentialClass: "read",
      serverId: "srv1",
      toolName: "toolB",
      expiresAt: Date.now() + 100000,
    });
    const purged = v.purgeExpired();
    expect(purged).toBe(1);
    expect(v.count()).toBe(1);
  });
});
