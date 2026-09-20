import { describe, expect, it } from "vitest";
import { AuditLogger, MemorySink, AUDIT_EVENTS } from "@rtq/audit";

describe("AuditLogger", () => {
  it("emits structured events with sequence + timestamp and audits capability/ticket refs", () => {
    const sink = new MemorySink();
    const log = new AuditLogger(sink);
    log.emit(
      "CAPABILITY_REGISTERED",
      "registered",
      { name: "x" },
      { capability: "x" },
    );
    log.emit("TICKET_ISSUED", "ticket", { id: "t1" }, { ticketId: "t1" });
    const events = log.snapshot();
    expect(events).toHaveLength(2);
    expect(events[0]!.seq).toBe(1);
    expect(events[0]!.event).toBe("CAPABILITY_REGISTERED");
    expect(events[0]!.capability).toBe("x");
    expect(events[1]!.ticketId).toBe("t1");
    expect(typeof events[0]!.timestamp).toBe("number");
  });

  it("redacts secrets in context before they reach the sink", () => {
    const sink = new MemorySink();
    const log = new AuditLogger(sink);
    log.emit("AUTHORIZATION_REQUESTED", "ctx", {
      apiKey: "sk-live-1234567890",
      password: "hunter2",
      safe: "visible",
      nested: { authorization: "Bearer abcdefghij" },
    });
    const entry = log.snapshot()[0]!;
    expect(entry.context.safe).toBe("visible");
    expect(entry.context.apiKey).toBe("[REDACTED]");
    expect(entry.context.password).toBe("[REDACTED]");
    expect(
      (entry.context.nested as Record<string, unknown>).authorization,
    ).toBe("[REDACTED]");
    expect(JSON.stringify(entry)).not.toContain("hunter2");
    expect(JSON.stringify(entry)).not.toContain("sk-live-1234567890");
  });

  it("redacts caller-supplied secret values", () => {
    const log = new AuditLogger(new MemorySink(), {
      secretValues: new Set(["super-secret-token-value"]),
    });
    log.emit("POLICY_CONFIGURED", "val=super-secret-token-value", {});
    expect(log.snapshot()[0]!.message).not.toContain(
      "super-secret-token-value",
    );
  });

  it("exposes the full event taxonomy including required names", () => {
    expect(AUDIT_EVENTS).toContain("CAPABILITY_REGISTERED");
    expect(AUDIT_EVENTS).toContain("EXECUTION_DENIED");
    expect(AUDIT_EVENTS).toContain("TICKET_REPLAYED");
    expect(AUDIT_EVENTS).toContain("SANDBOX_FAILED");
    expect(AUDIT_EVENTS).toContain("APPROVAL_GRANTED");
  });

  it("bounds the in-memory sink", () => {
    const sink = new MemorySink(3);
    const log = new AuditLogger(sink);
    for (let i = 0; i < 6; i++) log.emit("EXECUTION_DENIED", `e${i}`);
    expect(log.snapshot()).toHaveLength(3);
  });
});
