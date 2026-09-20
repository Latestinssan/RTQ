import { redactString, redactValue } from "@rtq/crypto";
import type {
  AuditEvent,
  AuditEventName,
  AuditRedactionPolicy,
  AuditSink,
  Auditor,
} from "./types";

export type {
  AuditEvent,
  AuditEventName,
  AuditRedactionPolicy,
  AuditSink,
  Auditor,
};

export class NoopSink implements AuditSink {
  write(): void {
    /* no-op */
  }
}

/** In-memory sink (bounded) — used by tests and as the default. */
export class MemorySink implements AuditSink {
  readonly events: AuditEvent[] = [];
  private readonly maxEvents: number;

  constructor(maxEvents = 10_000) {
    this.maxEvents = maxEvents;
  }

  write(event: AuditEvent): void {
    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }
  }

  /** Copy of the events recorded so far. */
  snapshot(): AuditEvent[] {
    return [...this.events];
  }
}

export interface FileSinkOptions {
  /** Append (default: true). */
  append?: boolean;
  /** Redaction policy forwarded at write time (values are already redacted by the Auditor). */
  policy?: AuditRedactionPolicy;
}

/** JSONL file sink. Never logs unredacted content because Auditors redact first. */
export class FileSink implements AuditSink {
  private readonly fd: import("fs").WriteStream | null = null;
  private readonly path: string;

  constructor(path: string, options: FileSinkOptions = {}) {
    this.path = path;
    try {
      const fs = require("fs");
      this.fd = fs.createWriteStream(path, {
        flags: options.append === false ? "w" : "a",
      });
    } catch {
      this.fd = null;
    }
  }

  write(event: AuditEvent): void {
    if (!this.fd) return;
    this.fd.write(JSON.stringify(event) + "\n");
  }

  close(): void {
    if (this.fd) this.fd.end();
  }

  get pathName(): string {
    return this.path;
  }
}

export class AuditLogger implements Auditor {
  readonly sink: AuditSink;
  readonly events: readonly AuditEvent[];
  private readonly policy: AuditRedactionPolicy;
  private seq = 0;

  constructor(
    sink: AuditSink = new MemorySink(),
    policy: AuditRedactionPolicy = {},
  ) {
    this.sink = sink;
    this.events = sink instanceof MemorySink ? sink.events : [];
    this.policy = policy;
  }

  emit(
    event: AuditEventName,
    message: string,
    context: Record<string, unknown> = {},
    refs: { capability?: string; ticketId?: string } = {},
  ): void {
    const secretValues = this.policy.secretValues ?? new Set();
    const redactedContext = redactValue(context, secretValues) as Record<
      string,
      unknown
    >;
    // Messages are attacker/configuration-influenced too (they interpolate
    // capability names, reasons and ticket ids). Redact them as well so a
    // secret can never reach the sink merely by appearing in prose.
    const redactedMessage = redactString(message, secretValues);
    const entry: AuditEvent = {
      seq: ++this.seq,
      event,
      timestamp: Date.now(),
      message: redactedMessage,
      context: redactedContext,
      ...(refs.capability ? { capability: refs.capability } : {}),
      ...(refs.ticketId ? { ticketId: refs.ticketId } : {}),
    };
    this.sink.write(entry);
  }

  snapshot(): AuditEvent[] {
    return [...this.events];
  }
}

export * from "./types";
