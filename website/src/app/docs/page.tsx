import Link from "next/link";
import { APP_INFO } from "@/lib/version";
import {
  BookOpen, Shield, AlertTriangle, CheckCircle2, Layers,
  Server, Code2, Smartphone, Zap, Eye, FileText, ArrowRight,
} from "lucide-react";

export default function DocsIndex() {
  const pages = [
    { href: "/docs/overview", icon: BookOpen, title: "Overview", desc: "RTQ pipeline, packages, and getting started." },
    { href: "/docs/security-overview", icon: Shield, title: "Security Overview", desc: "Pipeline layers, core principles, quick example." },
    { href: "/docs/threat-model", icon: AlertTriangle, title: "Threat Model", desc: "Trust boundaries, threats, mitigations, honest limitations." },
    { href: "/docs/verification-matrix", icon: CheckCircle2, title: "Verification Matrix", desc: "12 automated invariants, test suites, platform gating." },
    { href: "/docs/verification-traceability", icon: Layers, title: "Verification & Traceability", desc: "Source file:line citations for every security claim." },
    { href: "/docs/platform-support", icon: Server, title: "Platform Support", desc: "macOS Seatbelt, Linux bubblewrap, Windows AppContainer." },
    { href: "/docs/aartiq-integration", icon: Code2, title: "Aartiq Integration", desc: "How to bring RTQ to an Aartiq-style federated MCP app." },
    { href: "/docs/mobile-approval", icon: Smartphone, title: "Mobile Approval", desc: "QR challenge-response, signing, pairing, protocol." },
    { href: "/docs/cli", icon: Zap, title: "CLI Reference", desc: "Capabilities, policy check, sandbox test, verify, diagnostics." },
    { href: "/docs/testing-strategy", icon: Eye, title: "Testing Strategy", desc: "Labels, suites, platform gating, CI." },
    { href: "/docs/provenance", icon: FileText, title: "Provenance", desc: "Original implementation, audit trail, design inputs." },
  ];

  return (
    <div>
      <div className="mb-12">
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">RTQ Documentation</h1>
        <p className="text-lg text-white/50">
          Dependency-free capability-security runtime. Every operation is an explicitly
          registered capability; every authorization is a short-lived, single-use,
          cryptographically-signed ticket.
        </p>
      </div>

      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-sky-400">Command</span> → Capability (registered) → Risk (authoritative) → Policy (default-deny)<br />
        &nbsp;&nbsp;&nbsp;→ Clarification → Approval (human/device) → Ticket (signed, single-use)<br />
        &nbsp;&nbsp;&nbsp;→ Execution (OS-sandboxed) → Audit (redacted)
      </div>

      <div className="grid gap-3">
        {pages.map((p) => (
          <Link key={p.href} href={p.href}
            className="group flex items-center gap-4 rounded-2xl border border-white/5 bg-white/[0.02] p-5 transition hover:border-sky-500/30 hover:bg-sky-500/5">
            <p.icon size={20} className="shrink-0 text-sky-400" />
            <div className="flex-1">
              <p className="text-sm font-bold text-white">{p.title}</p>
              <p className="text-xs text-white/40">{p.desc}</p>
            </div>
            <ArrowRight size={16} className="shrink-0 text-white/20 transition group-hover:text-sky-400" />
          </Link>
        ))}
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-2 text-xs font-black uppercase tracking-wider text-white/30">Quick start</p>
        <pre className="overflow-x-auto text-xs text-white/50"><code>{`import { createRTQ } from "@rtq/security";

const rtq = createRTQ({ signingKey: process.env.RTQ_SIGNING_KEY! });

rtq.registerCapability({
  name: "files.read",
  version: 1,
  description: "Read a file inside the workspace",
  inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  risk: { base: "low" },
  execute: async (ctx, input) => ({ ok: true, data: { input } }),
});`}</code></pre>
      </div>
    </div>
  );
}
