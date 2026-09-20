import Link from "next/link";
import { APP_INFO } from "@/lib/version";
import { COMMIT_SHA } from "@/components/evidence/EvidenceBadge";
import { TestTube, Shield, BookOpen, ExternalLink, Download, Smartphone, Package } from "lucide-react";

export const metadata = {
  title: "RTQ Overview",
  description: "Introduction to RTQ pipeline, zero-npm-runtime-dependency packages, and evidence-backed security.",
};

export default function OverviewPage() {
  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Getting Started &bull; Overview
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          RTQ Overview
        </h1>
        <p className="mt-4 text-base text-white/70 leading-relaxed">
          RTQ is a production-grade, dependency-free capability-security runtime for Node.js, TypeScript,
          Model Context Protocol (MCP) servers, and mobile approval hosts. Every operation requires an
          explicitly registered capability; authorizations are short-lived, single-use, cryptographically-signed tickets.
        </p>
      </div>

      {/* Why RTQ Was Created */}
      <div className="rounded-2xl border border-sky-500/20 bg-sky-500/[0.03] p-6 text-sm leading-relaxed text-slate-200 space-y-3">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Shield className="text-sky-400" size={18} />
          <span>Why RTQ Was Created</span>
        </h2>
        <p className="text-white/80">
          While developing <strong>Aartiq</strong>, a disproportionate amount of engineering time was spent repeatedly
          implementing OS-level sandboxing, capability scoping, fine-grained permission gating, and challenge-response
          authorization from scratch.
        </p>
        <p className="text-white/80">
          RTQ was created to solve this problem once and for all — packaging a battle-tested, risk-adaptive capability
          security runtime into a clean suite of reusable packages. With RTQ, developers can instantly integrate capability
          security, OS-enforced sandboxing, Model Context Protocol (MCP) policy enforcement, and mobile QR challenge-response
          approvals into their applications without having to build security infrastructure from scratch.
        </p>
      </div>

      {/* Release & Downloads Card */}
      <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Download className="text-sky-400" size={18} />
          <span>Release v1.0.0 &amp; Downloads</span>
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 text-xs">
          <a
            href={APP_INFO.releases}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between rounded-xl border border-white/10 bg-white/5 p-4 transition hover:bg-white/10 hover:border-white/20"
          >
            <div className="space-y-1">
              <span className="font-mono font-bold text-sky-400 text-sm">GitHub Release v1.0.0</span>
              <p className="text-white/50">Tag provenance, assets &amp; source code</p>
            </div>
            <ExternalLink size={16} className="text-white/40" />
          </a>

          <a
            href={APP_INFO.apkDownload}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 transition hover:bg-emerald-500/20"
          >
            <div className="space-y-1">
              <span className="font-mono font-bold text-emerald-300 text-sm flex items-center gap-1.5">
                <Smartphone size={15} /> Android Mobile App (.apk)
              </span>
              <p className="text-emerald-200/60">Flutter Ed25519 approval host (62 MB)</p>
            </div>
            <Download size={16} className="text-emerald-400" />
          </a>
        </div>
      </div>

      {/* Core Pipeline */}
      <div>
        <h2 className="text-xl font-bold text-white mb-4">Core Security Pipeline</h2>
        <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-5 font-mono text-xs leading-relaxed text-white/60">
          <span className="text-sky-400">Command</span> &rarr;{" "}
          <span className="text-white/80">Capability</span> (registered) &rarr;{" "}
          <span className="text-white/80">Risk</span> (authoritative) &rarr;{" "}
          <span className="text-white/80">Policy</span> (default-deny)
          <br />
          &nbsp;&nbsp;&nbsp;&rarr; <span className="text-white/80">Clarification</span> &rarr;{" "}
          <span className="text-white/80">Approval</span> (challenge-response) &rarr;{" "}
          <span className="text-white/80">Ticket</span> (signed, single-use)
          <br />
          &nbsp;&nbsp;&nbsp;&rarr; <span className="text-white/80">Execution</span> (OS-sandboxed) &rarr;{" "}
          <span className="text-white/80">Audit</span> (redacted)
        </div>
      </div>

      {/* Packages Grid */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white">Published npm Packages</h2>
          <a
            href={APP_INFO.npmOrg}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-sky-400 hover:underline flex items-center gap-1"
          >
            <Package size={14} /> View @rtq Scope on npm &rarr;
          </a>
        </div>
        <div className="grid gap-3 md:grid-cols-2 text-xs">
          {[
            ["@rtq/security", "Pipeline façade (createRTQ) unifying the security model", "https://www.npmjs.com/package/@rtq/security"],
            ["@rtq/cli", "Operator tooling, verification suites, and sandbox test harnesses", "https://www.npmjs.com/package/@rtq/cli"],
            ["@rtq/mcp", "Business-Grade MCP integration layer & security gateway", "https://www.npmjs.com/package/@rtq/mcp"],
            ["@rtq/core", "Security-model types, capability registry, atomic ticket store", "https://www.npmjs.com/package/@rtq/core"],
            ["@rtq/risk", "Authoritative risk engine; ignores caller demotion attempts", "https://www.npmjs.com/package/@rtq/risk"],
            ["@rtq/policy", "Default-deny declarative rule evaluator", "https://www.npmjs.com/package/@rtq/policy"],
            ["@rtq/crypto", "RFC 8785 canonical JSON, HMAC-SHA256, constant-time compare", "https://www.npmjs.com/package/@rtq/crypto"],
            ["@rtq/approval", "Verification strategies + QR/mobile challenge-response", "https://www.npmjs.com/package/@rtq/approval"],
            ["@rtq/sandbox", "macOS Seatbelt, Linux bubblewrap, Windows AppContainer wrappers", "https://www.npmjs.com/package/@rtq/sandbox"],
            ["@rtq/audit", "Structured, HMAC-integrity redacted event logging", "https://www.npmjs.com/package/@rtq/audit"],
            ["@rtq/clarification", "Structured questions for missing parameters with timeout", "https://www.npmjs.com/package/@rtq/clarification"],
            ["@rtq/mobile", "Mobile approval host transport and pairing server", "https://www.npmjs.com/package/@rtq/mobile"],
          ].map(([pkg, desc, url]) => (
            <a
              key={pkg}
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-xl border border-white/5 bg-white/[0.02] p-4 transition hover:bg-white/[0.05] hover:border-sky-500/30 block group"
            >
              <div className="flex items-center justify-between">
                <code className="text-xs font-bold text-sky-400 font-mono group-hover:text-sky-300">{pkg}</code>
                <ExternalLink size={12} className="text-white/30 group-hover:text-sky-400" />
              </div>
              <p className="mt-1 text-white/50">{desc}</p>
            </a>
          ))}
        </div>
      </div>

      {/* Quick Start */}
      <div>
        <h2 className="text-xl font-bold text-white mb-4">Quick Start</h2>
        <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-5 font-mono text-xs leading-relaxed text-white/60 space-y-3">
          <p className="text-white/40"># Install the main security runtime</p>
          <p className="text-emerald-300 font-bold">npm install @rtq/security</p>
          <br />
          <p className="text-white/40"># Or install the CLI</p>
          <p className="text-emerald-300 font-bold">npm install -g @rtq/cli</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition inline-flex items-center gap-1.5"
        >
          <TestTube size={13} />
          <span>Security Evidence &rarr;</span>
        </Link>
        <Link
          href="/docs/threat-model"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          Threat Model &amp; Limitations &rarr;
        </Link>
        <Link
          href="/docs/verification-matrix"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          12 Tested Properties &rarr;
        </Link>
      </div>
    </div>
  );
}
