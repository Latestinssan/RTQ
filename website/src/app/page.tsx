"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Shield,
  Zap,
  Lock,
  Eye,
  Smartphone,
  Code2,
  ArrowRight,
  Github,
  BookOpen,
  Terminal,
  Check,
  Copy,
  ChevronRight,
  Server,
  Layers,
  FileCheck2,
  AlertTriangle,
  TestTube,
} from "lucide-react";
import { APP_INFO } from "@/lib/version";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { PipelineSimulator } from "@/components/home/PipelineSimulator";
import { CodeShowcase } from "@/components/home/CodeShowcase";
import { InvariantsMatrix } from "@/components/home/InvariantsMatrix";
import { SandboxPlatformViewer } from "@/components/home/SandboxPlatformViewer";
import { HonestLedger } from "@/components/home/HonestLedger";
import { COMMIT_SHA } from "@/components/evidence/EvidenceBadge";

export default function HomePage() {
  const [copiedInstall, setCopiedInstall] = useState(false);

  const handleCopyInstall = async () => {
    try {
      await navigator.clipboard.writeText("npm install @rtq/security");
      setCopiedInstall(true);
      setTimeout(() => setCopiedInstall(false), 2000);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="min-h-screen bg-[#03050c] text-slate-100 selection:bg-sky-500/30 selection:text-white">
      <Navbar />

      {/* Hero Section */}
      <section className="relative overflow-hidden pt-36 pb-20 md:pt-44 md:pb-24">
        {/* Ambient high-tech background glow & mesh */}
        <div className="pointer-events-none absolute inset-0 bg-grid-pattern opacity-40" />
        <div className="pointer-events-none absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[550px] w-[800px] rounded-full bg-sky-500/10 blur-[130px]" />
        <div className="pointer-events-none absolute top-1/3 left-1/3 h-[400px] w-[400px] rounded-full bg-indigo-500/10 blur-[120px]" />

        <div className="relative z-10 mx-auto max-w-5xl px-6 text-center">
          {/* Status Badge */}
          <div className="mb-8 inline-flex items-center gap-2.5 rounded-full border border-sky-500/30 bg-sky-500/10 px-4 py-1.5 font-mono text-xs font-semibold text-sky-300 shadow-[0_0_20px_rgba(56,189,248,0.15)]">
            <Shield size={14} className="text-sky-400" />
            <span>Alpha Release &middot; Apache-2.0 &middot; Zero npm Runtime Dependencies</span>
          </div>

          {/* Main Title */}
          <h1 className="text-4xl font-black tracking-tight text-white sm:text-6xl md:text-7xl">
            RTQ
            <span className="block mt-3 bg-gradient-to-r from-white via-slate-200 to-white/60 bg-clip-text text-2xl font-bold tracking-tight text-transparent sm:text-4xl md:text-5xl">
              Risk-Adaptive Capability Security Runtime
            </span>
          </h1>

          {/* Direct, Honest Value Proposition */}
          <p className="mx-auto mt-6 max-w-3xl text-base leading-relaxed text-slate-300/80 md:text-lg">
            Capability-security runtime for autonomous agents and tools. Every operation requires an
            explicitly registered capability; authorizations are short-lived, single-use,
            cryptographically-signed tickets. Missing rules evaluate to refusal.
          </p>

          {/* Alpha Notice & Evidence Links */}
          <div className="mx-auto mt-6 max-w-2xl rounded-xl border border-amber-500/20 bg-amber-500/[0.04] p-3.5 text-xs text-amber-200/90 flex items-center justify-center gap-2.5 flex-wrap">
            <AlertTriangle size={14} className="text-amber-400 shrink-0" />
            <span>
              <strong>Alpha Software:</strong> RTQ has not undergone an independent security audit.
              Every claim is tied to CI evidence at commit{" "}
              <code className="font-mono text-amber-300">{COMMIT_SHA}</code>.
            </span>
            <Link
              href="/docs/evidence"
              className="inline-flex items-center gap-1 font-mono font-bold text-sky-400 underline hover:text-sky-300"
            >
              <span>View Evidence &rarr;</span>
            </Link>
          </div>

          {/* Quick Install Bar & CTAs */}
          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            {/* 1-Click Copy Install Command */}
            <div className="flex h-12 items-center rounded-xl border border-white/10 bg-white/[0.04] p-1 shadow-inner backdrop-blur-md">
              <div className="flex items-center gap-2 px-3 font-mono text-xs text-sky-400">
                <Terminal size={14} />
                <span className="text-white/40">$</span>
                <span className="text-slate-200">npm install @rtq/security</span>
              </div>
              <button
                onClick={handleCopyInstall}
                className="flex h-full items-center gap-1.5 rounded-lg border border-white/10 bg-white/10 px-3.5 font-mono text-xs font-semibold text-white transition hover:bg-white/20 active:scale-95"
                title="Copy install command"
              >
                {copiedInstall ? (
                  <>
                    <Check size={13} className="text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy size={13} />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>

            {/* CTAs */}
            <Link
              href="/docs/evidence"
              className="flex h-12 items-center gap-2 rounded-xl bg-sky-500 px-6 font-mono text-xs font-bold uppercase tracking-wider text-white transition hover:bg-sky-400 shadow-lg shadow-sky-500/20 active:scale-95"
            >
              <TestTube size={16} />
              <span>Explore CI Evidence</span>
            </Link>

            <Link
              href="/docs/overview"
              className="flex h-12 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-5 font-mono text-xs font-semibold text-white/70 transition hover:border-white/20 hover:bg-white/10 hover:text-white"
            >
              <BookOpen size={16} />
              <span>Read Docs</span>
            </Link>

            <a
              href={APP_INFO.repo}
              target="_blank"
              rel="noopener noreferrer"
              className="flex h-12 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-4 font-mono text-xs font-semibold text-white/50 transition hover:text-white"
            >
              <Github size={16} />
            </a>
          </div>

          {/* Evidence Truth Chips */}
          <div className="mt-14 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-3 text-center backdrop-blur-sm">
              <span className="font-mono text-[10px] uppercase tracking-wider text-sky-400">
                Package Deps
              </span>
              <p className="mt-1 font-mono text-xs font-bold text-white">0 npm Runtime Deps</p>
              <p className="text-[11px] text-white/40">In security-critical packages</p>
            </div>
            <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-3 text-center backdrop-blur-sm">
              <span className="font-mono text-[10px] uppercase tracking-wider text-emerald-400">
                Authoritative
              </span>
              <p className="mt-1 font-mono text-xs font-bold text-white">Risk Engine</p>
              <p className="text-[11px] text-white/40">Caller cannot demote risk (INV-04)</p>
            </div>
            <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-3 text-center backdrop-blur-sm">
              <span className="font-mono text-[10px] uppercase tracking-wider text-purple-400">
                Single-Use
              </span>
              <p className="mt-1 font-mono text-xs font-bold text-white">Signed Tickets</p>
              <p className="text-[11px] text-white/40">Replay yields ok: false (INV-09)</p>
            </div>
            <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-3 text-center backdrop-blur-sm">
              <span className="font-mono text-[10px] uppercase tracking-wider text-amber-400">
                Delegated Sandbox
              </span>
              <p className="mt-1 font-mono text-xs font-bold text-white">Fail-Closed on Missing</p>
              <p className="text-[11px] text-white/40">Seatbelt / bwrap / AppContainer</p>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Pipeline Simulator */}
      <PipelineSimulator />

      {/* Core Architectural Pillars */}
      <section className="relative mx-auto max-w-6xl px-6 py-20">
        <div className="mb-12 text-center">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
            <Lock size={13} />
            <span>Repository Tested Properties</span>
          </div>
          <h2 className="text-3xl font-black tracking-tight text-white md:text-4xl">
            Tested Security Properties at a Glance
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-white/50">
            The repository currently contains automated tests covering the 12 properties listed below. Evidence level varies by property and platform.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[
            {
              icon: Shield,
              title: "Explicit Surface Registration",
              badge: "INV-01 (Unit Tested)",
              desc: "Only registered capabilities can execute. Unknown capability strings return decision: 'denied'.",
            },
            {
              icon: Lock,
              title: "Strict Default-Deny Policy",
              badge: "INV-03 (Unit Tested)",
              desc: "A missing policy rule is a denial, never an implicit allow. There is no silent fallback or permissive degraded state.",
            },
            {
              icon: Zap,
              title: "Authoritative Risk Computation",
              badge: "INV-04 (Unit Tested)",
              desc: "Caller claims can never lower risk. RTQ independently calculates risk from declared base rating and operation factors.",
            },
            {
              icon: Eye,
              title: "Single-Use Signed Tickets",
              badge: "INV-09 (Integration Tested)",
              desc: "Tickets are signed with HMAC-SHA256 and bound to exact operation parameters. Second redemption attempt returns ok: false.",
            },
            {
              icon: Smartphone,
              title: "Challenge-Response Approval",
              badge: "INV-12 (Integration Tested)",
              desc: "Scanning grants zero permissions. Mobile devices sign a cryptographically random challenge nonce; substitution is rejected.",
            },
            {
              icon: Code2,
              title: "Fail-Closed Sandbox Initiation",
              badge: "INV-07 (Construction Tested)",
              desc: "If platform sandbox tooling cannot be initialized, execution halts. Uncontained execution is never permitted by default.",
            },
          ].map((item) => (
            <div
              key={item.title}
              className="group relative flex flex-col justify-between rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6 transition duration-300 hover:border-sky-500/40 hover:bg-sky-500/[0.04] hover:shadow-[0_0_30px_rgba(56,189,248,0.1)]"
            >
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400">
                    <item.icon size={20} />
                  </div>
                  <span className="font-mono text-[10px] font-bold text-sky-400/80 rounded bg-sky-500/10 px-2 py-0.5 border border-sky-500/20">
                    {item.badge}
                  </span>
                </div>
                <h3 className="mt-4 text-base font-bold text-white">{item.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-white/50">{item.desc}</p>
              </div>

              <div className="mt-6 flex items-center gap-1 font-mono text-[11px] font-semibold text-sky-400 opacity-0 transition duration-200 group-hover:opacity-100">
                <Link href="/docs/evidence" className="inline-flex items-center gap-1">
                  <span>View Evidence Chain</span>
                  <ChevronRight size={13} />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Code Showcase Tabbed Terminal */}
      <CodeShowcase />

      {/* Platform Sandboxing Deep Dive */}
      <SandboxPlatformViewer />

      {/* 12 Invariants Verification Matrix */}
      <InvariantsMatrix />

      {/* The Honest Ledger: Guarantees vs Limitations */}
      <HonestLedger />

      {/* Packages Breakdown */}
      <section id="packages" className="relative mx-auto max-w-6xl px-6 py-20">
        <div className="mb-10 text-center">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
            <Layers size={13} />
            <span>Modular Architecture</span>
          </div>
          <h2 className="text-3xl font-black tracking-tight text-white md:text-4xl">
            10 Focused Packages
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-white/50">
            Security-critical packages declare zero third-party npm dependencies. Import only what you
            need, or use the pipeline façade via <code className="text-sky-300">@rtq/security</code>.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-2">
          {[
            {
              name: "@rtq/core",
              desc: "Security-model types, capability registry, atomic ticket store, and schema validation.",
              tag: "0 Third-Party Deps",
            },
            {
              name: "@rtq/risk",
              desc: "Authoritative risk computation engine. Ignores caller claims to lower privilege.",
              tag: "0 Third-Party Deps",
            },
            {
              name: "@rtq/policy",
              desc: "Default-deny declarative rules evaluator. Missing rules evaluate to refusal.",
              tag: "0 Third-Party Deps",
            },
            {
              name: "@rtq/crypto",
              desc: "RFC 8785 Canonical JSON, HMAC-SHA256, constant-time compare, and nonce validation.",
              tag: "0 Third-Party Deps",
            },
            {
              name: "@rtq/approval",
              desc: "Verification strategies, QR challenge-response protocols, and mobile pairing.",
              tag: "Interactive",
            },
            {
              name: "@rtq/sandbox",
              desc: "Adapters for macOS Seatbelt, Linux bubblewrap, and Windows AppContainer.",
              tag: "OS Delegation",
            },
            {
              name: "@rtq/audit",
              desc: "Structured, tamper-evident event logging with automatic secret and token redaction.",
              tag: "Redacted Trail",
            },
            {
              name: "@rtq/clarification",
              desc: "Structured interactive questions for missing parameters with timeout invariants.",
              tag: "Bounded Loop",
            },
            {
              name: "@rtq/security",
              desc: "Unified pipeline façade (createRTQ) binding registry, policy, tickets, and sandbox.",
              tag: "Primary Façade",
            },
            {
              name: "@rtq/cli",
              desc: "Actionable operator tooling for verifying invariants, testing sandboxes, and diagnostics.",
              tag: "Operator Tooling",
            },
          ].map((pkg) => (
            <div
              key={pkg.name}
              className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 transition hover:border-sky-500/30 hover:bg-sky-500/[0.02]"
            >
              <div className="flex items-center justify-between">
                <code className="font-mono text-xs font-bold text-sky-400">{pkg.name}</code>
                <span className="rounded bg-white/5 px-2 py-0.5 font-mono text-[10px] text-white/40">
                  {pkg.tag}
                </span>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-white/60">{pkg.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Bottom CTA Banner */}
      <section className="relative mx-auto max-w-5xl px-6 pb-24">
        <div className="relative overflow-hidden rounded-3xl border border-sky-500/30 bg-gradient-to-b from-sky-500/10 to-transparent p-8 text-center md:p-14 shadow-2xl">
          <div className="pointer-events-none absolute -top-24 left-1/2 -translate-x-1/2 h-48 w-96 rounded-full bg-sky-500/20 blur-3xl" />

          <h2 className="text-2xl font-black text-white md:text-4xl">
            Evidence-Backed Capability Security
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm leading-relaxed text-white/60">
            Inspect the evidence matrix, browse source lines pinned to commit {COMMIT_SHA}, or explore
            the quickstart integration guide.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Link
              href="/docs/evidence"
              className="flex items-center gap-2 rounded-xl bg-white px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-black transition hover:bg-sky-400 hover:text-white"
            >
              <TestTube size={16} /> View Evidence Matrix
            </Link>
            <Link
              href="/docs/overview"
              className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-white transition hover:bg-white/10 hover:text-white"
            >
              <BookOpen size={16} /> Quickstart Guide
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
