import Link from "next/link";
import { APP_INFO } from "@/lib/version";
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
} from "lucide-react";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[#03040b] text-white">
      {/* Hero */}
      <section className="relative flex flex-col items-center justify-center px-6 pt-32 pb-20 text-center">
        <div className="pointer-events-none absolute inset-0 overflow-hidden">
          <div className="absolute left-1/2 top-0 -translate-x-1/2 h-[600px] w-[600px] rounded-full bg-sky-500/5 blur-3xl" />
        </div>
        <div className="relative z-10 mx-auto max-w-3xl">
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-widest text-sky-400">
            <Shield size={14} /> Open Source &middot; Apache-2.0
          </div>
          <h1 className="mb-6 text-5xl font-black leading-tight tracking-tight md:text-7xl">
            RTQ
            <span className="block mt-2 text-2xl font-bold text-white/60 md:text-3xl">
              Risk-Adaptive Capability Security Runtime
            </span>
          </h1>
          <p className="mx-auto mb-10 max-w-2xl text-lg text-white/50 leading-relaxed">
            Dependency-free capability-security runtime. Every operation is an
            explicitly registered capability; every authorization is a
            short-lived, single-use, cryptographically-signed ticket.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <Link
              href="/docs/overview"
              className="flex items-center gap-2 rounded-xl bg-white px-6 py-3 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-sky-400 hover:text-white"
            >
              <BookOpen size={16} /> Read the Docs
            </Link>
            <a
              href={APP_INFO.repo}
              target="_blank"
              className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-6 py-3 text-sm font-bold uppercase tracking-wider text-white/60 transition hover:bg-white/10 hover:text-white"
            >
              <Github size={16} /> GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Pipeline */}
      <section className="mx-auto max-w-4xl px-6 pb-20">
        <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-8 font-mono text-sm leading-relaxed text-white/60">
          <span className="text-sky-400">Command</span>{" "}
          → <span className="text-white/80">Capability</span> (registered){" "}
          → <span className="text-white/80">Risk</span> (authoritative){" "}
          → <span className="text-white/80">Policy</span> (default-deny)
          <br />
          &nbsp;&nbsp;&nbsp;→ <span className="text-white/80">Clarification</span>{" "}
          → <span className="text-white/80">Approval</span> (human/device){" "}
          → <span className="text-white/80">Ticket</span> (signed, single-use)
          <br />
          &nbsp;&nbsp;&nbsp;→ <span className="text-white/80">Execution</span>{" "}
          (OS-sandboxed){" "}
          → <span className="text-white/80">Audit</span> (redacted)
        </div>
      </section>

      {/* Features Grid */}
      <section className="mx-auto max-w-6xl px-6 pb-24">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[
            { icon: Shield, title: "Explicit Surface", desc: "Only registered capabilities can run. Everything else is denied." },
            { icon: Lock, title: "Default Deny", desc: "A missing rule is a denial, never an allow." },
            { icon: Zap, title: "Authoritative Risk", desc: "Caller claims can never lower risk. RTQ computes risk itself." },
            { icon: Eye, title: "Single-Use Tickets", desc: "HMAC-SHA256, bound to exact operation; replay and tamper are rejected." },
            { icon: Smartphone, title: "QR / Mobile Approval", desc: "Challenge-response only — scanning grants nothing. No PINs." },
            { icon: Code2, title: "Fail-Closed Sandbox", desc: "No sandbox → no execution. The escape hatch is explicit and reported." },
          ].map((f) => (
            <div
              key={f.title}
              className="group rounded-2xl border border-white/5 bg-white/[0.02] p-6 transition hover:border-sky-500/30 hover:bg-sky-500/5"
            >
              <f.icon size={24} className="mb-4 text-sky-400" />
              <h3 className="mb-2 text-sm font-bold uppercase tracking-wider text-white">
                {f.title}
              </h3>
              <p className="text-sm text-white/40 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Packages */}
      <section className="mx-auto max-w-4xl px-6 pb-24">
        <h2 className="mb-8 text-center text-xs font-black uppercase tracking-[0.5em] text-white/20">
          Packages
        </h2>
        <div className="grid gap-3 md:grid-cols-2">
          {[
            ["@rtq/core", "Security-model types, registry, ticket store"],
            ["@rtq/risk", "Authoritative risk engine"],
            ["@rtq/policy", "Default-deny declarative rules"],
            ["@rtq/clarification", "Structured questions for missing params"],
            ["@rtq/approval", "Strategies + QR/mobile challenge-response"],
            ["@rtq/sandbox", "macOS Seatbelt, Linux bubblewrap, Windows AppContainer"],
            ["@rtq/audit", "Structured, redacted events"],
            ["@rtq/security", "Pipeline façade (createRTQ)"],
            ["@rtq/crypto", "Canonical JSON, HMAC-SHA256, constant-time compare"],
            ["@rtq/cli", "Actionable operator tooling"],
          ].map(([pkg, desc]) => (
            <div
              key={pkg}
              className="flex items-start gap-3 rounded-xl border border-white/5 bg-white/[0.02] p-4"
            >
              <code className="shrink-0 text-xs font-bold text-sky-400">{pkg}</code>
              <span className="text-xs text-white/40">{desc}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/5 py-12 text-center text-sm text-white/30">
        <p>
          Apache-2.0 &middot;{" "}
          <a href={APP_INFO.repo} target="_blank" className="hover:text-white transition">
            GitHub
          </a>{" "}
          &middot;{" "}
          <Link href="/docs/overview" className="hover:text-white transition">
            Docs
          </Link>
        </p>
      </footer>
    </div>
  );
}
