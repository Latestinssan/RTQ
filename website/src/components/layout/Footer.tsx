import Link from "next/link";
import { Shield, Github, BookOpen, ExternalLink, CheckCircle2, Lock } from "lucide-react";
import { APP_INFO } from "@/lib/version";

export function Footer() {
  return (
    <footer className="relative border-t border-white/[0.08] bg-[#020308] text-white/60">
      {/* Subtle top ambient glow */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-sky-500/30 to-transparent" />

      <div className="mx-auto max-w-7xl px-6 py-16">
        <div className="grid grid-cols-1 gap-10 md:grid-cols-2 lg:grid-cols-5">
          {/* Brand & Manifesto */}
          <div className="lg:col-span-2">
            <Link href="/" className="inline-flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10">
                <Shield className="h-4 w-4 text-sky-400" />
              </div>
              <span className="font-mono text-base font-black tracking-widest text-white">
                RTQ
              </span>
            </Link>
            <p className="mt-4 max-w-sm text-xs leading-relaxed text-white/50">
              Risk-Adaptive Capability Security Runtime (Alpha). Security-critical packages currently declare
              zero npm runtime dependencies. Every operation passes through explicit capability checks,
              authoritative risk evaluation, default-deny policy, single-use signed tickets, and OS sandbox delegation.
            </p>
            <div className="mt-6 flex flex-wrap items-center gap-3 text-xs text-white/40">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1 font-mono text-[10px] text-emerald-400">
                <CheckCircle2 size={12} /> Apache-2.0 Licensed
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1 font-mono text-[10px] text-sky-400">
                <Lock size={12} /> 0 npm runtime deps
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1 font-mono text-[10px] text-white/40">
                Pinned at commit e179d2b
              </span>
            </div>
          </div>

          {/* Architecture & Docs */}
          <div>
            <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-white">
              Architecture
            </h4>
            <ul className="mt-4 space-y-2.5 text-xs">
              <li>
                <Link href="/docs/overview" className="transition hover:text-white">
                  Overview & Pipeline
                </Link>
              </li>
              <li>
                <Link href="/docs/security-overview" className="transition hover:text-white">
                  Security Model
                </Link>
              </li>
              <li>
                <Link href="/docs/threat-model" className="transition hover:text-white">
                  Threat Model & Limitations
                </Link>
              </li>
              <li>
                <Link href="/docs/platform-support" className="transition hover:text-white">
                  Platform Sandboxes
                </Link>
              </li>
              <li>
                <Link href="/docs/mobile-approval" className="transition hover:text-white">
                  Mobile QR Challenge
                </Link>
              </li>
              <li>
                <Link href="/docs/aartiq-integration" className="transition hover:text-white">
                  Aartiq MCP Bridge
                </Link>
              </li>
            </ul>
          </div>

          {/* Verification & Proof */}
          <div>
            <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-white">
              Verification
            </h4>
            <ul className="mt-4 space-y-2.5 text-xs">
              <li>
                <Link href="/docs/evidence" className="font-bold text-sky-400 hover:text-sky-300">
                  Evidence & Verification &rarr;
                </Link>
              </li>
              <li>
                <Link href="/docs/verification-matrix" className="transition hover:text-white">
                  12 Tested Properties
                </Link>
              </li>
              <li>
                <Link href="/docs/verification-traceability" className="transition hover:text-white">
                  Source Code Traceability
                </Link>
              </li>
              <li>
                <Link href="/docs/testing-strategy" className="transition hover:text-white">
                  Testing Strategy & CI
                </Link>
              </li>
              <li>
                <Link href="/docs/cli" className="transition hover:text-white">
                  Operator CLI Reference
                </Link>
              </li>
              <li>
                <Link href="/docs/provenance" className="transition hover:text-white">
                  Implementation Provenance
                </Link>
              </li>
            </ul>
          </div>

          {/* Packages & Source */}
          <div>
            <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-white">
              Ecosystem
            </h4>
            <ul className="mt-4 space-y-2.5 text-xs font-mono">
              <li>
                <a
                  href={APP_INFO.repo}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 text-sky-400 hover:text-sky-300"
                >
                  <Github size={13} />
                  <span>GitHub Repository</span>
                </a>
              </li>
              <li className="text-white/40">@rtq/core</li>
              <li className="text-white/40">@rtq/risk</li>
              <li className="text-white/40">@rtq/policy</li>
              <li className="text-white/40">@rtq/sandbox</li>
              <li className="text-white/40">@rtq/audit</li>
              <li className="text-white/40">@rtq/crypto</li>
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-14 flex flex-col items-center justify-between border-t border-white/[0.06] pt-8 text-xs text-white/40 md:flex-row">
          <p>
            &copy; {new Date().getFullYear()} RTQ Contributors. Released under Apache-2.0. Alpha software not independently audited.
          </p>
          <div className="mt-4 flex items-center gap-6 md:mt-0 font-mono text-[11px]">
            <span>Evidence-Based</span>
            <span>&bull;</span>
            <span>Zero npm Runtime Deps</span>
            <span>&bull;</span>
            <Link href="/docs/evidence" className="text-sky-400 hover:underline">
              CI Evidence Chains
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
