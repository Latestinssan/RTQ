import Link from "next/link";
import { CheckCircle2, AlertTriangle, ArrowRight, Shield, TestTube, Code2, Lock } from "lucide-react";
import { COMMIT_SHA } from "@/components/evidence/EvidenceBadge";

export function HonestLedger() {
  return (
    <section className="relative mx-auto max-w-6xl px-6 py-20">
      <div className="mb-12 text-center">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
          <Shield size={13} />
          <span>The Security Contract</span>
        </div>
        <h2 className="text-3xl font-black tracking-tight text-white md:text-4xl">
          The Honest Security Contract
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-sm leading-relaxed text-white/50">
          Security software that promises everything delivers nothing. RTQ establishes clear boundaries.
          We distinguish between what is implemented, what is automatically tested, and what has not been
          established.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        {/* 1. Implemented */}
        <div className="flex flex-col justify-between rounded-2xl border border-sky-500/20 bg-sky-500/[0.02] p-6">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-wider text-sky-400">
              <Code2 size={16} />
              <span>1. What Is Implemented</span>
            </div>
            <h3 className="mt-2 text-lg font-black text-white">Repository Logic</h3>

            <ul className="mt-5 space-y-3.5 text-xs text-white/70">
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
                <div>
                  <strong className="text-white">Explicit Registry:</strong> Unknown capabilities reject execution at the boundary.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
                <div>
                  <strong className="text-white">Authoritative Risk:</strong> Caller claimedRisk cannot downgrade declared risk levels.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
                <div>
                  <strong className="text-white">Signed Tickets:</strong> HMAC-SHA256 bound to exact parameters and action.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
                <div>
                  <strong className="text-white">Zero npm Runtime Deps:</strong> Security-critical packages declare 0 third-party npm deps.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
                <div>
                  <strong className="text-white">Sandbox Backends:</strong> macOS Seatbelt, Linux bwrap, and Windows AppContainer adapters.
                </div>
              </li>
            </ul>
          </div>

          <div className="mt-6 border-t border-white/5 pt-3 font-mono text-[11px] text-sky-400/80">
            Source in packages/*
          </div>
        </div>

        {/* 2. Tested in CI */}
        <div className="flex flex-col justify-between rounded-2xl border border-emerald-500/20 bg-emerald-500/[0.02] p-6">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-wider text-emerald-400">
              <TestTube size={16} />
              <span>2. What Is Tested in CI</span>
            </div>
            <h3 className="mt-2 text-lg font-black text-white">Automated Verifications</h3>

            <ul className="mt-5 space-y-3.5 text-xs text-white/70">
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" />
                <div>
                  <strong className="text-white">Replay Rejection (INV-09):</strong> Calling execute() with an already consumed ticket returns ok: false.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" />
                <div>
                  <strong className="text-white">Default Deny (INV-03):</strong> Evaluator returns deny when zero matching rules exist.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" />
                <div>
                  <strong className="text-white">Real OS Seatbelt (macOS):</strong> Live kernel driver blocks unauthorized file writes on macos-15.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" />
                <div>
                  <strong className="text-white">Approval Replay (INV-12):</strong> Cryptographic challenge signature for A is rejected when sent to B.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" />
                <div>
                  <strong className="text-white">Env Sanitization (INV-08):</strong> Secrets and token variables are stripped prior to child launch.
                </div>
              </li>
            </ul>
          </div>

          <div className="mt-6 border-t border-emerald-500/10 pt-3">
            <Link
              href="/docs/evidence"
              className="inline-flex items-center gap-1 font-mono text-[11px] font-bold text-emerald-400 hover:text-emerald-300"
            >
              <span>View CI Evidence for {COMMIT_SHA} &rarr;</span>
            </Link>
          </div>
        </div>

        {/* 3. Not Established */}
        <div className="flex flex-col justify-between rounded-2xl border border-amber-500/20 bg-amber-500/[0.02] p-6">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-wider text-amber-400">
              <AlertTriangle size={16} />
              <span>3. Not Established</span>
            </div>
            <h3 className="mt-2 text-lg font-black text-white">Explicit Non-Claims</h3>

            <ul className="mt-5 space-y-3.5 text-xs text-white/70">
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                <div>
                  <strong className="text-white">No Independent Audit:</strong> RTQ has not undergone a formal third-party security audit.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                <div>
                  <strong className="text-white">No Formal Proof:</strong> Automated CI test passes are empirical checks, not mathematical proofs.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                <div>
                  <strong className="text-white">Compromised Host Kernel:</strong> Root-level kernel exploits bypass userland sandboxes.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                <div>
                  <strong className="text-white">Rubber-Stamping Approvers:</strong> Cryptographic challenge signing cannot force human diligence.
                </div>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                <div>
                  <strong className="text-white">Side-Channel Attacks:</strong> No hardware-level mitigation against CPU cache timing leaks.
                </div>
              </li>
            </ul>
          </div>

          <div className="mt-6 border-t border-amber-500/10 pt-3">
            <Link
              href="/docs/threat-model"
              className="inline-flex items-center gap-1 font-mono text-[11px] font-bold text-amber-400 hover:text-amber-300"
            >
              <span>Read Full Threat Model &rarr;</span>
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
