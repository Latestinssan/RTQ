"use client";

import { useState } from "react";
import { Server, Terminal, ShieldAlert, Check, ExternalLink } from "lucide-react";
import {
  COMMIT_SHA,
  EvidenceBadge,
  type EvidenceLevel,
  getGithubSourceUrl,
  getWorkflowUrl,
} from "@/components/evidence/EvidenceBadge";

interface PlatformInfo {
  id: "macos" | "linux" | "windows";
  name: string;
  delegatedMechanism: string;
  ciRunner: string;
  evidenceLevel: EvidenceLevel;
  testFile: string;
  testLines: [number, number];
  isolationMechanisms: string[];
  commandPreview: string;
  failClosedGuarantee: string;
  limitation: string;
}

const PLATFORMS: Record<string, PlatformInfo> = {
  macos: {
    id: "macos",
    name: "macOS (Apple Seatbelt)",
    delegatedMechanism: "Apple Seatbelt (sandbox-exec driver)",
    ciRunner: "macos-15 (GitHub Actions runner)",
    evidenceLevel: "LEVEL 3 — REAL OS ENFORCEMENT",
    testFile: "tests/sandbox/darwin.test.ts",
    testLines: [63, 117],
    isolationMechanisms: [
      "Dynamic Scheme-based profile generation",
      "Explicit subpath allowlists for filesystems",
      "Network egress blocking when network: 'none'",
      "Child process spawning restricted to allowlisted paths",
    ],
    commandPreview: `sandbox-exec -f /tmp/rtq-profile.sb /bin/sh -c "run_capability"`,
    failClosedGuarantee:
      "When /usr/bin/sandbox-exec is absent or profile generation fails, execution aborts with E_SANDBOX_INIT_FAILED.",
    limitation:
      "Apple has marked Seatbelt deprecated in modern macOS. This test does not prove resistance against local kernel exploits.",
  },
  linux: {
    id: "linux",
    name: "Linux (bubblewrap)",
    delegatedMechanism: "bubblewrap (bwrap) unshare namespaces",
    ciRunner: "ubuntu-latest (GitHub Actions runner with bwrap)",
    evidenceLevel: "LEVEL 1 — UNIT TESTED",
    testFile: "tests/sandbox/linux.test.ts",
    testLines: [38, 82],
    isolationMechanisms: [
      "Unshares PID, network, user, and mount namespaces (--unshare-all)",
      "Read-only bind mounts (--ro-bind) for system binaries",
      "Isolated in-memory /tmp and /dev mount points",
      "Environment scrubbing (--clearenv)",
    ],
    commandPreview: `bwrap --unshare-all --ro-bind /usr /usr --ro-bind /workspace /workspace --tmpfs /tmp --clearenv /bin/sh -c "run_capability"`,
    failClosedGuarantee:
      "If bwrap binary is not installed in PATH, checkBwrapCapability() returns false and execution halts.",
    limitation:
      "The current Linux test suite asserts argument construction and binary presence; it does not execute live adversarial rootkit binaries in CI.",
  },
  windows: {
    id: "windows",
    name: "Windows (AppContainer & Job Object)",
    delegatedMechanism: "Windows AppContainer Isolation Tokens",
    ciRunner: "windows-latest (GitHub Actions runner)",
    evidenceLevel: "LEVEL 1 — UNIT TESTED",
    testFile: "tests/sandbox/windows.test.ts",
    testLines: [6, 92],
    isolationMechanisms: [
      "Low integrity SID execution boundary",
      "Job object assignment with memory/process limits",
      "Blocked Win32 named pipes and registry modifications",
      "PowerShell runner script with fail-closed exit codes",
    ],
    commandPreview: `powershell -File packages/sandbox/scripts/windows-runner.ps1 -Profile "AppContainer" -Target "run_capability"`,
    failClosedGuarantee:
      "If AppContainer profile or job assignment fails, windows-runner.ps1 reports sandboxed = $false and exits with code 1.",
    limitation:
      "Test asserts PowerShell script invariants and output parsing; does not test native Win32 token isolation against kernel driver elevation in CI.",
  },
};

export function SandboxPlatformViewer() {
  const [activePlatform, setActivePlatform] = useState<"macos" | "linux" | "windows">("macos");

  const platform = PLATFORMS[activePlatform];
  const testUrl = getGithubSourceUrl(
    platform.testFile,
    platform.testLines[0],
    platform.testLines[1],
  );

  return (
    <section id="sandbox" className="relative mx-auto max-w-6xl px-6 py-20">
      <div className="mb-10 text-center">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
          <Server size={13} />
          <span>Delegated Platform Isolation</span>
        </div>
        <h2 className="text-3xl font-black tracking-tight text-white md:text-4xl">
          Platform Security Delegation
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-sm leading-relaxed text-white/50">
          RTQ delegates execution containment to operating system security facilities rather than
          relying only on userland JavaScript abstractions. Evidence is measured separately for each
          backend.
        </p>
      </div>

      {/* Platform Switcher */}
      <div className="flex justify-center mb-8">
        <div className="inline-flex rounded-xl border border-white/10 bg-[#070914] p-1.5">
          {(["macos", "linux", "windows"] as const).map((p) => (
            <button
              key={p}
              onClick={() => setActivePlatform(p)}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 font-mono text-xs transition ${
                activePlatform === p
                  ? "bg-sky-500 text-white font-bold shadow-md"
                  : "text-white/40 hover:text-white"
              }`}
            >
              <span>{p === "macos" ? "macOS Seatbelt" : p === "linux" ? "Linux bubblewrap" : "Windows AppContainer"}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Platform Details Card */}
      <div className="overflow-hidden rounded-2xl border border-white/10 bg-[#070914] shadow-2xl">
        <div className="grid grid-cols-1 lg:grid-cols-12">
          {/* Left: Primitives & Limits */}
          <div className="space-y-6 border-b border-white/10 p-6 lg:col-span-7 lg:border-b-0 lg:border-r lg:p-8">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 pb-4">
              <div>
                <h3 className="text-2xl font-black text-white">{platform.name}</h3>
                <p className="mt-1 font-mono text-xs text-white/50">
                  Mechanism: <span className="text-sky-300">{platform.delegatedMechanism}</span>
                </p>
              </div>
              <EvidenceBadge level={platform.evidenceLevel} />
            </div>

            <div>
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-white/40">
                Isolation Primitives Delegated
              </span>
              <ul className="mt-3 space-y-2.5">
                {platform.isolationMechanisms.map((mech, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-xs text-white/70">
                    <Check size={14} className="mt-0.5 shrink-0 text-emerald-400" />
                    <span>{mech}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 space-y-1.5">
              <div className="flex items-center gap-2 font-mono text-xs font-bold text-amber-400">
                <ShieldAlert size={14} />
                <span>What This Test Does NOT Prove:</span>
              </div>
              <p className="text-xs text-amber-300/80 leading-relaxed">{platform.limitation}</p>
            </div>
          </div>

          {/* Right: Test Execution & Command */}
          <div className="flex flex-col justify-between bg-[#04060d] p-6 lg:col-span-5 lg:p-8 space-y-6">
            <div>
              <div className="mb-4 flex items-center justify-between border-b border-white/5 pb-3">
                <div className="flex items-center gap-2">
                  <Terminal size={14} className="text-sky-400" />
                  <span className="font-mono text-xs text-white/60">Execution Command</span>
                </div>
                <span className="font-mono text-[10px] text-white/40">Runner: {platform.ciRunner.split(" ")[0]}</span>
              </div>

              <pre className="overflow-x-auto rounded-lg border border-white/5 bg-black/40 p-3 font-mono text-xs leading-relaxed text-sky-200">
                <code>{platform.commandPreview}</code>
              </pre>

              <div className="mt-6 space-y-2.5 font-mono text-xs text-white/60">
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <span className="text-white/40">CI Runner:</span>
                  <span className="text-white font-semibold">{platform.ciRunner}</span>
                </div>
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <span className="text-white/40">Verified Commit:</span>
                  <span className="text-sky-400 font-bold">{COMMIT_SHA}</span>
                </div>
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <span className="text-white/40">Fail-Closed On Missing:</span>
                  <span className="text-emerald-400 font-bold">YES</span>
                </div>
              </div>
            </div>

            <div className="border-t border-white/5 pt-4 flex items-center justify-between text-xs font-mono">
              <a
                href={testUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sky-400 hover:underline"
              >
                <span>View {platform.testFile.split("/").pop()}</span>
                <ExternalLink size={12} />
              </a>
              <a
                href={getWorkflowUrl("sandbox.yml")}
                target="_blank"
                rel="noopener noreferrer"
                className="text-white/40 hover:text-white hover:underline"
              >
                sandbox.yml
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
