import Link from "next/link";
import { Server, ExternalLink, ShieldAlert, CheckCircle2, ArrowRight } from "lucide-react";
import {
  COMMIT_SHA,
  REPO_BASE,
  EvidenceBadge,
  getGithubSourceUrl,
  getWorkflowUrl,
} from "@/components/evidence/EvidenceBadge";

export const metadata = {
  title: "Platform Sandboxing Support & Evidence",
  description: "Operating system isolation mechanisms, CI runner evidence, and platform-specific limitations.",
};

export default function PlatformSupportPage() {
  const platforms = [
    {
      platform: "macOS",
      mechanism: "Apple Seatbelt (sandbox-exec driver)",
      level: "LEVEL 3 — REAL OS ENFORCEMENT" as const,
      runner: "macos-15",
      details:
        "Compiles Scheme profiles (.sb) dynamically. The kernel driver enforces filesystem subpath allowlists, blocks network sockets, and restricts process execution.",
      ciStatus: "Real OS enforcement tested in CI",
      testFile: "tests/sandbox/darwin.test.ts",
      testLines: [63, 117] as [number, number],
      source: "packages/sandbox/src/index.ts",
      sourceLines: [220, 280] as [number, number],
      limitation:
        "Seatbelt is marked deprecated by Apple in modern macOS versions. Live tests demonstrate file-write and network egress denial, but do not guarantee resistance against kernel-level exploits.",
    },
    {
      platform: "Linux",
      mechanism: "bubblewrap (bwrap) namespaces",
      level: "LEVEL 1 — UNIT TESTED" as const,
      runner: "ubuntu-latest",
      details:
        "Generates argument vectors for bwrap to isolate PID, mount, IPC, UTS, and network namespaces. Binds host root as read-only and allocates private tmpfs.",
      ciStatus: "Argument construction & probe tested in CI",
      testFile: "tests/sandbox/linux.test.ts",
      testLines: [38, 82] as [number, number],
      source: "packages/sandbox/src/index.ts",
      sourceLines: [130, 215] as [number, number],
      limitation:
        "Requires the bubblewrap binary installed on the host system. The current Linux test suite asserts argument construction and probe detection; it does not execute live adversarial rootkit binaries in CI.",
    },
    {
      platform: "Windows",
      mechanism: "AppContainer & Windows Job Object",
      level: "LEVEL 1 — UNIT TESTED" as const,
      runner: "windows-latest",
      details:
        "Executes via PowerShell runner script configuring low-privilege AppContainer SIDs and Job Objects to restrict process capabilities and memory.",
      ciStatus: "Script contract & output parsing tested in CI",
      testFile: "tests/sandbox/windows.test.ts",
      testLines: [6, 92] as [number, number],
      source: "packages/sandbox/scripts/windows-runner.ps1",
      sourceLines: [1, 95] as [number, number],
      limitation:
        "Requires Windows 10/11 or Windows Server with PowerShell. Test suite verifies runner script fail-closed behavior and output parsing; does not test native Win32 token isolation against kernel driver bugs.",
    },
  ];

  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Architecture &bull; Platform Isolation
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          Platform Sandboxing Support
        </h1>
        <p className="mt-4 text-base text-white/60 leading-relaxed">
          RTQ delegates execution containment to platform security mechanisms rather than relying on
          soft in-process JavaScript checks. Below is the exact evidence, test runner, and known
          limitations for each supported operating system.
        </p>
      </div>

      {/* Platform Cards */}
      <div className="space-y-6">
        {platforms.map((p) => {
          const testUrl = getGithubSourceUrl(p.testFile, p.testLines[0], p.testLines[1]);
          const sourceUrl = getGithubSourceUrl(p.source, p.sourceLines[0], p.sourceLines[1]);

          return (
            <div
              key={p.platform}
              className="rounded-2xl border border-white/10 bg-[#070914] p-6 space-y-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 pb-3">
                <div>
                  <h2 className="text-xl font-bold text-white">{p.platform}</h2>
                  <p className="font-mono text-xs text-sky-400">{p.mechanism}</p>
                </div>
                <EvidenceBadge level={p.level} />
              </div>

              <p className="text-xs text-white/60 leading-relaxed">{p.details}</p>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 border-t border-b border-white/5 py-3 font-mono text-xs">
                <div>
                  <span className="block text-[10px] uppercase text-white/40">CI Runner</span>
                  <span className="text-white font-semibold">{p.runner}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase text-white/40">Implementation</span>
                  <a
                    href={sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-400 hover:underline inline-flex items-center gap-1"
                  >
                    <span>{p.source.split("/").pop()}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
                <div>
                  <span className="block text-[10px] uppercase text-white/40">Test File</span>
                  <a
                    href={testUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-300 hover:underline inline-flex items-center gap-1"
                  >
                    <span>{p.testFile.split("/").pop()}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>

              <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.02] p-3.5 space-y-1">
                <span className="font-mono font-bold text-[10px] uppercase text-amber-400 block">
                  Platform Limitations (What This Test Does NOT Prove):
                </span>
                <p className="text-xs text-amber-200/80 leading-relaxed">{p.limitation}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Fail-Closed Behavior */}
      <section className="space-y-4 rounded-2xl border border-white/10 bg-white/[0.02] p-6">
        <h3 className="text-lg font-bold text-white">Fail-Closed Sandbox Invariants</h3>
        <p className="text-xs text-white/60 leading-relaxed">
          The sandbox execution path rejects execution when the required sandbox backend cannot be
          initialized. RTQ does not silently fall back to unsandboxed execution:
        </p>
        <ul className="space-y-2 text-xs text-white/70">
          <li className="flex items-start gap-2">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong>macOS:</strong> If <code className="text-white font-mono">/usr/bin/sandbox-exec</code> is
              missing or returns a configuration error, execution fails with <code className="text-white font-mono">E_SANDBOX_INIT_FAILED</code>.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong>Linux:</strong> If <code className="text-white font-mono">bwrap</code> is absent from PATH,
              execution is blocked before spawning child processes.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong>Windows:</strong> If AppContainer profile creation or job assignment fails, the runner
              script exits with code 1 and reports <code className="text-white font-mono">sandboxed: false</code>.
            </span>
          </li>
        </ul>
      </section>

      <div className="flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition"
        >
          View Sandbox Evidence Chains &rarr;
        </Link>
        <Link
          href="/docs/threat-model"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          Threat Model &amp; Kernel Boundaries &rarr;
        </Link>
      </div>
    </div>
  );
}
