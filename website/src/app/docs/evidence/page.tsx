import Link from "next/link";
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Cpu,
  TestTube,
  FileCode,
  Layers,
  ArrowRight,
  Info,
} from "lucide-react";
import {
  EvidenceBlock,
  EvidenceBadge,
  COMMIT_SHA,
  REPO_BASE,
  getGithubSourceUrl,
  getWorkflowUrl,
} from "@/components/evidence/EvidenceBadge";

export const metadata = {
  title: "Security Evidence & Verification",
  description:
    "Evidence chains mapping RTQ security claims to implementation source lines, automated tests, and GitHub Actions CI runs.",
};

const PROPERTIES = [
  {
    id: "INV-01",
    claim: "Explicit surface: An unregistered capability is denied (no implicit surface).",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/security/src/index.ts",
    implementationLines: [295, 301] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [54, 62] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Calling rtq.authorize() with an unregistered capability name returns decision: 'denied' with code 'capability.not_registered'.",
    notProven:
      "Does not prove that registered capability handlers themselves are free of internal logic errors or memory corruption.",
  },
  {
    id: "INV-02",
    claim: "Explicit surface: A registered capability requested with the wrong version is denied.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/security/src/index.ts",
    implementationLines: [302, 307] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [64, 72] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Version numbers must match registered definitions exactly (integer equality check).",
    notProven:
      "Does not verify schema migration safety or semantic version range compatibility across deployments.",
  },
  {
    id: "INV-03",
    claim: "Default-deny policy: No matching policy rule results in a denial, never an allow.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/policy/src/index.ts",
    implementationLines: [365, 382] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [74, 82] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "When the policy engine evaluates an operation against an empty or non-matching rule set, it yields decision: 'deny'.",
    notProven:
      "Does not prevent human operators from inadvertently authoring overly permissive allow rules.",
  },
  {
    id: "INV-04",
    claim: "Authoritative risk: Caller claims to lower risk are ignored; declared risk takes precedence.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/security/src/index.ts",
    implementationLines: [337, 347] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [84, 112] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "A caller passing metadata.claimedRisk = 'low' for a high-risk capability still triggers approval_required with risk = 'high'.",
    notProven:
      "Does not prove the declared risk rating matches real-world exploitability or side effects of arbitrary commands.",
  },
  {
    id: "INV-05",
    claim: "Origin is a hint: Unknown origin is never treated as local and escalates approval requirements.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/security/src/index.ts",
    implementationLines: [320, 325] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [114, 131] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "An untrusted origin 'unknown' is not granted automatic approval for low-risk capabilities.",
    notProven:
      "Relies on host integration accurately passing caller origin identifiers without spoofing outside RTQ.",
  },
  {
    id: "INV-06",
    claim: "Approval strategy defaults: High or critical risk is never automatic.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/security/src/index.ts",
    implementationLines: [437, 449] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [133, 189] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Default approval strategy resolution for high or critical risk capabilities rejects automatic execution.",
    notProven:
      "Operators can explicitly override defaults with custom policy rules if configured to do so.",
  },
  {
    id: "INV-07",
    claim: "Sandbox network deny-by-default: Generates --unshare-net and rejects unsupported allowlists.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/sandbox/src/index.ts",
    implementationLines: [140, 195] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [191, 217] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Verifies bubblewrap command line construction unshares the network namespace and throws if network allowlist cannot be enforced.",
    notProven:
      "This unit check does not execute live network sockets in kernel space (real network blocking is tested in macOS darwin.test.ts).",
  },
  {
    id: "INV-08",
    claim: "Sandboxed processes do not inherit ambient secrets matching sensitive key patterns.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/sandbox/src/index.ts",
    implementationLines: [85, 125] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [219, 243] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "buildSandboxEnvironment() strips environment keys matching 'secret', 'token', and 'API_TOKEN' from child processes.",
    notProven:
      "Does not prevent child processes from reading secrets stored on accessible disk paths or over authorized sockets.",
  },
  {
    id: "INV-09",
    claim: "Single-use tickets: The second redemption of an authorization ticket is denied (replay rejection).",
    level: "LEVEL 2 — INTEGRATION TESTED" as const,
    implementationFile: "packages/core/src/ticket-store.ts",
    implementationLines: [194, 206] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [245, 263] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "rtq.execute(ticketId) marks ticket redeemed; subsequent execution attempt with identical ticketId returns ok: false.",
    notProven:
      "Relies on in-memory ticket store state within a single Node.js process; does not establish distributed cluster synchronization.",
  },
  {
    id: "INV-10",
    claim: "Tickets are replay- and tamper-resistant via HMAC-SHA256 signatures.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/core/src/ticket-store.ts",
    implementationLines: [159, 164] as [number, number],
    testFile: "tests/unit/ticket-store.test.ts",
    testLines: [70, 86] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Modifying any ticket body attribute causes signature verification to fail prior to redemption.",
    notProven:
      "Assumes the HMAC signing key is kept strictly confidential in host memory and never leaked.",
  },
  {
    id: "INV-11",
    claim: "Replacing a capability invalidates its previously issued, outstanding tickets.",
    level: "LEVEL 2 — INTEGRATION TESTED" as const,
    implementationFile: "packages/core/src/ticket-store.ts",
    implementationLines: [232, 240] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [291, 323] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Bumping capability version causes redemption of tickets issued for the previous version to fail.",
    notProven:
      "Tickets for other unchanged capabilities remain redeemable until their standard expiration timestamp.",
  },
  {
    id: "INV-12",
    claim: "Approval substitution is rejected: An approval signed for challenge A cannot authorize challenge B.",
    level: "LEVEL 2 — INTEGRATION TESTED" as const,
    implementationFile: "packages/security/src/index.ts",
    implementationLines: [470, 520] as [number, number],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [325, 380] as [number, number],
    workflow: "security.yml",
    runner: "ubuntu-latest",
    scope:
      "Device approval signature bound to challengeId A is rejected when submitted against challengeId B.",
    notProven:
      "Does not protect against an attacker with physical access to an unlocked approval device or compromised private keys.",
  },
];

const PLATFORM_TESTS = [
  {
    id: "OS-DARWIN",
    platform: "macOS (Apple Seatbelt)",
    claim: "Kernel-level Seatbelt sandbox blocks unauthorized filesystem writes and network egress.",
    level: "LEVEL 3 — REAL OS ENFORCEMENT" as const,
    implementationFile: "packages/sandbox/src/index.ts",
    implementationLines: [220, 280] as [number, number],
    testFile: "tests/sandbox/darwin.test.ts",
    testLines: [63, 117] as [number, number],
    workflow: "sandbox.yml",
    runner: "macos-15",
    scope:
      "Executes /usr/bin/sandbox-exec live on macOS runner; verifies /usr/bin/touch fails to write outside allowed directory and /usr/bin/curl fails egress when network=none.",
    notProven:
      "macOS Seatbelt is deprecated by Apple in modern macOS; this test does not prove resistance against local kernel privilege escalation.",
  },
  {
    id: "OS-LINUX",
    platform: "Linux (bubblewrap)",
    claim: "Generates correct bubblewrap argument vector with namespace unsharing and ro/rw binds.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/sandbox/src/index.ts",
    implementationLines: [130, 215] as [number, number],
    testFile: "tests/sandbox/linux.test.ts",
    testLines: [38, 82] as [number, number],
    workflow: "sandbox.yml",
    runner: "ubuntu-latest",
    scope:
      "Verifies argv construction includes --unshare-pid, --unshare-net, --unshare-user, --ro-bind for system dirs, and --bind for writable workspaces.",
    notProven:
      "This test file verifies argument assembly and binary probing; it does not spawn a long-running adversarial rootkit payload in this test suite.",
  },
  {
    id: "OS-WINDOWS",
    platform: "Windows (AppContainer)",
    claim: "Windows runner script exits 1 on failure and output parser reports sandboxed: false if markers missing.",
    level: "LEVEL 1 — UNIT TESTED" as const,
    implementationFile: "packages/sandbox/scripts/windows-runner.ps1",
    implementationLines: [1, 95] as [number, number],
    testFile: "tests/sandbox/windows.test.ts",
    testLines: [6, 92] as [number, number],
    workflow: "sandbox.yml",
    runner: "windows-latest",
    scope:
      "Verifies windows-runner.ps1 contains no bypass flags and that parseWindowsRunnerOutput correctly interprets AppContainer job markers.",
    notProven:
      "Does not prove AppContainer integrity tokens prevent Win32 GDI or font driver elevation bugs on Windows.",
  },
];

export default function EvidencePage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div>
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
          <Shield size={13} />
          <span>Independently Verifiable</span>
        </div>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          Security Evidence &amp; Verification
        </h1>
        <p className="mt-4 text-base leading-relaxed text-white/60">
          RTQ is experimental security infrastructure (Alpha). We replace marketing assertions with
          an unbroken evidence chain:{" "}
          <strong className="text-white">
            Claim &rarr; Implementation &rarr; Test &rarr; CI Run &rarr; Platform/Commit
          </strong>
          .
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-4 font-mono text-xs text-white/40">
          <span>Pinned Commit: <code className="text-sky-400 font-bold">{COMMIT_SHA}</code></span>
          <span>&middot;</span>
          <a
            href={`${REPO_BASE}/tree/${COMMIT_SHA}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sky-400 underline hover:text-sky-300"
          >
            Browse Tree at {COMMIT_SHA}
          </a>
        </div>
      </div>

      {/* Prominent Disclaimer Banner */}
      <div className="rounded-2xl border border-amber-500/30 bg-amber-500/[0.05] p-5 md:p-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 shrink-0 text-amber-400 mt-0.5" />
          <div className="space-y-2 text-xs leading-relaxed text-amber-200/90">
            <h3 className="font-mono font-bold uppercase tracking-wider text-amber-300">
              CI Verification Disclaimer &amp; Status
            </h3>
            <p>
              Green CI indicates that the repository&apos;s automated checks passed for a particular
              commit and environment. It does not constitute an independent security audit, formal
              mathematical verification, or guarantee that the implementation is free of vulnerabilities.
            </p>
            <p className="font-mono text-[11px] text-amber-300/70">
              Rule of Claim Strength: The strength of a security claim must never exceed the strength
              of its evidence.
            </p>
          </div>
        </div>
      </div>

      {/* Verification Methodology & Evidence Levels */}
      <section className="space-y-6">
        <h2 className="text-2xl font-black text-white">Verification Methodology</h2>
        <p className="text-sm text-white/60 leading-relaxed">
          Every claim in RTQ documentation is tagged with an Evidence Level indicating the rigor of
          the verification behind it. We never describe a unit test as an OS enforcement proof.
        </p>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            {
              level: "LEVEL 0 — DOCUMENTED DESIGN" as const,
              desc: "Behavior is documented in architecture specifications but is not yet asserted by an automated test.",
            },
            {
              level: "LEVEL 1 — UNIT TESTED" as const,
              desc: "Isolated in-process logic is asserted by automated unit tests. Does not establish OS kernel containment.",
            },
            {
              level: "LEVEL 2 — INTEGRATION TESTED" as const,
              desc: "Multiple RTQ pipeline components (registry, policy, ticket store) are exercised together.",
            },
            {
              level: "LEVEL 3 — REAL OS ENFORCEMENT" as const,
              desc: "Test launches the platform’s actual sandbox mechanism and verifies the OS rejects the tested unauthorized operation.",
            },
            {
              level: "LEVEL 4 — ADVERSARIAL TESTED" as const,
              desc: "Explicit red-team or bypass payloads (symlink traversal, path tampering, replay) attempt to violate boundary.",
            },
            {
              level: "LEVEL 5 — INDEPENDENTLY AUDITED" as const,
              desc: "Publicly verifiable audit report by a reputable third-party security firm. (RTQ has NOT yet been audited at Level 5).",
            },
          ].map((item) => (
            <div
              key={item.level}
              className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 space-y-2"
            >
              <EvidenceBadge level={item.level} />
              <p className="text-xs text-white/50 leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 12 Automated Security Properties */}
      <section className="space-y-6">
        <div>
          <h2 className="text-2xl font-black text-white">
            12 Security Properties Tested in CI
          </h2>
          <p className="mt-2 text-sm text-white/50">
            These 12 standalone checks execute in <code className="text-sky-300 font-mono">tests/invariants/invariants.test.ts</code> on
            every push and scheduled CI run. Below is the complete evidence mapping for each property.
          </p>
        </div>

        <div className="space-y-4">
          {PROPERTIES.map((prop) => (
            <EvidenceBlock key={prop.id} {...prop} />
          ))}
        </div>
      </section>

      {/* Platform Sandbox Tests */}
      <section className="space-y-6">
        <div>
          <h2 className="text-2xl font-black text-white">
            Operating System Sandbox Evidence
          </h2>
          <p className="mt-2 text-sm text-white/50">
            Platform isolation claims are tested on their respective GitHub Actions runner operating
            systems in <code className="text-sky-300 font-mono">.github/workflows/sandbox.yml</code>.
          </p>
        </div>

        <div className="space-y-4">
          {PLATFORM_TESTS.map((item) => (
            <EvidenceBlock
              key={item.id}
              id={item.id}
              claim={`${item.platform}: ${item.claim}`}
              level={item.level}
              implementationFile={item.implementationFile}
              implementationLines={item.implementationLines}
              testFile={item.testFile}
              testLines={item.testLines}
              workflow={item.workflow}
              runner={item.runner}
              scope={item.scope}
              notProven={item.notProven}
            />
          ))}
        </div>
      </section>

      {/* Honest Security Contract */}
      <section className="space-y-6 border-t border-white/10 pt-10">
        <h2 className="text-2xl font-black text-white">Honest Security Contract</h2>
        <p className="text-sm text-white/60 leading-relaxed">
          To maintain rigorous credibility, we separate what is built, what is tested, and what has
          explicitly not been established.
        </p>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-3 text-xs">
          {/* Implemented */}
          <div className="rounded-2xl border border-sky-500/20 bg-sky-500/[0.02] p-5 space-y-3">
            <span className="font-mono font-bold uppercase tracking-wider text-sky-400">
              1. What Is Implemented
            </span>
            <ul className="space-y-2 text-white/70">
              <li>&bull; Explicit capability registration with JSON Schema checks.</li>
              <li>&bull; Default-deny policy engine with declarative rules.</li>
              <li>&bull; Authoritative risk calculation ignoring caller claims.</li>
              <li>&bull; Single-use HMAC-SHA256 authorization ticket minting and consumption.</li>
              <li>&bull; macOS Seatbelt profile generator &amp; execution wrapper.</li>
              <li>&bull; Linux bubblewrap namespace argument generator.</li>
              <li>&bull; Windows PowerShell AppContainer runner script.</li>
              <li>&bull; Redacted audit log emitter with HMAC integrity.</li>
            </ul>
          </div>

          {/* Automatically Tested */}
          <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/[0.02] p-5 space-y-3">
            <span className="font-mono font-bold uppercase tracking-wider text-emerald-400">
              2. What Is Tested in CI
            </span>
            <ul className="space-y-2 text-white/70">
              <li>&bull; 12 automated invariants on ubuntu-latest in tests/invariants.</li>
              <li>&bull; Replay rejection of consumed tickets (INV-09).</li>
              <li>&bull; Override rejection of caller risk demotion (INV-04).</li>
              <li>&bull; Approval substitution rejection (INV-12).</li>
              <li>&bull; Real macOS Seatbelt file-write and network denial on macos-15 (OS-DARWIN).</li>
              <li>&bull; Bubblewrap argument construction with namespace unsharing (OS-LINUX).</li>
              <li>&bull; Windows runner fail-closed script contract (OS-WINDOWS).</li>
            </ul>
          </div>

          {/* Not Established */}
          <div className="rounded-2xl border border-amber-500/20 bg-amber-500/[0.02] p-5 space-y-3">
            <span className="font-mono font-bold uppercase tracking-wider text-amber-400">
              3. What Has Not Been Established
            </span>
            <ul className="space-y-2 text-white/60">
              <li>&bull; <strong>Independent Security Audit:</strong> Not yet audited by third-party firm.</li>
              <li>&bull; <strong>Formal Proofs:</strong> Automated tests are not mathematical proofs.</li>
              <li>&bull; <strong>Compromised Kernel:</strong> Kernel rootkits can bypass OS sandboxes.</li>
              <li>&bull; <strong>Side-Channel Resistance:</strong> No defense against microarchitectural timing leaks.</li>
              <li>&bull; <strong>Out-of-Runtime Code:</strong> Code executing outside RTQ is unconstrained.</li>
              <li>&bull; <strong>Blind Human Approval:</strong> Cannot force humans to read what they approve.</li>
            </ul>
          </div>
        </div>
      </section>

      {/* CI Workflows Summary */}
      <section className="space-y-4 rounded-2xl border border-white/10 bg-[#070914] p-6">
        <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white">
          Active GitHub Actions Workflows
        </h3>
        <p className="text-xs text-white/50">
          Workflows run on push to <code className="text-white">main</code> and on pull requests:
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs font-mono">
          <a
            href={getWorkflowUrl("security.yml")}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between rounded-lg border border-white/5 bg-white/[0.02] p-3 hover:border-sky-500/30 text-sky-400"
          >
            <span>security.yml (Invariants &amp; Pipeline)</span>
            <ExternalLink size={13} />
          </a>
          <a
            href={getWorkflowUrl("sandbox.yml")}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between rounded-lg border border-white/5 bg-white/[0.02] p-3 hover:border-sky-500/30 text-sky-400"
          >
            <span>sandbox.yml (Real OS Matrix)</span>
            <ExternalLink size={13} />
          </a>
        </div>
      </section>
    </div>
  );
}
