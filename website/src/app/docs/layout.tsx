"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, ChevronRight, Menu, X, Github, BookOpen,
  Lock, Zap, Eye, Smartphone, Code2, FileText, Search,
  AlertTriangle, CheckCircle2, Layers, Server, ArrowRight, TestTube,
} from "lucide-react";
import { SearchModal } from "@/components/docs/SearchModal";
import { APP_INFO } from "@/lib/version";
import Image from "next/image";

interface NavItem {
  id: string;
  title: string;
  href: string;
  icon: React.ElementType;
}

const navigation: NavItem[] = [
  { id: "overview", title: "Overview", href: "/docs/overview", icon: BookOpen },
  { id: "evidence", title: "Evidence & Verification", href: "/docs/evidence", icon: TestTube },
  { id: "security-overview", title: "Security Overview", href: "/docs/security-overview", icon: Shield },
  { id: "threat-model", title: "Threat Model", href: "/docs/threat-model", icon: AlertTriangle },
  { id: "verification-matrix", title: "Verification Matrix", href: "/docs/verification-matrix", icon: CheckCircle2 },
  { id: "verification-traceability", title: "Traceability", href: "/docs/verification-traceability", icon: Layers },
  { id: "platform-support", title: "Platform Support", href: "/docs/platform-support", icon: Server },
  { id: "aartiq-integration", title: "Aartiq Integration", href: "/docs/aartiq-integration", icon: Code2 },
  { id: "mobile-approval", title: "Mobile Approval", href: "/docs/mobile-approval", icon: Smartphone },
  { id: "cli", title: "CLI Reference", href: "/docs/cli", icon: Zap },
  { id: "testing-strategy", title: "Testing Strategy", href: "/docs/testing-strategy", icon: Eye },
  { id: "provenance", title: "Provenance", href: "/docs/provenance", icon: FileText },
];

const sectionGroups = [
  { title: "Evidence & Overview", items: navigation.filter(n => ["overview", "evidence", "security-overview", "provenance"].includes(n.id)) },
  { title: "Security & Verification", items: navigation.filter(n => ["threat-model", "verification-matrix", "verification-traceability", "platform-support"].includes(n.id)) },
  { title: "Integration", items: navigation.filter(n => ["aartiq-integration", "mobile-approval", "cli"].includes(n.id)) },
  { title: "Reference", items: navigation.filter(n => ["testing-strategy"].includes(n.id)) },
];

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setSearchOpen(true); }
  }, []);

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  return (
    <div className="min-h-screen bg-[#03040b] text-white font-inter">
      <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            itemListElement: [
              { "@type": "ListItem", position: 1, name: "RTQ", item: APP_INFO.siteUrl },
              { "@type": "ListItem", position: 2, name: "Docs", item: `${APP_INFO.siteUrl}/docs` },
            ],
          }),
        }}
      />

      {/* Top Nav */}
      <header className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-white/[0.08] bg-[#03050c]/90 backdrop-blur-xl">
        <div className="flex h-full items-center justify-between px-6">
          <div className="flex items-center gap-6">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-white/40 transition hover:bg-white/10 hover:text-white lg:hidden"
            >
              {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <Link href="/" className="flex items-center gap-3 group">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10 p-1 transition group-hover:bg-sky-500/20">
                <img src="/icon.png" alt="RTQ Logo" className="h-5 w-5 object-contain" />
              </div>
              <span className="font-mono text-sm font-black tracking-widest text-white">RTQ</span>
            </Link>
            <span className="hidden text-[10px] font-mono uppercase tracking-[0.3em] text-sky-400/80 sm:block">
              / Documentation
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSearchOpen(true)}
              className="group hidden h-9 w-64 items-center gap-3 rounded-xl border border-white/10 bg-white/5 px-4 text-xs text-white/30 transition hover:border-sky-500/50 hover:bg-white/10 hover:text-white/60 md:flex"
            >
              <Search size={15} className="transition group-hover:text-sky-400" />
              <span className="flex-1 text-left font-mono">Search docs...</span>
              <kbd className="flex items-center gap-0.5 rounded border border-white/10 bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-white/40">⌘K</kbd>
            </button>
            <a
              href={APP_INFO.repo}
              target="_blank"
              className="hidden items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3.5 py-2 font-mono text-xs font-semibold text-white/70 transition hover:bg-white/10 hover:text-white sm:flex"
            >
              <Github size={15} /> GitHub
            </a>
          </div>
        </div>
      </header>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden" onClick={() => setSidebarOpen(false)} />
            <motion.aside initial={{ x: -300 }} animate={{ x: 0 }} exit={{ x: -300 }}
              className="fixed left-0 top-16 bottom-0 z-50 w-80 overflow-y-auto border-r border-white/10 bg-[#04060e] p-6 lg:hidden">
              <SidebarContent pathname={pathname} sectionGroups={sectionGroups} />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Desktop Layout */}
      <div className="flex pt-16">
        <aside className="hidden lg:block lg:w-72 lg:shrink-0 lg:fixed lg:top-16 lg:bottom-0 lg:overflow-y-auto lg:border-r lg:border-white/[0.08] lg:bg-[#03050c]">
          <div className="sticky top-0 p-6">
            <div className="mb-6 flex items-center justify-between rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3.5">
              <div className="flex items-center gap-2.5">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
                </span>
                <span className="font-mono text-[11px] font-bold text-emerald-400">12 Invariants CI</span>
              </div>
              <span className="font-mono text-[10px] font-semibold text-white/40">v{APP_INFO.version}</span>
            </div>
            <SidebarContent pathname={pathname} sectionGroups={sectionGroups} />
          </div>
        </aside>

        <main className="flex-1 lg:ml-72">
          <div className="relative mx-auto max-w-4xl px-6 py-12 lg:px-12 lg:py-16">
            {/* Subtle ambient light */}
            <div className="pointer-events-none absolute -top-10 right-0 h-64 w-64 rounded-full bg-sky-500/5 blur-3xl" />
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

function SidebarContent({ pathname, sectionGroups }: { pathname: string; sectionGroups: { title: string; items: NavItem[] }[] }) {
  return (
    <nav className="space-y-8">
      {sectionGroups.map((group) => (
        <div key={group.title}>
          <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-white/20">{group.title}</p>
          <ul className="space-y-1">
            {group.items.map((item) => {
              const isActive = pathname === item.href;
              return (
                <li key={item.id}>
                  <Link href={item.href}
                    className={`flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium transition ${
                      isActive ? "bg-sky-500/10 text-sky-400 border border-sky-500/20" : "text-white/40 hover:bg-white/5 hover:text-white border border-transparent"
                    }`}>
                    <item.icon size={16} className={isActive ? "text-sky-400" : ""} />
                    {item.title}
                    {isActive && <ChevronRight size={14} className="ml-auto" />}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
      <div className="border-t border-white/5 pt-6">
        <ul className="space-y-2">
          <li>
            <a href={APP_INFO.repo} target="_blank"
              className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium text-white/40 hover:bg-white/5 hover:text-white transition">
              <Github size={16} /> GitHub
            </a>
          </li>
          <li>
            <Link href="/"
              className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium text-white/40 hover:bg-white/5 hover:text-white transition">
              <ArrowRight size={16} /> Back to Home
            </Link>
          </li>
        </ul>
      </div>
    </nav>
  );
}
