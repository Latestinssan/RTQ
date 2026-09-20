"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, ChevronRight, Menu, X, Github, BookOpen,
  Lock, Zap, Eye, Smartphone, Code2, FileText, Search,
  AlertTriangle, CheckCircle2, Layers, Server, ArrowRight,
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
  { title: "Overview", items: navigation.filter(n => ["overview", "security-overview", "provenance"].includes(n.id)) },
  { title: "Security", items: navigation.filter(n => ["threat-model", "verification-matrix", "verification-traceability", "platform-support"].includes(n.id)) },
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
      <header className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-white/5 bg-[#03040b]/95 backdrop-blur-xl">
        <div className="flex h-full items-center justify-between px-6">
          <div className="flex items-center gap-6">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-white/40 transition hover:bg-white/10 hover:text-white lg:hidden"
            >
              {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <Link href="/" className="flex items-center gap-3">
              <div className="relative h-8 w-8 overflow-hidden rounded-lg">
                <Image src="/icon.png" alt="RTQ" fill className="object-cover" />
              </div>
              <span className="text-sm font-black uppercase tracking-widest">RTQ</span>
            </Link>
            <span className="hidden text-[10px] font-black uppercase tracking-[0.4em] text-sky-400/60 sm:block">
              Documentation
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSearchOpen(true)}
              className="group hidden h-9 w-64 items-center gap-3 rounded-xl border border-white/10 bg-white/5 px-4 text-xs text-white/30 transition hover:border-sky-500/50 hover:bg-white/10 hover:text-white/60 md:flex"
            >
              <Search size={16} className="transition group-hover:text-sky-400" />
              <span className="flex-1 text-left">Search docs...</span>
              <kbd className="flex items-center gap-0.5 rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-white/30">⌘K</kbd>
            </button>
            <a
              href={APP_INFO.repo}
              target="_blank"
              className="hidden items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-black uppercase tracking-wider text-white/60 transition hover:bg-white/10 hover:text-white sm:flex"
            >
              <Github size={16} /> GitHub
            </a>
          </div>
        </div>
      </header>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden" onClick={() => setSidebarOpen(false)} />
            <motion.aside initial={{ x: -300 }} animate={{ x: 0 }} exit={{ x: -300 }}
              className="fixed left-0 top-16 bottom-0 z-50 w-80 overflow-y-auto border-r border-white/5 bg-[#03040b] p-6 lg:hidden">
              <SidebarContent pathname={pathname} sectionGroups={sectionGroups} />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Desktop Layout */}
      <div className="flex pt-16">
        <aside className="hidden lg:block lg:w-72 lg:shrink-0 lg:fixed lg:top-16 lg:bottom-0 lg:overflow-y-auto lg:border-r lg:border-white/5 lg:bg-[#03040b]">
          <div className="sticky top-0 p-6">
            <div className="mb-6 flex items-center gap-3 rounded-2xl border border-sky-500/20 bg-sky-500/5 p-4">
              <div className="relative h-5 w-5 overflow-hidden">
                <Image src="/icon.png" alt="RTQ" fill className="object-cover" />
              </div>
              <div>
                <p className="text-[10px] font-black uppercase tracking-[0.3em] text-sky-400/60">Version</p>
                <p className="text-sm font-black text-white">v{APP_INFO.version}</p>
              </div>
            </div>
            <SidebarContent pathname={pathname} sectionGroups={sectionGroups} />
          </div>
        </aside>

        <main className="flex-1 lg:ml-72">
          <div className="mx-auto max-w-4xl px-6 py-12 lg:px-12 lg:py-20">
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
