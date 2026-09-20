"use client";

import type { ReactNode } from "react";
import { useState } from "react";

export function ManualLayout({
  children,
  pageMap,
}: {
  children: ReactNode;
  pageMap: any[];
}) {
  const [menuOpen, setMenuOpen] = useState(false);

  // Build nav items from pageMap
  const navItems = (pageMap || [])
    .filter((item: any) => item.name && item.name !== "_meta")
    .map((item: any) => ({
      name: item.name,
      title: item.title || item.name,
    }));

  return (
    <div className="nextra-container" style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Navbar */}
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 50,
          borderBottom: "1px solid var(--nextra-border-color, #e5e7eb)",
          backgroundColor: "var(--nextra-bg, #fff)",
          backdropFilter: "blur(8px)",
        }}
      >
        <div
          style={{
            maxWidth: "1200px",
            margin: "0 auto",
            padding: "0 1.5rem",
            height: "3.5rem",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <a href="/" style={{ fontWeight: 700, fontSize: "1.125rem", textDecoration: "none", color: "inherit" }}>
            RTQ
          </a>
          <nav style={{ display: "flex", gap: "1.5rem", alignItems: "center" }}>
            <a href="https://github.com/Latestinssan/RTQ" target="_blank" rel="noopener" style={{ fontSize: "0.875rem", color: "#6b7280" }}>
              GitHub
            </a>
          </nav>
        </div>
      </header>

      {/* Content */}
      <main style={{ flex: 1, maxWidth: "1200px", margin: "0 auto", padding: "2rem 1.5rem", width: "100%" }}>
        {children}
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: "1px solid var(--nextra-border-color, #e5e7eb)",
          padding: "1.5rem",
          textAlign: "center",
          fontSize: "0.875rem",
          color: "#6b7280",
        }}
      >
        MIT {new Date().getFullYear()} © RTQ.{" "}
        <a href="https://nextra.site" target="_blank" rel="noopener">
          Powered by Nextra
        </a>
      </footer>
    </div>
  );
}
