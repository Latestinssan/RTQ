"use client";

import type { ReactNode } from "react";
import { Layout } from "nextra-theme-docs";

export function ClientLayout({
  children,
  pageMap,
}: {
  children: ReactNode;
  pageMap: any[];
}) {
  return (
    <Layout pageMap={pageMap} docsRepositoryBase="https://github.com/example/rtq/tree/main/website">
      {children}
    </Layout>
  );
}
