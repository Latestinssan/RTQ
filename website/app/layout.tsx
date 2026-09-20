import type { ReactNode } from "react";
import { Layout } from "nextra-theme-docs";
import { getPageMap } from "nextra/page-map";
import "nextra-theme-docs/style.css";

export const metadata = {
  title: "RTQ — Risk-Adaptive Capability Security Runtime",
  description:
    "Dependency-free capability-security runtime. Every operation is an explicitly registered capability; every authorization is a short-lived, single-use, cryptographically-signed ticket.",
};

export const dynamic = "force-dynamic";

export default async function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  const pageMap = await getPageMap();
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body>
        <Layout pageMap={pageMap} docsRepositoryBase="https://github.com/Latestinssan/RTQ/tree/main/website">
          {children}
        </Layout>
      </body>
    </html>
  );
}
