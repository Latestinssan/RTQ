import type { ReactNode } from "react";
import { Head } from "nextra/components";
import { getPageMap } from "nextra/page-map";
import { ClientLayout } from "./client-layout";
import "nextra-theme-docs/style.css";

export const metadata = {
  title: "RTQ — Risk-Adaptive Capability Security Runtime",
  description:
    "Dependency-free capability-security runtime. Every operation is an explicitly registered capability; every authorization is a short-lived, single-use, cryptographically-signed ticket.",
};

// Prevent static prerendering of this layout (Layout component needs runtime context)
export const dynamic = "force-dynamic";

export default async function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  const pageMap = await getPageMap();
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head />
      <body>
        <ClientLayout pageMap={pageMap}>{children}</ClientLayout>
      </body>
    </html>
  );
}
