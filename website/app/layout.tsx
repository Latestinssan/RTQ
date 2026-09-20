import type { ReactNode } from "react";
import { Head } from "nextra/components";
import { getPageMap } from "nextra/page-map";
import { ManualLayout } from "./manual-layout";
import "nextra-theme-docs/style.css";

export const metadata = {
  title: "RTQ — Risk-Adaptive Capability Security Runtime",
  description:
    "Dependency-free capability-security runtime. Every operation is an explicitly registered capability; every authorization is a short-lived, single-use, cryptographically-signed ticket.",
};

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
        <ManualLayout pageMap={pageMap}>{children}</ManualLayout>
      </body>
    </html>
  );
}
