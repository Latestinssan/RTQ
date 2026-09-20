import type { Metadata, Viewport } from "next";
import "./globals.css";
import { APP_INFO } from "@/lib/version";

const SITE_URL = APP_INFO.siteUrl;

export const viewport: Viewport = {
  themeColor: "#03040b",
};

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  applicationName: "RTQ",
  category: "technology",
  title: {
    default: "RTQ — Risk-Adaptive Capability Security Runtime",
    template: "%s | RTQ Docs",
  },
  description: APP_INFO.description,
  keywords: [
    "RTQ",
    "Risk-Adaptive",
    "Capability Security",
    "Security Runtime",
    "Capability-Based Security",
    "Zero Trust Runtime",
    "Agent Security",
    "MCP Security",
    "OS Sandbox",
    "macOS Seatbelt",
    "Linux bubblewrap",
    "Windows AppContainer",
    "HMAC-SHA256",
    "Single-Use Tickets",
    "QR Approval",
    "Default Deny",
    "Open Source Security",
    "Apache-2.0",
    "Latestinssan",
    "Ponsri School",
    "PONSRISCHOOL",
    "Aartiq",
    "MCP Bridge Security",
    "Capability Registry",
    "Policy Engine",
    "Fail-Closed Sandbox",
    "Redacted Audit",
    "Security Invariants",
    "Dependency-Free Security",
    "Capability Authorization",
    "Declarative Security Policy",
  ],
  authors: [
    { name: "Latestinssan", url: "https://github.com/Latestinssan" },
  ],
  creator: "Latestinssan",
  publisher: "Latestinssan",
  formatDetection: { email: false, address: false, telephone: false },
  openGraph: {
    title: "RTQ — Risk-Adaptive Capability Security Runtime",
    description: APP_INFO.description,
    url: SITE_URL,
    siteName: "RTQ",
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "RTQ — Risk-Adaptive Capability Security Runtime",
    description: APP_INFO.description,
    creator: "@Latestinssan",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  other: { "llms.txt": `${SITE_URL}/llms.txt` },
  alternates: {
    canonical: SITE_URL,
    languages: { en: SITE_URL, "x-default": SITE_URL },
  },
  icons: [
    { rel: "icon", url: "/icon.png" },
    { rel: "apple-touch-icon", url: "/icon.png" },
    { rel: "manifest", url: "/manifest.json" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="scroll-smooth">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
          rel="stylesheet"
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "SoftwareApplication",
              name: "RTQ",
              alternateName: "Risk-Adaptive Capability Security Runtime",
              description: APP_INFO.description,
              url: SITE_URL,
              applicationCategory: "SecurityApplication",
              operatingSystem: ["macOS", "Linux", "Windows"],
              offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
              author: {
                "@type": "Person",
                name: "Latestinssan",
                url: "https://github.com/Latestinssan",
              },
              sameAs: [
                "https://github.com/Latestinssan/RTQ",
                SITE_URL,
              ],
            }),
          }}
        />
      </head>
      <body className="font-inter antialiased bg-[#03040b] text-white">
        {children}
      </body>
    </html>
  );
}
