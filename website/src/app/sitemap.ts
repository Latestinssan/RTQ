import type { MetadataRoute } from "next";
import { APP_INFO } from "@/lib/version";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = APP_INFO.siteUrl;
  const docs = [
    "overview",
    "security-overview",
    "threat-model",
    "verification-matrix",
    "verification-traceability",
    "platform-support",
    "aartiq-integration",
    "mobile-approval",
    "cli",
    "testing-strategy",
    "provenance",
  ];

  return [
    { url: base, lastModified: new Date(), changeFrequency: "weekly", priority: 1 },
    { url: `${base}/docs`, lastModified: new Date(), changeFrequency: "weekly", priority: 0.9 },
    ...docs.map((doc) => ({
      url: `${base}/docs/${doc}`,
      lastModified: new Date(),
      changeFrequency: "weekly" as const,
      priority: 0.8,
    })),
  ];
}
