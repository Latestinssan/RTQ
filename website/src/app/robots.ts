import type { MetadataRoute } from "next";
import { APP_INFO } from "@/lib/version";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: ["/api/", "/admin/"],
      },
    ],
    sitemap: `${APP_INFO.siteUrl}/sitemap.xml`,
  };
}
