import { NextResponse } from "next/server";
import { APP_INFO } from "@/lib/version";

export async function GET() {
  const content = `# ${APP_INFO.fullName}

> ${APP_INFO.description}

## Documentation

- [Overview](${APP_INFO.siteUrl}/docs/overview)
- [Security Overview](${APP_INFO.siteUrl}/docs/security-overview)
- [Threat Model](${APP_INFO.siteUrl}/docs/threat-model)
- [Verification Matrix](${APP_INFO.siteUrl}/docs/verification-matrix)
- [Verification Traceability](${APP_INFO.siteUrl}/docs/verification-traceability)
- [Platform Support](${APP_INFO.siteUrl}/docs/platform-support)
- [Aartiq Integration](${APP_INFO.siteUrl}/docs/aartiq-integration)
- [Mobile Approval](${APP_INFO.siteUrl}/docs/mobile-approval)
- [CLI Reference](${APP_INFO.siteUrl}/docs/cli)
- [Testing Strategy](${APP_INFO.siteUrl}/docs/testing-strategy)
- [Provenance](${APP_INFO.siteUrl}/docs/provenance)

## Source

- [GitHub](${APP_INFO.repo})
- [License: Apache-2.0](${APP_INFO.repo}/blob/main/LICENSE)
`;

  return new NextResponse(content, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
