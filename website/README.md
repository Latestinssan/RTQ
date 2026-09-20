# Aartiq Landing Page

**Production URL:** https://aartiq.ponsrischool.in

This directory contains the public marketing site and documentation for Aartiq.

## Current Release

- Version: `0.3.2`
- Codename: `Nebula`
- Channel: `alpha`
- Release date: `2026-07-10`

## Purpose

The landing page is the public-facing source of truth for:

- Product overview and downloads
- Documentation under `/docs/*`
- AI/LLM crawlability assets such as `llms.txt`, `sitemap.xml`, and `robots.txt`
- Search metadata and documentation indexing

## Structure

```text
Landing_Page/
├── public/
│   ├── llms.txt
│   ├── robots.txt
│   ├── sitemap.xml
│   └── .well-known/ai-plugin.json
├── src/
│   ├── app/
│   │   ├── docs/
│   │   ├── api/
│   │   └── llms.txt/
│   ├── components/
│   ├── data/
│   └── lib/
└── README.md
```

## Documentation Pages

These pages should stay aligned with `Landing_Page/AI-GUIDE.md`:

- `/docs/getting-started`
- `/docs/overview`
- `/docs/components`
- `/docs/changelog`
- `/docs/cloud-sync`
- `/docs/ai-commands`
- `/docs/security`
- `/docs/automation`
- `/docs/native-api`
- `/docs/deep-links`
- `/docs/plugins`
- `/docs/extensions`
- `/docs/api-reference`
- `/docs/troubleshooting`
- `/docs/contributing`

## AI Command Documentation Rules

- Public docs should treat structured JSON as the primary command format.
- `/docs/ai-commands`, `src/lib/search-index.ts`, `public/llms.txt`, and `src/app/llms.txt/route.ts` should stay in sync.
- The canonical public command set is:
  - `NAVIGATE`
  - `SEARCH`
  - `WEB_SEARCH`
  - `RELOAD`
  - `GO_BACK`
  - `GO_FORWARD`
  - `READ_PAGE_CONTENT`
  - `LIST_OPEN_TABS`
  - `CLICK_ELEMENT`
  - `FIND_AND_CLICK`
  - `FILL_FORM`
  - `CREATE_PDF_JSON`
  - `CREATE_FILE_JSON`
  - `SHELL_COMMAND`
  - `SET_VOLUME`
  - `SET_BRIGHTNESS`
  - `OPEN_APP`
  - `OCR_SCREEN`
  - `OCR_COORDINATES`
  - `CLICK_APP_ELEMENT`
  - `SCHEDULE_TASK`
  - `LIST_AUTOMATIONS`
  - `DELETE_AUTOMATION`
  - `THINK`
  - `PLAN`
  - `PLUGIN_COMMAND`

## Maintenance Checklist

When landing-page docs change, also review:

- `src/lib/version.ts`
- `src/lib/search-index.ts`
- `public/llms.txt`
- `src/app/llms.txt/route.ts`
- `src/app/docs/metadata.ts`

## Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).
