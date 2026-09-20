#!/usr/bin/env node
// Patch Nextra 4.6.1 Layout component: add children back to themeConfig before validation
// This fixes a Zod v4 bug where Layout destructures children from props,
// then validates the remaining props against a schema that requires children.
const fs = require('fs');
const path = require('path');

const layoutPath = path.join(__dirname, 'node_modules/nextra-theme-docs/dist/layout.js');
if (!fs.existsSync(layoutPath)) {
  console.log('nextra-theme-docs layout.js not found, skipping patch');
  process.exit(0);
}

let content = fs.readFileSync(layoutPath, 'utf8');

// The bug: destructuring extracts children, then safeParse validates themeConfig (without children)
// Fix: add children back to themeConfig before safeParse
const old = 'LayoutPropsSchema.safeParse(themeConfig)';
const patched = 'LayoutPropsSchema.safeParse({...themeConfig, children})';

if (content.includes(old)) {
  content = content.replace(old, patched);
  fs.writeFileSync(layoutPath, content, 'utf8');
  console.log('✓ Patched nextra-theme-docs/layout.js (added children back to themeConfig)');
} else if (content.includes(patched)) {
  console.log('✓ Already patched');
} else {
  console.log('⚠ Could not find patch target in layout.js — manual fix needed');
}
