#!/usr/bin/env node
import { runCli } from "./index";

runCli(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`rtq: fatal: ${(err as Error).message}\n`);
    process.exitCode = 1;
  },
);
