import { existsSync, readFileSync } from "fs";
import { join } from "path";

export function getVersionFromPackage(): {
  version: string;
  codename: string;
  releaseDate: string;
  channel: string;
} {
  try {
    const candidates = [
      join(process.cwd(), "..", "aartiq-browser", "package.json"),
      join(process.cwd(), "aartiq-browser", "package.json"),
      join(process.cwd(), "package.json"),
    ];
    const packagePath =
      candidates.find((candidate) => existsSync(candidate)) ||
      candidates[candidates.length - 1];
    const packageJson = JSON.parse(readFileSync(packagePath, "utf-8"));
    return {
      version: packageJson.version || "0.0.0",
      codename: "Nebula",
      releaseDate: new Date().toISOString().split("T")[0],
      channel: "stable",
    };
  } catch {
    return {
      version: "0.0.0",
      codename: "Nebula",
      releaseDate: "2026-01-01",
      channel: "stable",
    };
  }
}
