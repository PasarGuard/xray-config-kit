import { describe, expect, it } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

const ignoredDirectories = new Set([
  ".git",
  "dist",
  "node_modules"
]);

const textExtensions = new Set([
  ".json",
  ".md",
  ".ts",
  ".tsx",
  ".yml",
  ".yaml"
]);

const allowedFiles = new Set([
  ".github/xray-ci-matrix.json",
  "README.md",
  "src/adapters/xray/generated-capabilities.ts",
  "src/xray-json/parity-manifest.ts",
  "src/xray-json/parity-types.ts",
  "tests/helpers/xray-releases.ts",
  "tests/parity/generated-types.test.ts",
  "tests/parity/generator-config.test.ts",
  "tests/parity/manifest.test.ts",
  "tests/versions/parity-release.test.ts",
  "xray-parity.config.ts"
]);

function normalizePath(path: string): string {
  return path.split(sep).join("/");
}

async function collectTextFiles(directory: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) continue;
      files.push(...await collectTextFiles(join(directory, entry.name)));
      continue;
    }
    if (entry.isFile() && textExtensions.has(extname(entry.name))) {
      files.push(join(directory, entry.name));
    }
  }
  return files;
}

describe("dynamic release usage", () => {
  it("keeps the latest generated release out of handwritten app and ordinary test code", async () => {
    const root = process.cwd();
    const files = await collectTextFiles(root);
    const findings: string[] = [];
    const needles = [latestGeneratedRelease.tag, latestGeneratedRelease.version];

    for (const file of files) {
      const relativePath = normalizePath(relative(root, file));
      if (allowedFiles.has(relativePath)) continue;
      const content = await readFile(file, "utf8");
      if (needles.some((needle) => content.includes(needle))) findings.push(relativePath);
    }

    expect(findings).toEqual([]);
  });
});
