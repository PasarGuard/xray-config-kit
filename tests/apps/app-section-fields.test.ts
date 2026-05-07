import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

function structName(type: string): string | undefined {
  const normalized = type.trim().replace(/^\*/, "");
  if (normalized.startsWith("[]") || normalized.startsWith("map[")) return undefined;
  const name = normalized.includes(".") ? normalized.split(".").pop() : normalized;
  return name && /^[A-Z]\w+$/.test(name) ? name : undefined;
}

describe("xray app section field parity", () => {
  it("accepts representative top-level app section fields from xray-core", () => {
    const result = validateStrictXrayConfig({
      log: {
        access: "",
        error: "",
        loglevel: "warning",
        dnsLog: false,
        maskAddress: ""
      },
      api: {
        tag: "api",
        listen: "127.0.0.1:8080",
        services: ["HandlerService", "StatsService"]
      },
      metrics: {
        tag: "metrics",
        listen: "127.0.0.1:9090"
      },
      reverse: {
        bridges: [],
        portals: []
      },
      observatory: {
        subjectSelector: ["proxy"],
        probeURL: "https://www.google.com/generate_204",
        probeInterval: "1m",
        enableConcurrency: true
      },
      burstObservatory: {
        subjectSelector: ["proxy"],
        pingConfig: {}
      },
      geodata: {
        cron: "0 0 * * *",
        outbound: "direct",
        assets: []
      },
      version: {
        min: "26.0.0",
        max: latestGeneratedRelease.version
      },
      policy: {
        levels: {},
        system: {}
      }
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ")).toBe(true);
  });

  it("rejects unknown fields on every object-shaped app section captured from Config", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    const configFields = release.structs.Config ?? [];
    const objectSections = configFields.filter((field) => {
      const name = structName(field.type);
      return name !== undefined
        && field.json !== "inbounds"
        && field.json !== "outbounds"
        && (release.structs[name]?.length ?? 0) > 0;
    });

    expect(objectSections.map((field) => field.json)).toEqual(expect.arrayContaining([
      "log",
      "routing",
      "dns",
      "policy",
      "api",
      "metrics",
      "reverse",
      "observatory",
      "burstObservatory",
      "version",
      "geodata"
    ]));

    for (const section of objectSections) {
      const result = validateStrictXrayConfig({
        [section.json]: {
          notFromXray: true
        }
      }, { releaseTag: release.tag });

      expect(result.ok, section.json).toBe(false);
      expect(result.issues.map((issue) => issue.path), section.json).toContain(`/${section.json}/notFromXray`);
    }
  });
});
