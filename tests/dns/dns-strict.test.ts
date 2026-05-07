import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { strictXrayConfigSchema } from "../../src/schemas/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray dns strict parity", () => {
  it("accepts the DNSConfig fields declared by xray-core", () => {
    const result = validateStrictXrayConfig({
      dns: {
        servers: [
          "1.1.1.1",
          {
            address: "https://dns.google/dns-query",
            domains: ["geosite:google"],
            expectedIPs: ["geoip:google"],
            skipFallback: true,
            queryStrategy: "UseIPv4",
            tag: "google-doh"
          }
        ],
        hosts: {
          "domain:example.com": "127.0.0.1"
        },
        clientIp: "1.1.1.1",
        tag: "dns-in",
        queryStrategy: "UseIP",
        disableCache: false,
        serveStale: true,
        serveExpiredTTL: 30,
        disableFallback: false,
        disableFallbackIfMatch: true,
        enableParallelQuery: true,
        useSystemHosts: false
      }
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => issue.message).join("; ")).toBe(true);
    expect(strictXrayConfigSchema.safeParse(result.config).success).toBe(true);
  });

  it("rejects DNS fields that are not in the selected xray-core release", () => {
    const result = validateStrictXrayConfig({
      dns: {
        servers: [],
        panelResolver: true
      }
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toContain("/dns/panelResolver");
  });

  it("requires dns to be an object when the section is present", () => {
    const result = validateStrictXrayConfig({
      dns: []
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues).toMatchObject([
      {
        code: "XCK_XRAY_STRICT_EXPECTED_OBJECT",
        path: "/dns"
      }
    ]);
  });
});
