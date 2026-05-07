import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { strictXrayConfigSchema } from "../../src/schemas/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("strict xray json validation", () => {
  it("accepts Xray-native sections and loader protocols from the selected release", () => {
    const result = validateStrictXrayConfig({
      log: { loglevel: "warning" },
      reverse: { bridges: [], portals: [] },
      transport: {},
      inbounds: [
        {
          protocol: "dokodemo-door",
          tag: "dokodemo",
          listen: "127.0.0.1",
          port: 10080,
          settings: {
            address: "example.com",
            port: 443,
            network: "tcp"
          }
        }
      ],
      outbounds: [
        { protocol: "freedom", tag: "direct", settings: { domainStrategy: "AsIs" } }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(strictXrayConfigSchema.safeParse(result.config).success).toBe(true);
  });

  it("rejects kit-only or unknown Xray fields in strict mode", () => {
    const result = validateStrictXrayConfig({
      imaginaryTopLevel: true,
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          settings: {
            clients: [],
            kitOnly: true
          },
          streamSettings: {
            network: "xhttp",
            security: "none",
            madeUpSettings: {}
          }
        }
      ]
    }, { xrayVersion: latestGeneratedRelease.version });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/imaginaryTopLevel",
      "/inbounds/0/settings/kitOnly",
      "/inbounds/0/streamSettings/madeUpSettings"
    ]));
  });

  it("uses version-specific Xray transport acceptance from the manifest", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          settings: { clients: [], decryption: "none" },
          streamSettings: { network: "quic", security: "none" }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.some((issue) => issue.code === "XCK_XRAY_STRICT_UNKNOWN_TRANSPORT")).toBe(true);
  });
});
