import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray inbound sniffing strict parity", () => {
  it("accepts SniffingConfig fields declared by xray-core", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "socks",
          tag: "socks",
          port: 1080,
          settings: {},
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls", "quic", "fakedns"],
            domainsExcluded: ["domain:example.com"],
            ipsExcluded: ["geoip:private"],
            metadataOnly: false,
            routeOnly: true
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => issue.message).join("; ")).toBe(true);
  });

  it("rejects unknown SniffingConfig fields", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "socks",
          tag: "socks",
          port: 1080,
          settings: {},
          sniffing: {
            enabled: true,
            notFromXray: true
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toContain("/inbounds/1/sniffing/notFromXray");
  });
});
