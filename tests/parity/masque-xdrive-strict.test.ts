import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import type { Issue, JsonObject } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("strict MASQUE and XDrive JSON", () => {
  const config = {
    inbounds: [
      {
        protocol: "masque",
        tag: "masque-in",
        port: 443,
        settings: {
          users: [{ email: "alice@example.com", pass: "alice-masque-pass-1", level: 0 }],
          address: ["10.14.0.1/16", "fd14::1/64"],
          mtu: 1400,
          remoteDNS: ["1.1.1.1"]
        },
        streamSettings: {
          network: "masque",
          security: "tls",
          tlsSettings: { alpn: ["h3", "h2"] },
          masqueSettings: { path: "/.well-known/masque/ip/{target}/{ipproto}/" }
        }
      },
      {
        protocol: "vless",
        tag: "vless-xdrive",
        port: 8443,
        settings: { clients: [], decryption: "none" },
        streamSettings: {
          network: "xdrive",
          security: "tls",
          xdriveSettings: {
            service: "Google Drive",
            remoteFolder: "1AbCdEf",
            secrets: ["id", "secret", "refresh"],
            segmentBytes: 524288,
            flushIntervalMs: 20,
            pollIntervalMs: 50,
            maxPollIntervalMs: 500,
            sessionTtlSeconds: 300,
            concurrency: 8,
            eagerWindowMs: 2000,
            holeTimeoutMs: 30000,
            template: { flatten: true }
          }
        }
      }
    ],
    outbounds: [
      {
        protocol: "masque",
        tag: "warp",
        settings: { address: "162.159.198.1", port: 443, remoteDNS: ["1.1.1.1"] },
        streamSettings: {
          network: "masque",
          security: "tls",
          masqueSettings: {
            host: "cloudflareaccess.com",
            path: "/",
            headers: { "X-Client": "xck" },
            warp: { privateKey: "cHJpdmF0ZQ==", publicKey: "cHVibGlj", address: ["172.16.0.2/32"] }
          }
        }
      }
    ]
  };
  const summary = (issues: Issue[]) => issues.map((issue) => `${issue.code} ${issue.severity} ${issue.path}`);

  it("accepts MASQUE inbound/outbound and XDrive streams in the latest release", () => {
    const result = validateStrictXrayConfig(config, { releaseTag: latestGeneratedRelease.tag });
    expect(result.ok, summary(result.issues).join("; ")).toBe(true);
    expect(result.issues).toEqual([]);
  });

  it("rejects MASQUE and XDrive before they existed", () => {
    const result = validateStrictXrayConfig(config, { releaseTag: "v26.7.28" });
    expect(result.ok).toBe(false);
    expect(summary(result.issues)).toEqual(expect.arrayContaining([
      "XCK_XRAY_STRICT_UNKNOWN_INBOUND_PROTOCOL error /inbounds/1/protocol",
      "XCK_XRAY_STRICT_UNKNOWN_TRANSPORT error /inbounds/2/streamSettings/network",
      "XCK_XRAY_STRICT_UNKNOWN_FIELD error /inbounds/2/streamSettings/xdriveSettings",
      "XCK_XRAY_STRICT_UNKNOWN_OUTBOUND_PROTOCOL error /outbounds/1/protocol"
    ]));
  });

  it("keeps masqueSettings.warp a strict error on v26.9.30", () => {
    const result = validateStrictXrayConfig(config, { releaseTag: "v26.9.30" });
    expect(summary(result.issues)).toEqual(["XCK_XRAY_STRICT_UNKNOWN_FIELD error /outbounds/1/streamSettings/masqueSettings/warp"]);
  });

  it("still rejects other unknown MASQUE server settings", () => {
    const inbound = { ...config.inbounds[0]!, settings: { ...config.inbounds[0]!.settings, pool: [] } };
    const result = validateStrictXrayConfig({ inbounds: [inbound] }, { releaseTag: latestGeneratedRelease.tag });
    expect(summary(result.issues)).toEqual(["XCK_XRAY_STRICT_UNKNOWN_FIELD error /inbounds/1/settings/pool"]);
  });

  it("accepts the masqueSettings.remoteDNS fallback the panel reads and rejects other unknown masqueSettings keys", () => {
    const inbound = config.inbounds[0]!;
    const withMasqueSettings = (masqueSettings: JsonObject) => ({ inbounds: [{ ...inbound, streamSettings: { ...inbound.streamSettings, masqueSettings } }] });
    const path = "/.well-known/masque/ip/{target}/{ipproto}/";
    const latest = { releaseTag: latestGeneratedRelease.tag };
    expect(validateStrictXrayConfig(withMasqueSettings({ path, remoteDNS: ["1.1.1.1", "2606:4700:4700::1111"] }), latest).issues).toEqual([]);
    expect(summary(validateStrictXrayConfig(withMasqueSettings({ path, dns: ["1.1.1.1"] }), latest).issues))
      .toEqual(["XCK_XRAY_STRICT_UNKNOWN_FIELD error /inbounds/1/streamSettings/masqueSettings/dns"]);
  });
});
