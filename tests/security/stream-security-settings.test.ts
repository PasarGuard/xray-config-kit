import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray stream security settings parity", () => {
  it("accepts current TLS and REALITY setting fields from xray-core", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless-tls",
          port: 443,
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: {
              allowInsecure: false,
              serverName: "example.com",
              alpn: ["h2", "http/1.1"],
              enableSessionResumption: true,
              disableSystemRoot: false,
              minVersion: "1.2",
              maxVersion: "1.3",
              cipherSuites: "TLS_AES_128_GCM_SHA256",
              fingerprint: "chrome",
              rejectUnknownSni: false,
              curvePreferences: ["X25519"],
              masterKeyLog: "",
              pinnedPeerCertSha256: "",
              verifyPeerCertByName: "example.com",
              verifyPeerCertInNames: ["example.com"],
              echServerKeys: "",
              echConfigList: "",
              echForceQuery: "none",
              echSockopt: {}
            }
          }
        },
        {
          protocol: "vless",
          tag: "vless-reality",
          port: 444,
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            network: "tcp",
            security: "reality",
            realitySettings: {
              show: false,
              target: "example.com:443",
              dest: "example.com:443",
              type: "tcp",
              xver: 0,
              serverNames: ["example.com"],
              privateKey: "private",
              minClientVer: "",
              maxClientVer: "",
              maxTimeDiff: 0,
              shortIds: [""],
              mldsa65Seed: "",
              fingerprint: "chrome",
              serverName: "example.com",
              password: "",
              publicKey: "public",
              shortId: "",
              mldsa65Verify: "",
              spiderX: "/"
            }
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ")).toBe(true);
  });

  it("rejects unknown nested TLS and REALITY setting fields", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            network: "tcp",
            security: "reality",
            tlsSettings: {
              kitOnlyTls: true
            },
            realitySettings: {
              kitOnlyReality: true
            }
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/inbounds/0/streamSettings/tlsSettings/kitOnlyTls",
      "/inbounds/0/streamSettings/realitySettings/kitOnlyReality"
    ]));
  });

  it("requires nested TLS and REALITY settings to be objects", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: "not-object",
            realitySettings: "not-object"
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/inbounds/0/streamSettings/tlsSettings",
      "/inbounds/0/streamSettings/realitySettings"
    ]));
  });
});
