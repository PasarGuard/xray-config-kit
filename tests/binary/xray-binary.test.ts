import { describe, expect, it } from "bun:test";
import { buildXrayConfig, createProfile } from "../../src/index.js";
import { testXrayConfig } from "../../src/node/index.js";

const key32 = "OEQIJdY9VnmJ78XX_hyUZueFyqvtdmCWY8e4NJ6B-lk";
const publicKey32 = "0UsWoTj6Ad7JKR_FsQ9p_r05ZXhtRSnWlw53kpwgT34";

describe("real Xray binary", () => {
  const maybeIt = process.env.XRAY_BINARY ? it : it.skip;

  maybeIt("accepts generated VLESS REALITY TCP config", async () => {
    const profile = createProfile({
      presets: ["dns-simple"],
      inbounds: [
        {
          kind: "inbound",
          protocol: "vless",
          tag: "vless-reality",
          listen: "0.0.0.0",
          port: 443,
          clients: [
            {
              protocol: "vless",
              id: "11111111-1111-4111-8111-111111111111",
              email: "alice",
              flow: "xtls-rprx-vision"
            }
          ],
          security: {
            type: "reality",
            serverNames: ["www.example.com"],
            privateKey: key32,
            publicKey: publicKey32,
            shortIds: ["a1b2c3d4"],
            target: "www.example.com:443",
            fingerprint: "chrome",
            spiderX: "/"
          },
          transport: {
            type: "tcp",
            header: { type: "none" }
          },
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls"]
          }
        }
      ]
    });

    const built = buildXrayConfig(profile, {
      xrayVersion: process.env.XRAY_VERSION
    });
    const buildErrors = built.issues.filter((issue) => issue.severity === "error");
    if (buildErrors.length > 0) {
      throw new Error(buildErrors.map((issue) => `${issue.code}: ${issue.message}`).join("\n"));
    }

    const result = await testXrayConfig(built.config, {
      binaryPath: process.env.XRAY_BINARY,
      timeoutMs: 30_000
    });

    if (!result.ok) throw new Error(result.stdout + result.stderr);
    expect(result.ok).toBe(true);
  });
});
