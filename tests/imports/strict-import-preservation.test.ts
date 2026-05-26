import { describe, expect, it } from "bun:test";
import { buildXrayConfig, importXrayConfig, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray import preservation vs strict parity", () => {
  it("preserves unknown import JSON but strict Xray mode rejects the same unknown fields", () => {
    const raw = {
      unknownTopLevel: { keep: true },
      inbounds: [
        {
          protocol: "unknown-in",
          tag: "raw-in",
          port: 10000,
          settings: { keep: true }
        }
      ],
      outbounds: [
        {
          protocol: "unknown-out",
          tag: "raw-out",
          settings: { keep: true }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    expect(imported.unmanaged).toBe(2);
    expect(imported.profile.unknown?.pointers["/unknownTopLevel"]).toEqual({ keep: true });
    expect(imported.issues.map((issue) => issue.code)).toEqual(expect.arrayContaining([
      "XCK_IMPORT_UNKNOWN_TOP_LEVEL",
      "XCK_IMPORT_UNMANAGED_INBOUND",
      "XCK_IMPORT_UNMANAGED_OUTBOUND"
    ]));

    const strict = validateStrictXrayConfig(raw, { releaseTag: latestGeneratedRelease.tag });
    expect(strict.ok).toBe(false);
    expect(strict.issues.map((issue) => issue.code)).toEqual(expect.arrayContaining([
      "XCK_XRAY_STRICT_UNKNOWN_FIELD",
      "XCK_XRAY_STRICT_UNKNOWN_INBOUND_PROTOCOL",
      "XCK_XRAY_STRICT_UNKNOWN_OUTBOUND_PROTOCOL"
    ]));
  });

  it("preserves PasarGuard TLS certificate JSON fields during profile round-trip", () => {
    const raw = {
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
              certificates: [
                {
                  serveOnNode: true,
                  certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                  key: ["-----BEGIN PRIVATE KEY-----", "MIIB", "-----END PRIVATE KEY-----"],
                  pasarguardExtra: { keep: true }
                }
              ]
            }
          }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const rebuilt = buildXrayConfig(imported.profile, { mode: "permissive" });
    const certificate = rebuilt.config.inbounds?.[0]?.streamSettings?.tlsSettings?.certificates?.[0];

    expect(certificate).toEqual(raw.inbounds[0].streamSettings.tlsSettings.certificates[0]);
  });

  it("returns imported Xray JSON unchanged until structured fields change", () => {
    const raw = {
      log: { loglevel: "warning", customLogField: true },
      inbounds: [
        {
          protocol: "vless",
          tag: "vless-tls",
          port: 443,
          customInboundField: { keep: true },
          settings: {
            clients: [
              {
                id: "11111111-1111-4111-8111-111111111111",
                email: "alice@example.com",
                customClientField: "keep"
              }
            ],
            decryption: "none",
            customSettingsField: ["keep"]
          },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: {
              certificates: [
                {
                  certificate: "pem-as-string",
                  key: "key-as-string",
                  serveOnNode: true,
                  customCertField: "keep"
                }
              ],
              customTlsField: "keep"
            },
            customStreamField: "keep"
          }
        }
      ],
      routing: {
        rules: [
          {
            type: "field",
            inboundTag: ["vless-tls"],
            outboundTag: "direct",
            customRuleField: "keep"
          }
        ],
        customRoutingField: "keep"
      },
      customTopLevel: { keep: true }
    };

    const imported = importXrayConfig(raw);
    const unchanged = buildXrayConfig(imported.profile, { mode: "permissive" });
    expect(unchanged.config).toEqual(raw);

    const changedProfile = {
      ...imported.profile,
      inbounds: [
        {
          ...imported.profile.inbounds[0],
          port: 8443
        },
        ...imported.profile.inbounds.slice(1)
      ]
    };
    const changed = buildXrayConfig(changedProfile, { mode: "permissive" });

    expect(changed.config.inbounds?.[0]?.port).toBe(8443);
    expect(changed.config.inbounds?.[0]?.customInboundField).toEqual({ keep: true });
    expect(changed.config.inbounds?.[0]?.settings?.customSettingsField).toEqual(["keep"]);
    expect(changed.config.inbounds?.[0]?.streamSettings?.tlsSettings?.customTlsField).toBe("keep");
    expect(changed.config.routing?.rules?.[0]?.customRuleField).toBe("keep");
    expect(changed.config.customTopLevel).toEqual({ keep: true });
  });
});
