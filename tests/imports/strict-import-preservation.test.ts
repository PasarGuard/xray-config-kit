import { describe, expect, it } from "bun:test";
import { buildXrayConfig, createDefaultOutbound, importXrayConfig, validateStrictXrayConfig } from "../../src/index.js";
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

  it("preserves imported inbound and outbound JSON by tag when rows are reordered", () => {
    const raw = {
      inbounds: [
        {
          protocol: "vless",
          tag: "VLESS_XHTTP",
          port: 443,
          settings: {
            clients: [{ id: "11111111-1111-4111-8111-111111111111" }],
            decryption: "none",
            fallbacks: [{ path: "/vless", dest: 8080 }]
          },
          streamSettings: {
            network: "xhttp",
            security: "reality",
            xhttpSettings: { path: "/xhttp-vless" },
            realitySettings: { dest: "example.com:443", serverNames: ["example.com"] }
          }
        },
        {
          protocol: "vmess",
          tag: "VMESS_WS",
          port: 8443,
          settings: {
            clients: [{ id: "22222222-2222-4222-8222-222222222222" }]
          },
          streamSettings: {
            network: "httpupgrade",
            httpupgradeSettings: { path: "/vmess-upgrade" }
          }
        }
      ],
      outbounds: [
        {
          protocol: "freedom",
          tag: "direct",
          settings: { domainStrategy: "AsIs" }
        },
        {
          protocol: "blackhole",
          tag: "block",
          settings: { response: { type: "http" } }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const reorderedProfile = {
      ...imported.profile,
      inbounds: [imported.profile.inbounds[1], imported.profile.inbounds[0]],
      outbounds: [imported.profile.outbounds[1], imported.profile.outbounds[0]]
    };

    const rebuilt = buildXrayConfig(reorderedProfile, { mode: "permissive" });
    const vmess = rebuilt.config.inbounds?.[0];
    const vless = rebuilt.config.inbounds?.[1];
    const block = rebuilt.config.outbounds?.[0];
    const direct = rebuilt.config.outbounds?.[1];

    expect(vmess?.tag).toBe("VMESS_WS");
    expect(vmess?.protocol).toBe("vmess");
    expect(vmess?.settings?.decryption).toBeUndefined();
    expect(vmess?.settings?.fallbacks).toBeUndefined();
    expect(vmess?.streamSettings?.xhttpSettings).toBeUndefined();
    expect(vmess?.streamSettings?.httpupgradeSettings?.path).toBe("/vmess-upgrade");

    expect(vless?.tag).toBe("VLESS_XHTTP");
    expect(vless?.settings?.decryption).toBe("none");
    expect(vless?.settings?.fallbacks).toEqual([{ path: "/vless", dest: 8080 }]);
    expect(vless?.streamSettings?.xhttpSettings?.path).toBe("/xhttp-vless");

    expect(block?.tag).toBe("block");
    expect(block?.settings?.response).toEqual({ type: "http" });
    expect(direct?.tag).toBe("direct");
    expect(direct?.settings?.domainStrategy).toBe("AsIs");
  });

  it("does not inject typed HTTP stream defaults into advanced pasted inbound JSON", () => {
    const raw = {
      inbounds: [
        {
          tag: "http",
          port: 22457,
          listen: "127.0.0.1",
          protocol: "http",
          streamSettings: {
            sockopt: {
              tcpFastOpen: true,
              acceptProxyProtocol: true,
              tcpKeepAliveInterval: 0
            },
            security: "tls",
            tlsSettings: {
              certificates: [
                {
                  key: [
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "key",
                    "-----END RSA PRIVATE KEY-----"
                  ],
                  certificate: [
                    "-----BEGIN CERTIFICATE-----",
                    "cert",
                    "-----END CERTIFICATE-----"
                  ]
                }
              ]
            }
          }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const changedProfile = {
      ...imported.profile,
      inbounds: [
        {
          ...imported.profile.inbounds[0],
          port: 22458
        }
      ]
    };

    const changed = buildXrayConfig(changedProfile, { mode: "permissive" });
    expect(changed.config.inbounds?.[0]?.port).toBe(22458);
    expect(changed.config.inbounds?.[0]).not.toHaveProperty("settings");
    expect(changed.config.inbounds?.[0]?.streamSettings).not.toHaveProperty("network");
    expect(changed.config.inbounds?.[0]?.streamSettings).not.toHaveProperty("tcpSettings");
    expect(changed.config.inbounds?.[0]?.streamSettings?.tlsSettings?.certificates).toEqual(raw.inbounds[0].streamSettings.tlsSettings.certificates);
  });

  it("does not preserve old inbound or outbound config when protocol changes", () => {
    const raw = {
      inbounds: [
        {
          protocol: "vless",
          tag: "proxy-in",
          port: 443,
          settings: {
            clients: [{ id: "11111111-1111-4111-8111-111111111111" }],
            decryption: "none",
            staleInboundSetting: true
          },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: { certificates: [{ certificate: ["old-cert"], key: ["old-key"] }] }
          },
          staleInboundEnvelope: true
        }
      ],
      outbounds: [
        {
          protocol: "vless",
          tag: "proxy-out",
          settings: {
            address: "example.com",
            port: 443,
            id: "11111111-1111-4111-8111-111111111111",
            encryption: "none",
            reverse: { tag: "TUN" }
          },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: { serverName: "old.example.com" }
          }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const changedProfile = {
      ...imported.profile,
      inbounds: [
        {
          kind: "inbound" as const,
          protocol: "http" as const,
          tag: "proxy-in",
          port: 8080
        }
      ],
      outbounds: [
        createDefaultOutbound({
          protocol: "freedom",
          tag: "proxy-out",
          settings: { domainStrategy: "AsIs" }
        })
      ]
    };

    const changed = buildXrayConfig(changedProfile, { mode: "permissive" });

    expect(changed.config.inbounds?.[0]).toEqual({
      tag: "proxy-in",
      port: 8080,
      protocol: "http",
      settings: {}
    });
    expect(changed.config.outbounds?.[0]).toEqual({
      tag: "proxy-out",
      protocol: "freedom",
      settings: { domainStrategy: "AsIs" }
    });
  });
});
