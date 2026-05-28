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

  it("removes known imported fields when cleared from the typed inbound UI model", () => {
    const raw = {
      inbounds: [
        {
          protocol: "http",
          tag: "http",
          listen: "127.0.0.1",
          port: 8080,
          customInboundField: { keep: true },
          settings: {
            allowTransparent: true,
            userLevel: 3,
            customSettingsField: "keep"
          },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: {
              serverName: "old.example.com",
              allowInsecure: true,
              customTlsField: "keep"
            },
            customStreamField: "keep"
          }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const inbound = {
      ...imported.profile.inbounds[0],
      listen: undefined,
      allowTransparent: undefined,
      userLevel: undefined,
      security: {
        type: "tls" as const,
        allowInsecure: true
      },
      transport: {
        type: "tcp" as const
      }
    };
    const changed = buildXrayConfig({
      ...imported.profile,
      inbounds: [inbound]
    }, { mode: "permissive" });

    expect(changed.config.inbounds?.[0]).not.toHaveProperty("listen");
    expect(changed.config.inbounds?.[0]?.settings).not.toHaveProperty("allowTransparent");
    expect(changed.config.inbounds?.[0]?.settings).not.toHaveProperty("userLevel");
    expect(changed.config.inbounds?.[0]?.streamSettings?.tlsSettings).not.toHaveProperty("serverName");
    expect(changed.config.inbounds?.[0]?.customInboundField).toEqual({ keep: true });
    expect(changed.config.inbounds?.[0]?.settings?.customSettingsField).toBe("keep");
    expect(changed.config.inbounds?.[0]?.streamSettings?.customStreamField).toBe("keep");
    expect(changed.config.inbounds?.[0]?.streamSettings?.tlsSettings?.customTlsField).toBe("keep");
  });

  it("removes known imported fields when cleared from outbound, routing, and DNS models", () => {
    const raw = {
      dns: {
        servers: [
          {
            address: "8.8.8.8",
            port: 53,
            domains: ["geosite:google"],
            expectedIPs: ["geoip:us"],
            skipFallback: true,
            queryStrategy: "UseIP",
            tag: "google",
            customServerField: "keep"
          }
        ],
        hosts: { "example.com": "1.2.3.4" },
        queryStrategy: "UseIPv4",
        disableCache: true,
        disableFallback: true,
        customDnsField: "keep"
      },
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
          {
            type: "field",
            inboundTag: ["in"],
            outboundTag: "proxy",
            port: "443",
            domain: ["example.com"],
            webhook: {
              url: "https://hook.example",
              deduplication: 30,
              headers: { "X-Test": "1" },
              customWebhookField: "keep"
            },
            customRuleField: "keep"
          }
        ],
        balancers: [
          {
            tag: "bal",
            selector: ["proxy"],
            fallbackTag: "direct",
            strategy: {
              type: "leastPing",
              settings: { expected: 1 },
              customStrategyField: "keep"
            },
            customBalancerField: "keep"
          }
        ],
        customRoutingField: "keep"
      },
      outbounds: [
        {
          protocol: "vless",
          tag: "proxy",
          sendThrough: "1.1.1.1",
          settings: {
            address: "example.com",
            port: 443,
            id: "11111111-1111-4111-8111-111111111111",
            encryption: "none",
            flow: "xtls-rprx-vision",
            customSettingsField: "keep"
          },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: {
              serverName: "old.example.com",
              allowInsecure: true,
              customTlsField: "keep"
            },
            customStreamField: "keep"
          },
          proxySettings: {
            tag: "direct",
            transportLayer: true,
            customProxyField: "keep"
          },
          mux: {
            enabled: true,
            concurrency: 8,
            customMuxField: "keep"
          },
          customOutboundField: "keep"
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const outbound = imported.profile.outbounds?.[0];
    if (!outbound || outbound.protocol === "unmanaged") throw new Error("expected editable outbound");
    const outboundSettings = { ...(outbound.settings ?? {}) };
    delete outboundSettings.flow;

    const changed = buildXrayConfig({
      ...imported.profile,
      dns: {
        servers: [
          {
            address: "8.8.8.8"
          }
        ]
      } as never,
      routing: {
        ...imported.profile.routing,
        domainStrategy: undefined,
        rules: [
          {
            ...imported.profile.routing?.rules[0],
            port: undefined,
            webhook: {
              url: "https://hook.example"
            }
          }
        ],
        balancers: [
          {
            ...imported.profile.routing?.balancers?.[0],
            fallbackTag: undefined,
            strategy: {
              type: "leastPing"
            }
          }
        ]
      } as never,
      outbounds: [
        {
          ...outbound,
          sendThrough: undefined,
          settings: outboundSettings,
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: {
              allowInsecure: true
            }
          },
          proxySettings: {
            customProxyField: "keep"
          },
          mux: {
            enabled: true,
            customMuxField: "keep"
          }
        }
      ]
    }, { mode: "permissive" });

    expect(changed.config.outbounds?.[0]).not.toHaveProperty("sendThrough");
    expect(changed.config.outbounds?.[0]?.settings).not.toHaveProperty("flow");
    expect(changed.config.outbounds?.[0]?.streamSettings?.tlsSettings).not.toHaveProperty("serverName");
    expect(changed.config.outbounds?.[0]?.proxySettings).not.toHaveProperty("tag");
    expect(changed.config.outbounds?.[0]?.proxySettings).not.toHaveProperty("transportLayer");
    expect(changed.config.outbounds?.[0]?.mux).not.toHaveProperty("concurrency");
    expect(changed.config.outbounds?.[0]?.customOutboundField).toEqual("keep");
    expect(changed.config.outbounds?.[0]?.settings?.customSettingsField).toEqual("keep");
    expect(changed.config.outbounds?.[0]?.streamSettings?.customStreamField).toEqual("keep");
    expect(changed.config.outbounds?.[0]?.streamSettings?.tlsSettings?.customTlsField).toEqual("keep");
    expect(changed.config.outbounds?.[0]?.proxySettings?.customProxyField).toEqual("keep");
    expect(changed.config.outbounds?.[0]?.mux?.customMuxField).toEqual("keep");

    expect(changed.config.routing).not.toHaveProperty("domainStrategy");
    expect(changed.config.routing?.rules?.[0]).not.toHaveProperty("port");
    expect(changed.config.routing?.rules?.[0]?.webhook).not.toHaveProperty("deduplication");
    expect(changed.config.routing?.rules?.[0]?.webhook).not.toHaveProperty("headers");
    expect(changed.config.routing?.balancers?.[0]).not.toHaveProperty("fallbackTag");
    expect(changed.config.routing?.balancers?.[0]?.strategy).not.toHaveProperty("settings");
    expect(changed.config.routing?.customRoutingField).toEqual("keep");
    expect(changed.config.routing?.rules?.[0]?.customRuleField).toEqual("keep");
    expect(changed.config.routing?.rules?.[0]?.webhook?.customWebhookField).toEqual("keep");
    expect(changed.config.routing?.balancers?.[0]?.customBalancerField).toEqual("keep");
    expect(changed.config.routing?.balancers?.[0]?.strategy?.customStrategyField).toEqual("keep");

    expect(changed.config.dns).not.toHaveProperty("queryStrategy");
    expect(changed.config.dns).not.toHaveProperty("disableCache");
    expect(changed.config.dns).not.toHaveProperty("disableFallback");
    expect(changed.config.dns?.servers?.[0]).not.toHaveProperty("port");
    expect(changed.config.dns?.servers?.[0]).not.toHaveProperty("domains");
    expect(changed.config.dns?.servers?.[0]).not.toHaveProperty("expectedIPs");
    expect(changed.config.dns?.servers?.[0]).not.toHaveProperty("skipFallback");
    expect(changed.config.dns?.servers?.[0]).not.toHaveProperty("queryStrategy");
    expect(changed.config.dns?.servers?.[0]).not.toHaveProperty("tag");
    expect(changed.config.dns?.customDnsField).toEqual("keep");
    expect(changed.config.dns?.servers?.[0]?.customServerField).toEqual("keep");
  });

  it("removes imported top-level DNS and routing sections when the typed model disables them", () => {
    const raw = {
      dns: {
        servers: ["8.8.8.8"]
      },
      routing: {
        domainStrategy: "AsIs",
        rules: [{ type: "field", outboundTag: "direct" }]
      },
      inbounds: [
        {
          protocol: "http",
          tag: "http",
          port: 8080,
          settings: {}
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const changed = buildXrayConfig({
      ...imported.profile,
      dns: undefined,
      routing: undefined,
      inbounds: [
        {
          ...imported.profile.inbounds[0],
          port: 8081
        }
      ]
    }, { mode: "permissive" });

    expect(changed.config).not.toHaveProperty("dns");
    expect(changed.config).not.toHaveProperty("routing");
    expect(changed.config.inbounds?.[0]?.port).toBe(8081);
  });

  it("keeps imported known top-level sections that are not modeled by the typed editor", () => {
    const raw = {
      observatory: {
        subjectSelector: ["proxy"],
        probeURL: "https://example.com/generate_204"
      },
      policy: {
        levels: {
          "0": {
            handshake: 4
          }
        }
      },
      inbounds: [
        {
          protocol: "http",
          tag: "http",
          port: 8080,
          settings: {}
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const changed = buildXrayConfig({
      ...imported.profile,
      inbounds: [
        {
          ...imported.profile.inbounds[0],
          port: 8081
        }
      ]
    }, { mode: "permissive" });

    expect(changed.config.observatory).toEqual(raw.observatory);
    expect(changed.config.policy).toEqual(raw.policy);
    expect(changed.config.inbounds?.[0]?.port).toBe(8081);
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
