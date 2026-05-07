import { describe, expect, it } from "bun:test";
import {
  analyzeProfile,
  buildXrayConfig,
  createDefaultInbound,
  createProfile,
  diffConfigs,
  generateClientLink,
  generateShadowsocksLink,
  generateSubscription,
  generateVlessLink,
  generateWireGuardConfig,
  getCapabilities,
  getInboundFieldVisibility,
  getInboundFormCapabilities,
  getXrayParityRelease,
  importXrayConfig,
  validateProfile
} from "../src/index.js";
import { getProfileJsonSchema } from "../src/schemas/index.js";
import { latestGeneratedRelease } from "./helpers/xray-releases.js";
import type { Profile } from "../src/index.js";

const key32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function realityProfile(): Profile {
  return createProfile({
    name: "edge-1",
    presets: ["dns-simple", "routing-private-direct"],
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
          publicKey: key32,
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
}

function vmessProfile(): Profile {
  return createProfile({
    name: "vmess-edge",
    inbounds: [
      {
        kind: "inbound",
        protocol: "vmess",
        tag: "vmess-ws",
        listen: "0.0.0.0",
        port: 8443,
        clients: [
          {
            protocol: "vmess",
            id: "22222222-2222-4222-8222-222222222222",
            security: "auto",
            email: "bob"
          }
        ],
        security: {
          type: "tls",
          serverName: "edge.example.com",
          fingerprint: "chrome",
          alpn: ["h2", "http/1.1"]
        },
        transport: {
          type: "ws",
          path: "/ray",
          host: "edge.example.com"
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls"]
        }
      }
    ]
  });
}

describe("xray-config-kit core", () => {
  it("builds VLESS REALITY TCP Xray JSON", () => {
    const built = buildXrayConfig(realityProfile(), { xrayVersion: latestGeneratedRelease.version });

    expect(built.adapterId).toBe("xray@26.5");
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.inbounds?.[0]?.protocol).toBe("vless");
    expect(built.config.inbounds?.[0]?.streamSettings).toMatchObject({
      network: "tcp",
      security: "reality",
      realitySettings: {
        privateKey: key32,
        serverNames: ["www.example.com"],
        shortIds: ["a1b2c3d4"]
      }
    });
  });

  it("builds, imports, and links VMess WS TLS inbounds", () => {
    const profile = vmessProfile();
    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });

    expect(built.issues.some((issue) => issue.code === "XCK_COMPAT_VMESS_DEPRECATED")).toBe(true);
    expect(built.config.inbounds?.[0]).toMatchObject({
      protocol: "vmess",
      settings: {
        clients: [
          {
            id: "22222222-2222-4222-8222-222222222222",
            security: "auto",
            email: "bob"
          }
        ]
      },
      streamSettings: {
        network: "ws",
        security: "tls",
        wsSettings: {
          path: "/ray",
          host: "edge.example.com"
        }
      }
    });

    const imported = importXrayConfig({
      inbounds: built.config.inbounds,
      outbounds: built.config.outbounds
    });
    expect(imported.profile.inbounds[0]?.protocol).toBe("vmess");

    const link = generateClientLink(profile, {
      inboundTag: "vmess-ws",
      clientId: "bob",
      host: "edge.example.com"
    });
    expect(link.startsWith("vmess://")).toBe(true);
    const payload = JSON.parse(Buffer.from(link.slice("vmess://".length), "base64").toString("utf8"));
    expect(payload).toMatchObject({
      v: "2",
      ps: "bob",
      add: "edge.example.com",
      port: 8443,
      id: "22222222-2222-4222-8222-222222222222",
      scy: "auto",
      net: "ws",
      tls: "tls",
      path: "/ray",
      host: "edge.example.com",
      sni: "edge.example.com",
      fp: "chrome",
      alpn: "h2,http/1.1"
    });
  });

  it("builds HTTPUpgrade links and stream settings", () => {
    const profile = createProfile({
      inbounds: [
        {
          kind: "inbound",
          protocol: "vless",
          tag: "vless-httpupgrade",
          listen: "0.0.0.0",
          port: 443,
          clients: [{ protocol: "vless", id: "33333333-3333-4333-8333-333333333333", email: "carol" }],
          security: { type: "tls", serverName: "edge.example.com" },
          transport: {
            type: "httpupgrade",
            path: "/upgrade",
            host: "edge.example.com",
            headers: { "X-Test": "1" },
            acceptProxyProtocol: true
          }
        }
      ]
    });

    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.config.inbounds?.[0]?.streamSettings).toMatchObject({
      network: "httpupgrade",
      httpupgradeSettings: {
        path: "/upgrade",
        host: "edge.example.com",
        acceptProxyProtocol: true
      }
    });

    const link = generateVlessLink(profile, {
      inboundTag: "vless-httpupgrade",
      clientId: "carol",
      host: "edge.example.com"
    });
    expect(link).toContain("type=httpupgrade");
    expect(link).toContain("path=%2Fupgrade");
    expect(link).toContain("host=edge.example.com");
  });

  it("builds HTTP and Mixed inbounds and warns for public unauthenticated proxies", () => {
    const profile = createProfile({
      inbounds: [
        {
          kind: "inbound",
          protocol: "http",
          tag: "http-public",
          listen: "0.0.0.0",
          port: 8080
        },
        {
          kind: "inbound",
          protocol: "mixed",
          tag: "mixed-public",
          listen: "0.0.0.0",
          port: 1080,
          auth: "noauth",
          udp: true
        },
        {
          kind: "inbound",
          protocol: "socks",
          tag: "socks-public",
          listen: "0.0.0.0",
          port: 1081,
          auth: "noauth",
          udp: true
        }
      ]
    });

    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.config.inbounds?.[0]).toMatchObject({ protocol: "http", settings: {} });
    expect(built.config.inbounds?.[1]).toMatchObject({ protocol: "mixed", settings: { auth: "noauth", udp: true } });
    expect(built.config.inbounds?.[2]).toMatchObject({ protocol: "socks", settings: { auth: "noauth", udp: true } });

    const analysis = analyzeProfile(profile);
    expect(analysis.issues.filter((issue) => issue.code === "XCK_SECURITY_PUBLIC_UNAUTHENTICATED_PROXY")).toHaveLength(3);
  });

  it("builds/imports WireGuard inbounds and exports peer configs without implicit hostname", () => {
    const profile = createProfile({
      inbounds: [
        {
          kind: "inbound",
          protocol: "wireguard",
          tag: "wg",
          listen: "0.0.0.0",
          port: 51820,
          secretKey: key32,
          publicKey: key32,
          address: ["10.0.0.1/24"],
          mtu: 1420,
          noKernelTun: false,
          peers: [
            {
              publicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
              preSharedKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
              allowedIPs: ["10.0.0.2/32"],
              keepAlive: 25,
              meta: { privateKey: "client-private-key" }
            }
          ]
        }
      ]
    });

    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.config.inbounds?.[0]).toMatchObject({
      protocol: "wireguard",
      settings: {
        secretKey: key32,
        peers: [
          {
            publicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            preSharedKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            allowedIPs: ["10.0.0.2/32"]
          }
        ]
      }
    });
    expect(JSON.stringify(built.config)).not.toContain("client-private-key");

    const imported = importXrayConfig({ inbounds: built.config.inbounds });
    expect(imported.profile.inbounds[0]?.protocol).toBe("wireguard");

    const wg = generateWireGuardConfig(profile, {
      inboundTag: "wg",
      peerPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      endpointHost: "vpn.example.com",
      clientPrivateKey: "client-private-key",
      clientAddress: "10.0.0.2/32",
      dns: ["1.1.1.1"],
      remark: "alice"
    });
    expect(wg).toContain("Endpoint = vpn.example.com:51820");
    expect(wg).toContain("PrivateKey = client-private-key");
    expect(wg).toContain("PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  });

  it("builds and imports Hysteria, TUN, Dokodemo, and typed proxy outbounds", () => {
    const profile = createProfile({
      inbounds: [
        {
          kind: "inbound",
          protocol: "hysteria",
          tag: "hy2",
          listen: "0.0.0.0",
          port: 8443,
          version: 2,
          clients: [{ protocol: "hysteria", auth: "strong-hysteria-auth", email: "hy-user" }],
          security: { type: "tls", serverName: "hy.example.com" },
          transport: {
            type: "hysteria",
            version: 2,
            auth: "transport-auth",
            udpIdleTimeout: 60,
            masquerade: {
              type: "string",
              content: "ok",
              statusCode: 200
            }
          },
          streamAdvanced: {
            quicParams: {
              congestion: "bbr",
              brutalUp: "10mbps",
              brutalDown: "20mbps"
            }
          }
        },
        {
          kind: "inbound",
          protocol: "tun",
          tag: "tun0",
          name: "xray0",
          mtu: 1500,
          gateway: ["198.18.0.1/15"],
          dns: ["1.1.1.1"],
          autoOutboundsInterface: "auto"
        },
        {
          kind: "inbound",
          protocol: "dokodemo-door",
          tag: "dokodemo",
          listen: "127.0.0.1",
          port: 10080,
          address: "example.com",
          targetPort: 443,
          network: "tcp"
        }
      ],
      outbounds: [
        {
          protocol: "hysteria",
          tag: "hy-out",
          settings: {
            version: 2,
            address: "hy.example.com",
            port: 8443
          },
          streamSettings: {
            network: "hysteria",
            security: "tls",
            tlsSettings: { serverName: "hy.example.com" },
            hysteriaSettings: { version: 2, auth: "transport-auth" }
          }
        }
      ]
    });

    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.inbounds?.[0]?.streamSettings).toMatchObject({
      network: "hysteria",
      hysteriaSettings: {
        version: 2,
        auth: "transport-auth",
        udpIdleTimeout: 60
      },
      finalmask: {
        quicParams: {
          congestion: "bbr",
          brutalUp: "10mbps",
          brutalDown: "20mbps"
        }
      }
    });
    expect(built.config.inbounds?.[1]).toMatchObject({
      protocol: "tun",
      settings: {
        name: "xray0",
        mtu: 1500
      }
    });
    expect(built.config.inbounds?.[1]).not.toHaveProperty("port");
    expect(built.config.inbounds?.[2]).toMatchObject({
      protocol: "dokodemo-door",
      settings: {
        address: "example.com",
        port: 443,
        network: "tcp"
      }
    });
    expect(built.config.outbounds?.[0]).toMatchObject({
      protocol: "hysteria",
      streamSettings: {
        network: "hysteria"
      }
    });

    const imported = importXrayConfig({ inbounds: built.config.inbounds, outbounds: built.config.outbounds });
    expect(imported.profile.inbounds.map((inbound) => inbound.protocol)).toEqual(["hysteria", "tun", "dokodemo-door"]);
    expect(imported.profile.outbounds?.some((outbound) => outbound.protocol === "hysteria")).toBe(true);
  });

  it("generates Shadowsocks 2022 links with server and client passwords", () => {
    const profile = createProfile({
      inbounds: [
        {
          kind: "inbound",
          protocol: "shadowsocks",
          tag: "ss2022",
          listen: "0.0.0.0",
          port: 8388,
          method: "2022-blake3-aes-256-gcm",
          password: "server-password",
          network: "tcp,udp",
          clients: [{ protocol: "shadowsocks", password: "client-password", email: "erin" }],
          security: { type: "tls", serverName: "ss.example.com" },
          transport: { type: "ws", path: "/ss", host: "ss.example.com" }
        }
      ]
    });

    const link = generateShadowsocksLink(profile, {
      inboundTag: "ss2022",
      clientId: "erin",
      host: "ss.example.com"
    });
    const encodedUserInfo = link.slice("ss://".length).split("@")[0]!;
    expect(Buffer.from(encodedUserInfo, "base64").toString("utf8")).toBe("2022-blake3-aes-256-gcm:server-password:client-password");
    expect(link).toContain("type=ws");
    expect(link).toContain("security=tls");
    expect(link).toContain("path=%2Fss");
  });

  it("validates adapter compatibility for REALITY transports", () => {
    const profile = realityProfile();
    const inbound = profile.inbounds[0];

    expect(inbound?.protocol).toBe("vless");
    if (!inbound || inbound.protocol !== "vless") return;

    const invalid = createProfile({
      inbounds: [
        {
          ...inbound,
          transport: { type: "ws", path: "/ws" }
        }
      ]
    });

    const validation = validateProfile(invalid, { xrayVersion: latestGeneratedRelease.version });

    expect(validation.ok).toBe(false);
    expect(validation.issues.some((issue) => issue.code === "XCK_COMPAT_REALITY_TRANSPORT")).toBe(true);
  });

  it("blocks unsafe raw patches in strict validation", () => {
    const profile = createProfile({
      raw: {
        patches: [
          {
            op: "add",
            path: "/api",
            value: { tag: "api" },
            unsafe: true
          }
        ]
      }
    });

    const validation = validateProfile(profile);

    expect(validation.ok).toBe(false);
    expect(validation.issues.some((issue) => issue.code === "XCK_RAW_UNSAFE_PATCH")).toBe(true);
  });

  it("imports configs without losing unknown top-level sections or unsupported inbounds", () => {
    const imported = importXrayConfig({
      log: { loglevel: "warning" },
      inbounds: [
        {
          tag: "unknown",
          protocol: "made-up",
          listen: "0.0.0.0",
          port: 8080,
          settings: {}
        }
      ],
      outbounds: [{ tag: "direct", protocol: "freedom", settings: {} }],
      customSection: { enabled: true }
    });

    expect(imported.unmanaged).toBe(1);
    expect(imported.profile.unknown?.pointers["/customSection"]).toEqual({ enabled: true });

    const rebuilt = buildXrayConfig(imported.profile, { preserveUnknown: true, mode: "permissive" });
    expect(rebuilt.config.customSection).toEqual({ enabled: true });
    expect(rebuilt.config.inbounds?.[0]?.protocol).toBe("made-up");
  });

  it("generates client links and subscriptions without leaking REALITY privateKey", () => {
    const profile = realityProfile();
    const link = generateClientLink(profile, {
      inboundTag: "vless-reality",
      clientId: "alice",
      host: "edge.example.com"
    });

    expect(link).toContain("vless://11111111-1111-4111-8111-111111111111@edge.example.com:443");
    expect(link).toContain("pbk=");
    expect(link).not.toContain("privateKey");

    const subscription = generateSubscription(profile, {
      format: "links",
      clients: ["alice"],
      host: "edge.example.com"
    });

    expect(subscription.entries).toBe(1);
    expect(subscription.content).toBe(link);
  });

  it("exports capabilities, JSON Schema, analysis warnings, and diffs", () => {
    const capabilities = getCapabilities({ xrayVersion: latestGeneratedRelease.version });
    expect(capabilities.protocols).toContain("vmess");
    expect(capabilities.protocols).toContain("wireguard");
    expect(capabilities.protocols).toContain("hysteria");
    expect(capabilities.protocols).toContain("tun");
    expect(capabilities.transports).toContain("xhttp");
    expect(capabilities.transports).toContain("httpupgrade");
    expect(capabilities.transports).toContain("hysteria");
    expect(capabilities.transports).not.toContain("quic");
    expect(capabilities.compatibilityMatrix.quic?.supported).toBe(false);

    const xray25 = getCapabilities({ xrayVersion: "25.10.15" });
    const xray25Release = getXrayParityRelease({ xrayVersion: "25.10.15" });
    expect(xray25.adapterId).toBe("xray@25.10");
    expect(xray25.transports).toEqual(Object.keys(xray25Release.transportAliases).sort());
    expect(xray25.compatibilityMatrix).toMatchObject(
      Object.fromEntries(Object.keys(xray25Release.transportAliases).map((transport) => [transport, { supported: true }]))
    );

    const formCapabilities = getInboundFormCapabilities({ xrayVersion: latestGeneratedRelease.version });
    expect(formCapabilities.clientLinks).toMatchObject({ vless: true, wireguard: true, hysteria: false });
    const draft = createDefaultInbound({ protocol: "vless", port: 443, transport: "xhttp", security: "reality" });
    expect(getInboundFieldVisibility(draft, formCapabilities)).toMatchObject({
      clients: true,
      stream: true,
      reality: true
    });

    const schema = getProfileJsonSchema();
    expect(schema).toMatchObject({ $schema: "http://json-schema.org/draft-07/schema#" });

    const analysis = analyzeProfile(realityProfile());
    expect(analysis.issues.some((issue) => issue.code === "XCK_SECURITY_PLAIN_PUBLIC_DNS")).toBe(true);

    const diff = diffConfigs({ a: 1, b: 2 }, { a: 1, b: 3, c: 4 });
    expect(diff).toEqual([
      { op: "changed", path: "/b", before: 2, after: 3 },
      { op: "added", path: "/c", after: 4 }
    ]);
  });

  it("rejects unsupported stream defaults on local proxy inbounds", () => {
    const createUnsafeDefaultInbound = (options: unknown) => createDefaultInbound(options as Parameters<typeof createDefaultInbound>[0]);

    expect(() => createUnsafeDefaultInbound({ protocol: "mixed", security: "reality" }))
      .toThrow("mixed default inbound does not support stream security options.");
    expect(() => createUnsafeDefaultInbound({ protocol: "mixed", transport: "tcp" }))
      .toThrow("mixed default inbound does not support transport options.");
    expect(() => createUnsafeDefaultInbound({ protocol: "vmess", security: "reality" }))
      .toThrow("VMess default inbound supports only none or TLS security.");
    expect(() => createUnsafeDefaultInbound({ protocol: "shadowsocks", clientDefaults: "empty" }))
      .toThrow("shadowsocks default inbound requires a port.");
  });

  it("can create panel drafts with empty client arrays", () => {
    const defaultDraft = createDefaultInbound({ protocol: "vless", port: 443, transport: "tcp", security: "reality" });
    const panelDraft = createDefaultInbound({
      protocol: "vless",
      port: 443,
      transport: "tcp",
      security: "reality",
      clientDefaults: "empty"
    });
    const shadowsocksPanelDraft = createDefaultInbound({ protocol: "shadowsocks", port: 1080, clientDefaults: "empty" });

    expect(defaultDraft.clients).toHaveLength(1);
    expect(panelDraft.clients).toEqual([]);
    expect(shadowsocksPanelDraft.clients).toEqual([]);
  });

  it("builds minimal Shadowsocks drafts with default policy controls", () => {
    const profile = createProfile({
      log: { loglevel: "info" },
      inbounds: [
        createDefaultInbound({
          protocol: "shadowsocks",
          tag: "Shadowsocks TCP",
          port: 1080,
          clientDefaults: "empty"
        })
      ]
    });

    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.policy).toEqual({ levels: { "0": { statsUserOnline: true } } });
    expect(built.config.inbounds?.[0]).toMatchObject({
      tag: "Shadowsocks TCP",
      listen: "0.0.0.0",
      port: 1080,
      protocol: "shadowsocks",
      settings: {
        clients: [],
        network: "tcp,udp"
      }
    });
    expect(built.config.inbounds?.[0]?.settings).not.toHaveProperty("method");
    expect(built.config.inbounds?.[0]?.settings).not.toHaveProperty("password");

    const withoutPolicy = buildXrayConfig(createProfile({ includeDefaultPolicy: false }));
    expect(withoutPolicy.config.policy).toBeUndefined();
  });
});
