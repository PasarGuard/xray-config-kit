import { describe, expect, it } from "bun:test";
import {
  generateUriFromXrayJson,
  generateUriFromXrayOutbound,
  generateXrayConfigFromUri,
  generateXrayOutboundFromUri
} from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";

const uuid = "11111111-1111-4111-8111-111111111111";
const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("client URI and Xray outbound conversion", () => {
  it("parses VLESS REALITY links into Xray outbound JSON and emits them back", () => {
    const uri = [
      `vless://${uuid}@edge.example.com:443`,
      "?encryption=none",
      "&flow=xtls-rprx-vision",
      "&type=ws",
      "&path=%2Fray",
      "&host=edge.example.com",
      "&security=reality",
      "&sni=www.example.com",
      "&fp=chrome",
      `&pbk=${publicKey}`,
      "&sid=a1b2c3d4",
      "&spx=%2F",
      "#alice"
    ].join("");

    const outbound = generateXrayOutboundFromUri(uri);

    expect(outbound).toMatchObject({
      protocol: "vless",
      tag: "alice",
      settings: {
        vnext: [
          {
            address: "edge.example.com",
            port: 443,
            users: [
              {
                id: uuid,
                encryption: "none",
                flow: "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      streamSettings: {
        network: "ws",
        security: "reality",
        wsSettings: {
          path: "/ray",
          host: "edge.example.com"
        },
        realitySettings: {
          serverName: "www.example.com",
          fingerprint: "chrome",
          publicKey,
          shortId: "a1b2c3d4",
          spiderX: "/"
        }
      }
    });

    const emitted = generateUriFromXrayJson({ outbounds: [outbound] }, { remark: "alice" });
    expect(emitted).toContain(`vless://${uuid}@edge.example.com:443?`);
    expect(emitted).toContain("type=ws");
    expect(emitted).toContain("security=reality");
    expect(emitted).toContain("pbk=");
    expect(generateXrayOutboundFromUri(emitted)).toMatchObject(outbound);
  });

  it("generates Pasarguard-style VMess URI payloads from outbound JSON", () => {
    const outbound: JsonObject = {
      protocol: "vmess",
      tag: "bob",
      settings: {
        vnext: [
          {
            address: "edge.example.com",
            port: 8443,
            users: [
              {
                id: "22222222-2222-4222-8222-222222222222",
                alterId: 0,
                security: "auto"
              }
            ]
          }
        ]
      },
      streamSettings: {
        network: "ws",
        security: "tls",
        wsSettings: {
          path: "/ray",
          host: "edge.example.com"
        },
        tlsSettings: {
          serverName: "edge.example.com",
          fingerprint: "chrome",
          alpn: ["h2", "http/1.1"]
        }
      }
    };

    const uri = generateUriFromXrayOutbound(outbound);
    expect(uri.startsWith("vmess://")).toBe(true);

    const payload = JSON.parse(Buffer.from(uri.slice("vmess://".length), "base64").toString("utf8"));
    expect(payload).toMatchObject({
      add: "edge.example.com",
      aid: "0",
      host: "edge.example.com",
      id: "22222222-2222-4222-8222-222222222222",
      net: "ws",
      path: "/ray",
      port: 8443,
      ps: "bob",
      scy: "auto",
      tls: "tls",
      v: "2",
      sni: "edge.example.com",
      fp: "chrome",
      alpn: "h2,http/1.1"
    });

    expect(generateXrayOutboundFromUri(uri)).toMatchObject(outbound);
  });

  it("round-trips Shadowsocks SIP002 links with stream settings", () => {
    const userInfo = Buffer.from("2022-blake3-aes-256-gcm:server-password:client-password", "utf8").toString("base64");
    const uri = `ss://${userInfo}@ss.example.com:8388?type=ws&path=%2Fss&host=ss.example.com&security=tls&sni=ss.example.com#erin`;

    const outbound = generateXrayOutboundFromUri(uri);
    expect(outbound).toMatchObject({
      protocol: "shadowsocks",
      tag: "erin",
      settings: {
        servers: [
          {
            address: "ss.example.com",
            port: 8388,
            method: "2022-blake3-aes-256-gcm",
            password: "server-password:client-password"
          }
        ]
      },
      streamSettings: {
        network: "ws",
        security: "tls",
        wsSettings: {
          path: "/ss",
          host: "ss.example.com"
        },
        tlsSettings: {
          serverName: "ss.example.com"
        }
      }
    });

    const emitted = generateUriFromXrayOutbound(outbound, { remark: "erin" });
    const emittedUserInfo = emitted.slice("ss://".length).split("@")[0] ?? "";
    expect(Buffer.from(emittedUserInfo, "base64").toString("utf8")).toBe(
      "2022-blake3-aes-256-gcm:server-password:client-password"
    );
    expect(emitted).toContain("type=ws");
    expect(emitted).toContain("security=tls");
  });

  it("creates full outbound configs from WireGuard URIs", () => {
    const uri = [
      "wireguard://client-private@vpn.example.com:51820/",
      "?publickey=server-public",
      "&address=10.0.0.2%2F32",
      "&allowedips=0.0.0.0%2F0%2C%3A%3A%2F0",
      "&keepalive=25",
      "&reserved=1%2C2%2C3",
      "#wg-client"
    ].join("");

    const config = generateXrayConfigFromUri(uri);
    expect(config.outbounds?.[0]).toMatchObject({
      protocol: "wireguard",
      tag: "wg-client",
      settings: {
        secretKey: "client-private",
        address: ["10.0.0.2/32"],
        peers: [
          {
            endpoint: "vpn.example.com:51820",
            publicKey: "server-public",
            allowedIPs: ["0.0.0.0/0", "::/0"],
            keepAlive: 25
          }
        ],
        reserved: [1, 2, 3]
      }
    });
  });
});
