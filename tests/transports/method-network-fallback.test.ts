import { describe, expect, it } from "bun:test";
import { buildXrayConfig, generateUriFromXrayOutbound, importXrayConfig } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("streamSettings.method / streamSettings.network fallback", () => {
  it("importXrayConfig reads the transport type from method when network is absent", () => {
    const imported = importXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless-method",
          port: 443,
          settings: { clients: [{ id: "11111111-1111-4111-8111-111111111111" }], decryption: "none" },
          streamSettings: {
            method: "xhttp",
            security: "none",
            xhttpSettings: { path: "/x", mode: "auto" }
          }
        }
      ]
    });

    expect(imported.profile.inbounds[0]?.transport?.type).toBe("xhttp");
  });

  it("importXrayConfig prefers method over network when both are present, matching Xray-core priority", () => {
    const imported = importXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless-both",
          port: 443,
          settings: { clients: [{ id: "11111111-1111-4111-8111-111111111111" }], decryption: "none" },
          streamSettings: {
            method: "ws",
            network: "grpc",
            security: "none",
            wsSettings: { path: "/ray" }
          }
        }
      ]
    });

    expect(imported.profile.inbounds[0]?.transport?.type).toBe("ws");
  });

  it("does not reintroduce a legacy network key when the source already declares method", () => {
    const raw = {
      inbounds: [
        {
          protocol: "vless",
          tag: "vless-method",
          port: 443,
          settings: { clients: [{ id: "11111111-1111-4111-8111-111111111111" }], decryption: "none" },
          streamSettings: {
            method: "tcp",
            security: "none",
            tcpSettings: {}
          }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    const built = buildXrayConfig(imported.profile, { xrayVersion: latestGeneratedRelease.version });
    const streamSettings = built.config.inbounds?.[0]?.streamSettings as JsonObject | undefined;

    expect(streamSettings?.method).toBe("tcp");
    expect(streamSettings?.network).toBeUndefined();
  });

  it("generates VMess URIs from outbound JSON using method instead of network", () => {
    const outbound: JsonObject = {
      protocol: "vmess",
      tag: "bob",
      settings: {
        vnext: [
          {
            address: "edge.example.com",
            port: 8443,
            users: [{ id: "22222222-2222-4222-8222-222222222222", alterId: 0, security: "auto" }]
          }
        ]
      },
      streamSettings: {
        method: "ws",
        security: "none",
        wsSettings: { path: "/ray", host: "edge.example.com" }
      }
    };

    const uri = generateUriFromXrayOutbound(outbound);
    const payload = JSON.parse(Buffer.from(uri.slice("vmess://".length), "base64").toString("utf8"));
    expect(payload).toMatchObject({ net: "ws", path: "/ray", host: "edge.example.com" });
  });

  it("generates VLESS URIs from outbound JSON using method instead of network", () => {
    const outbound: JsonObject = {
      protocol: "vless",
      tag: "alice",
      settings: {
        vnext: [
          {
            address: "edge.example.com",
            port: 443,
            users: [{ id: "11111111-1111-4111-8111-111111111111", encryption: "none" }]
          }
        ]
      },
      streamSettings: {
        method: "grpc",
        security: "none",
        grpcSettings: { serviceName: "svc" }
      }
    };

    const uri = generateUriFromXrayOutbound(outbound);
    expect(uri).toContain("type=grpc");
    expect(uri).toContain("serviceName=svc");
  });
});
