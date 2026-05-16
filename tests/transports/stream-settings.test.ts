import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, validateStrictXrayConfig } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

function inboundWithStream(streamSettings: JsonObject): JsonObject {
  return {
    inbounds: [
      {
        protocol: "vless",
        tag: "vless",
        port: 443,
        settings: { clients: [], decryption: "none" },
        streamSettings
      }
    ]
  };
}

describe("xray stream transport settings parity", () => {
  it("accepts representative settings objects for every stream transport family", () => {
    const cases: readonly JsonObject[] = [
      {
        network: "tcp",
        security: "none",
        tcpSettings: { acceptProxyProtocol: true, header: {} }
      },
      {
        network: "raw",
        security: "none",
        rawSettings: { acceptProxyProtocol: false, header: {} }
      },
      {
        network: "grpc",
        security: "none",
        grpcSettings: {
          authority: "example.com",
          serviceName: "svc",
          multiMode: true,
          idle_timeout: 60,
          health_check_timeout: 20,
          permit_without_stream: true,
          initial_windows_size: 65535,
          user_agent: "@pasarguard/xray-config-kit"
        }
      },
      {
        network: "xhttp",
        security: "none",
        xhttpSettings: {
          host: "example.com",
          path: "/x",
          mode: "auto",
          headers: { Host: "example.com" },
          xPaddingBytes: "1-10",
          xPaddingObfsMode: true,
          xPaddingKey: "k",
          xPaddingHeader: "X-Padding",
          xPaddingPlacement: "header",
          xPaddingMethod: "repeat-x",
          uplinkHTTPMethod: "POST",
          sessionPlacement: "cookie",
          sessionKey: "sid",
          seqPlacement: "query",
          seqKey: "seq",
          uplinkDataPlacement: "body",
          uplinkDataKey: "data",
          uplinkChunkSize: "1024-2048",
          noGRPCHeader: false,
          noSSEHeader: false,
          scMaxEachPostBytes: "1024-4096",
          scMinPostsIntervalMs: "10-20",
          scMaxBufferedPosts: 4,
          scStreamUpServerSecs: "1-2",
          serverMaxHeaderBytes: 8192,
          xmux: {},
          downloadSettings: { network: "tcp", security: "none" },
          extra: {}
        }
      },
      {
        network: "splithttp",
        security: "none",
        splithttpSettings: { host: "example.com", path: "/split", mode: "stream-up" }
      },
      {
        network: "ws",
        security: "none",
        wsSettings: {
          host: "example.com",
          path: "/ws",
          headers: { Host: "example.com" },
          acceptProxyProtocol: true,
          heartbeatPeriod: 30
        }
      },
      {
        network: "httpupgrade",
        security: "none",
        httpupgradeSettings: {
          host: "example.com",
          path: "/up",
          headers: { Host: "example.com" },
          acceptProxyProtocol: true
        }
      },
      {
        network: "mkcp",
        security: "none",
        kcpSettings: {
          mtu: 1350,
          tti: 20,
          uplinkCapacity: 10,
          downlinkCapacity: 50,
          cwndMultiplier: 2,
          maxSendingWindow: 1024,
          header: {},
          seed: "seed"
        }
      },
      {
        network: "hysteria",
        security: "none",
        hysteriaSettings: {
          version: 2,
          auth: "secret",
          congestion: "bbr",
          udpIdleTimeout: 60,
          masquerade: {}
        }
      }
    ];

    for (const streamSettings of cases) {
      const result = validateStrictXrayConfig(inboundWithStream(streamSettings), { releaseTag: latestGeneratedRelease.tag });
      expect(result.ok, `${streamSettings.network}: ${result.issues.map((issue) => issue.message).join("; ")}`).toBe(true);
    }
  });

  it("rejects unknown fields inside every nested stream struct captured by the manifest", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    const streamStructFields = release.streamFields.filter((field) => {
      const typeName = field.type.replace(/^\*/, "").replace(/^\[\]\*/, "").replace(/^\[\]/, "").split(".").pop();
      return typeName !== undefined && release.structs[typeName] !== undefined;
    });

    for (const field of streamStructFields) {
      const result = validateStrictXrayConfig(inboundWithStream({
        network: "tcp",
        security: "none",
        [field.json]: {
          notFromXray: true
        }
      }), { releaseTag: release.tag });

      expect(result.ok, field.json).toBe(false);
      expect(result.issues.map((issue) => issue.path), field.json).toContain(`/inbounds/1/streamSettings/${field.json}/notFromXray`);
    }
  });
});
