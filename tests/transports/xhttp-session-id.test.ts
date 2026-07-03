import { describe, expect, it } from "bun:test";
import { buildXrayConfig, importXrayConfig } from "../../src/index.js";
import type { Profile } from "../../src/index.js";
import { xhttpTransportSchema } from "../../src/schemas/index.js";

function profileWithXhttp(extra: Record<string, unknown>): Profile {
  return {
    inbounds: [
      {
        kind: "inbound",
        protocol: "vless",
        tag: "vless",
        port: 443,
        clients: [{ protocol: "vless", id: "11111111-1111-4111-8111-111111111111" }],
        decryption: "none",
        security: { type: "none" },
        transport: {
          type: "xhttp",
          path: "/x",
          extra
        }
      }
    ]
  } as unknown as Profile;
}

describe("xhttp sessionID* fields", () => {
  it("accepts sessionIDPlacement, sessionIDKey, sessionIDTable, and sessionIDLength in the schema", () => {
    const result = xhttpTransportSchema.safeParse({
      type: "xhttp",
      path: "/x",
      extra: {
        sessionIDPlacement: "cookie",
        sessionIDKey: "sid",
        sessionIDTable: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        sessionIDLength: "8-16"
      }
    });

    expect(result.success).toBe(true);
  });

  it("compiles sessionID* extra fields to the xhttpSettings JSON", () => {
    const built = buildXrayConfig(profileWithXhttp({
      sessionIDPlacement: "cookie",
      sessionIDKey: "sid",
      sessionIDTable: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      sessionIDLength: "8-16"
    }));

    const xhttpSettings = (built.config.inbounds?.[0]?.streamSettings as { xhttpSettings?: Record<string, unknown> } | undefined)?.xhttpSettings;
    expect(xhttpSettings?.sessionIDPlacement).toBe("cookie");
    expect(xhttpSettings?.sessionIDKey).toBe("sid");
    expect(xhttpSettings?.sessionIDTable).toBe("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    expect(xhttpSettings?.sessionIDLength).toBe("8-16");
  });

  it("imports sessionID* fields from raw xhttpSettings JSON back into transport.extra", () => {
    const result = importXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            network: "xhttp",
            security: "none",
            xhttpSettings: {
              path: "/x",
              sessionIDPlacement: "header",
              sessionIDKey: "sid",
              sessionIDTable: "0123456789abcdef",
              sessionIDLength: "4-8"
            }
          }
        }
      ]
    });

    const transport = (result.profile?.inbounds?.[0] as { transport?: { extra?: Record<string, unknown> } } | undefined)?.transport;
    expect(transport?.extra?.sessionIDPlacement).toBe("header");
    expect(transport?.extra?.sessionIDKey).toBe("sid");
    expect(transport?.extra?.sessionIDTable).toBe("0123456789abcdef");
    expect(transport?.extra?.sessionIDLength).toBe("4-8");
  });
});
