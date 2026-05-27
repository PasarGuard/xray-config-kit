import { describe, expect, it } from "bun:test";
import {
  createDefaultVlessOptions,
  createWireGuardCoreConfigJson,
  DEFAULT_VLESS_ENCRYPTION,
  DEFAULT_VLESS_HANDSHAKE,
  DEFAULT_VLESS_PADDING,
  DEFAULT_VLESS_RESUME,
  DEFAULT_VLESS_SERVER_TICKET,
  defaultXrayConfig,
  generateCoreConfigTemplate,
  generateMldsa65,
  generateRealityKeyPair,
  generateShadowsocksPassword,
  generateShortId,
  generateVlessEncryption,
  generateWireGuardKeyPair,
  getWireGuardPublicKey,
  SHADOWSOCKS_ENCRYPTION_METHODS
} from "../../src/index.js";

function base64ByteLength(input: string): number {
  return Buffer.from(input, "base64").byteLength;
}

describe("core config generators", () => {
  it("keeps the core modal default Xray template shape", () => {
    expect(JSON.parse(defaultXrayConfig)).toEqual({
      policy: {
        levels: {
          "0": {
            statsUserOnline: true
          }
        }
      },
      log: {
        loglevel: "info"
      },
      inbounds: [
        {
          tag: "Shadowsocks TCP",
          listen: "0.0.0.0",
          port: 1080,
          protocol: "shadowsocks",
          settings: {
            clients: [],
            network: "tcp,udp"
          }
        }
      ],
      outbounds: [
        {
          protocol: "freedom",
          tag: "DIRECT"
        },
        {
          protocol: "blackhole",
          tag: "BLOCK"
        }
      ],
      routing: {
        rules: [
          {
            ip: ["geoip:private"],
            outboundTag: "BLOCK",
            type: "field"
          }
        ]
      }
    });
  });

  it("generates Reality and WireGuard X25519 key formats like the dashboard", () => {
    const reality = generateRealityKeyPair();
    expect(reality.privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(reality.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const wireguard = generateWireGuardKeyPair();
    expect(base64ByteLength(wireguard.privateKey)).toBe(32);
    expect(base64ByteLength(wireguard.publicKey)).toBe(32);
    expect(getWireGuardPublicKey(wireguard.privateKey)).toBe(wireguard.publicKey);
    expect(getWireGuardPublicKey("")).toBe("");
    expect(getWireGuardPublicKey("not-base64")).toBe("");
  });

  it("generates short IDs and Shadowsocks 2022 passwords with exact lengths", () => {
    expect(generateShortId()).toMatch(/^[0-9a-f]{16}$/);

    expect(SHADOWSOCKS_ENCRYPTION_METHODS[0]?.value).toBe("chacha20-poly1305");

    const generationMethods = SHADOWSOCKS_ENCRYPTION_METHODS.filter(method => method.value === "2022-blake3-aes-128-gcm" || method.value === "2022-blake3-aes-256-gcm");
    for (const method of generationMethods) {
      const result = generateShadowsocksPassword(method.value);
      expect(result?.encryptionMethod).toBe(method.label);
      expect(base64ByteLength(result?.password ?? "")).toBe(method.length);
    }

    for (const method of SHADOWSOCKS_ENCRYPTION_METHODS.filter(method => !generationMethods.includes(method))) {
      expect(generateShadowsocksPassword(method.value)).toBeUndefined();
    }

    expect(generateShadowsocksPassword("not-a-shadowsocks-method")).toBeUndefined();
  });

  it("creates WireGuard backend templates with generated keys", () => {
    const keyPair = generateWireGuardKeyPair();
    expect(JSON.parse(createWireGuardCoreConfigJson(keyPair))).toEqual({
      interface_name: "wg0",
      private_key: keyPair.privateKey,
      listen_port: 51820,
      address: ["10.0.0.1/8"]
    });

    const template = generateCoreConfigTemplate("wg");
    expect(template.wireGuardKeyPair).toBeDefined();
    expect(JSON.parse(template.config)).toMatchObject({
      interface_name: "wg0",
      listen_port: 51820,
      address: ["10.0.0.1/8"]
    });

    expect(generateCoreConfigTemplate("xray").config).toBe(defaultXrayConfig);
    expect(generateCoreConfigTemplate("singbox").config).toBe(defaultXrayConfig);
  });

  it("generates VLESS encryption strings using modal defaults and padding behavior", async () => {
    expect(createDefaultVlessOptions()).toEqual({
      handshakeMethod: DEFAULT_VLESS_HANDSHAKE,
      encryptionMethod: DEFAULT_VLESS_ENCRYPTION,
      serverTicket: DEFAULT_VLESS_SERVER_TICKET,
      clientTicket: DEFAULT_VLESS_RESUME,
      serverPadding: DEFAULT_VLESS_PADDING,
      clientPadding: DEFAULT_VLESS_PADDING,
      includeServerPadding: false,
      includeClientPadding: false
    });

    const result = await generateVlessEncryption({
      handshakeMethod: " ",
      encryptionMethod: "",
      serverTicket: "",
      clientTicket: "",
      serverPadding: " one . . two ",
      clientPadding: " three.four ",
      includeServerPadding: true,
      includeClientPadding: true
    });

    expect(result.x25519.decryption).toMatch(/^mlkem768x25519plus\.native\.600s\.one\.two\.[A-Za-z0-9_-]{43}$/);
    expect(result.x25519.encryption).toMatch(/^mlkem768x25519plus\.native\.0rtt\.three\.four\.[A-Za-z0-9_-]{43}$/);
    expect(result.mlkem768.decryption).toMatch(/^mlkem768x25519plus\.native\.600s\.one\.two\.[A-Za-z0-9_-]{86}$/);
    expect(result.mlkem768.encryption).toMatch(/^mlkem768x25519plus\.native\.0rtt\.three\.four\.[A-Za-z0-9_-]+$/);
  });

  it("keeps ML-DSA-65 generation browser-only like the dashboard utility", async () => {
    await expect(generateMldsa65()).rejects.toThrow("ML-DSA-65 generation requires a browser environment");
  });
});
