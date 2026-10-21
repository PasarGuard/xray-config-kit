import { describe, expect, it } from "bun:test";
import { createDefaultOutbound, validateInboundDraft, validateOutboundDraft } from "../../src/index.js";
import type { Inbound, Issue, JsonObject, MuxSettings, Outbound, ProxyOutboundProtocol, StreamSettings, VlessInbound } from "../../src/index.js";
import { vlessEncryptionPair } from "../helpers/vless-encryption.js";

const { decryption, encryption } = vlessEncryptionPair;
const id = "27848739-7e62-4138-9fd3-098a63964b6b";
const xdriveTransport = { type: "xdrive", service: "local", remoteFolder: "/var/lib/xray/xdrive" } as const;

const xdriveRows = (issues: Issue[]) => issues.map((issue) => `${issue.severity} ${issue.code} ${issue.path}`).filter((row) => row.includes("XDRIVE"));
const inboundRows = (inbound: Inbound) => xdriveRows(validateInboundDraft(inbound));
const outboundRows = (outbound: Outbound) => xdriveRows(validateOutboundDraft(outbound));

const vlessInbound = (overrides: Partial<VlessInbound> = {}): Inbound => ({
  kind: "inbound",
  protocol: "vless",
  tag: "vless-xdrive",
  port: 443,
  clients: [{ protocol: "vless", id, email: "alice" }],
  security: { type: "tls", serverName: "drive.example.com" },
  decryption,
  transport: xdriveTransport,
  ...overrides
});

const stream: StreamSettings = {
  network: "xdrive",
  security: "tls",
  tlsSettings: { serverName: "www.googleapis.com" },
  xdriveSettings: { service: "Google Drive", remoteFolder: "1AbCdEf", secrets: ["id", "secret", "refresh"] }
};
const flat = { address: "www.googleapis.com", port: 443, id, encryption };
const vnext = (user: JsonObject) => ({ vnext: [{ address: "www.googleapis.com", port: 443, users: [{ id, encryption, ...user }] }] });
const mux: MuxSettings = { enabled: true };
const outbound = (settings: JsonObject, muxSettings: MuxSettings | undefined, protocol: ProxyOutboundProtocol = "vless", streamSettings = stream) =>
  createDefaultOutbound({ protocol, tag: "drive-out", settings, streamSettings, mux: muxSettings });

describe("XDrive VLESS rules (Xray validateXDrive)", () => {
  describe("inbounds", () => {
    it("accepts a VLESS XDrive inbound with VLESS Encryption, no flow and one port", () => {
      expect(inboundRows(vlessInbound())).toEqual([]);
      expect(validateInboundDraft(vlessInbound()).filter((issue) => issue.severity === "error")).toEqual([]);
    });

    it("keeps the xdrive transport on VLESS", () => {
      const others: Inbound[] = [
        { kind: "inbound", protocol: "vmess", tag: "vmess-xdrive", port: 443, clients: [{ protocol: "vmess", id }], security: { type: "none" }, transport: xdriveTransport },
        { kind: "inbound", protocol: "trojan", tag: "trojan-xdrive", port: 443, clients: [{ protocol: "trojan", password: "trojan-password-1" }], security: { type: "tls", serverName: "drive.example.com" }, transport: xdriveTransport },
        { kind: "inbound", protocol: "shadowsocks", tag: "ss-xdrive", port: 443, method: "aes-256-gcm", password: "shadowsocks-password-1", clients: [], transport: xdriveTransport }
      ];
      for (const inbound of others) {
        expect(inboundRows(inbound)).toEqual(["error XCK_SEMANTIC_XDRIVE_PROTOCOL /transport/type"]);
      }
      expect(validateInboundDraft(others[0]!).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_PROTOCOL")?.message)
        .toBe("The xdrive transport can only be used by VLESS.");
      // Only the transport the stream runs counts.
      expect(inboundRows({ ...others[0]!, transport: { type: "tcp" } } as Inbound)).toEqual([]);
    });

    it("needs VLESS decryption", () => {
      expect(inboundRows(vlessInbound({ decryption: "none" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /decryption"]);
      // A missing decryption compiles to "none".
      expect(inboundRows(vlessInbound({ decryption: undefined }))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /decryption"]);
      // An empty decryption fails Xray's VLESS build before validateXDrive runs.
      expect(inboundRows(vlessInbound({ decryption: "" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /decryption"]);
      expect(validateInboundDraft(vlessInbound({ decryption: "none" })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION")?.message)
        .toBe('The xdrive transport needs VLESS "decryption"; run "xray vlessenc" to get one.');
    });

    it("rejects VLESS flow on clients and on the inbound", () => {
      const visionClient = { protocol: "vless", id, email: "alice", flow: "xtls-rprx-vision" } as const;
      expect(inboundRows(vlessInbound({ clients: [visionClient] }))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_FLOW /clients/0/flow"]);
      // Disabled clients are not compiled, so their flow never reaches Xray.
      expect(inboundRows(vlessInbound({ clients: [{ ...visionClient, enabled: false }] }))).toEqual([]);
      // The inbound flow is the default for every client without its own.
      expect(inboundRows(vlessInbound({ flow: "xtls-rprx-vision" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_FLOW /flow"]);
      expect(inboundRows(vlessInbound({ flow: "xtls-rprx-vision", clients: [] }))).toEqual([]);
      expect(validateInboundDraft(vlessInbound({ clients: [visionClient] })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_VLESS_FLOW")?.message)
        .toBe('The xdrive transport does not support VLESS "flow".');
    });

    it("listens on exactly one port", () => {
      expect(inboundRows(vlessInbound({ port: "10800-10803" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_SINGLE_PORT /port"]);
      expect(inboundRows(vlessInbound({ port: "443,8443" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_SINGLE_PORT /port"]);
      expect(validateInboundDraft(vlessInbound({ port: "10800-10803" })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_SINGLE_PORT")?.message)
        .toBe("The xdrive transport can only listen on one port.");
      expect(inboundRows(vlessInbound({ port: "8443" }))).toEqual([]);
      expect(inboundRows(vlessInbound({ port: "8443-8443" }))).toEqual([]);
      // Xray skips empty segments; a list that does not parse is left to XCK_SEMANTIC_INVALID_PORT.
      expect(inboundRows(vlessInbound({ port: "443," }))).toEqual([]);
      expect(inboundRows(vlessInbound({ port: "443,,8443" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_SINGLE_PORT /port"]);
      expect(inboundRows(vlessInbound({ port: "8443-8440" }))).toEqual([]);
      expect(inboundRows(vlessInbound({ port: "443,nope" }))).toEqual([]);
      // Xray cannot count an env port before it runs, and a Unix socket listener has no port list.
      expect(inboundRows(vlessInbound({ port: "env:XDRIVE_PORT" }))).toEqual([]);
      expect(inboundRows(vlessInbound({ listen: "@xdrive", port: "10800-10803" }))).toEqual([]);
      expect(inboundRows(vlessInbound({ listen: "/run/xray/xdrive.sock", port: undefined }))).toEqual([]);
    });
  });

  describe("outbounds", () => {
    it("accepts flat and vnext VLESS XDrive outbounds with VLESS Encryption and mux", () => {
      expect(outboundRows(outbound(flat, mux))).toEqual([]);
      expect(outboundRows(outbound(vnext({}), mux))).toEqual([]);
      expect(outboundRows(outbound(flat, { enabled: true, concurrency: 0, xudpConcurrency: 8, xudpProxyUDP443: "allow" }))).toEqual([]);
      expect(validateOutboundDraft(outbound(flat, mux)).filter((issue) => issue.severity === "error")).toEqual([]);
    });

    it("keeps the xdrive transport on VLESS", () => {
      expect(outboundRows(outbound({ address: "www.googleapis.com", port: 443, id }, mux, "vmess"))).toEqual(["error XCK_SEMANTIC_XDRIVE_PROTOCOL /streamSettings/network"]);
      expect(outboundRows(outbound({ address: "www.googleapis.com", port: 443, password: "trojan-password-1" }, mux, "trojan"))).toEqual(["error XCK_SEMANTIC_XDRIVE_PROTOCOL /streamSettings/network"]);
      const freedom = createDefaultOutbound({ protocol: "freedom", tag: "direct", streamSettings: stream });
      expect(outboundRows(freedom)).toEqual(["error XCK_SEMANTIC_XDRIVE_PROTOCOL /streamSettings/network"]);
      const { network: _network, ...streamWithoutNetwork } = stream;
      const methodKeyed = { ...streamWithoutNetwork, method: "xdrive" } as StreamSettings;
      expect(outboundRows(outbound({ address: "www.googleapis.com", port: 443, id }, mux, "vmess", methodKeyed))).toEqual(["error XCK_SEMANTIC_XDRIVE_PROTOCOL /streamSettings/method"]);
      expect(validateOutboundDraft(freedom).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_PROTOCOL")?.message)
        .toBe("The xdrive transport can only be used by VLESS.");
      // A stale xdriveSettings block on a stream that runs another transport is not an XDrive stream.
      expect(outboundRows(outbound({ address: "www.googleapis.com", port: 443, id }, undefined, "vmess", { ...stream, network: "tcp" }))).toEqual([]);
    });

    it("needs VLESS encryption in the flat and vnext shapes", () => {
      expect(outboundRows(outbound({ ...flat, encryption: "none" }, mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /settings/encryption"]);
      expect(outboundRows(outbound(vnext({ encryption: "none" }), mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /settings/vnext/0/users/0/encryption"]);
      // A missing or empty encryption fails Xray's VLESS build before validateXDrive runs.
      const { encryption: _encryption, ...flatWithoutEncryption } = flat;
      expect(outboundRows(outbound(flatWithoutEncryption, mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /settings/encryption"]);
      expect(outboundRows(outbound({ ...flat, encryption: "" }, mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /settings/encryption"]);
      expect(outboundRows(outbound(vnext({ encryption: "" }), mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /settings/vnext/0/users/0/encryption"]);
      expect(validateOutboundDraft(outbound({ ...flat, encryption: "none" }, mux)).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION")?.message)
        .toBe('The xdrive transport needs VLESS "encryption"; run "xray vlessenc" to get one.');
      // Xray reads the flat fields whenever settings.address is set and ignores vnext then.
      expect(outboundRows(outbound({ ...flat, ...vnext({ encryption: "none" }) }, mux))).toEqual([]);
    });

    it("rejects VLESS flow in the flat and vnext shapes", () => {
      expect(outboundRows(outbound({ ...flat, flow: "xtls-rprx-vision" }, mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_FLOW /settings/flow"]);
      expect(outboundRows(outbound(vnext({ flow: "xtls-rprx-vision" }), mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_FLOW /settings/vnext/0/users/0/flow"]);
      expect(outboundRows(outbound({ ...flat, flow: "" }, mux))).toEqual([]);
    });

    it("rejects VLESS testpre in the flat and vnext shapes", () => {
      expect(outboundRows(outbound({ ...flat, testpre: 1 }, mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_TESTPRE /settings/testpre"]);
      expect(outboundRows(outbound(vnext({ testpre: 2 }), mux))).toEqual(["error XCK_SEMANTIC_XDRIVE_VLESS_TESTPRE /settings/vnext/0/users/0/testpre"]);
      expect(validateOutboundDraft(outbound({ ...flat, testpre: 1 }, mux)).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_VLESS_TESTPRE")?.message)
        .toBe('The xdrive transport does not support VLESS "testpre".');
      expect(outboundRows(outbound({ ...flat, testpre: 0 }, mux))).toEqual([]);
    });

    it("needs mux enabled with no negative concurrency and no xudpProxyUDP443 skip", () => {
      expect(outboundRows(outbound(flat, undefined))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux"]);
      expect(outboundRows(outbound(flat, { enabled: false }))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux/enabled"]);
      expect(outboundRows(outbound(flat, { concurrency: 8 }))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux/enabled"]);
      expect(outboundRows(outbound(flat, { enabled: true, concurrency: -1 }))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux/concurrency"]);
      expect(outboundRows(outbound(flat, { enabled: true, xudpConcurrency: -1 }))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux/xudpConcurrency"]);
      expect(outboundRows(outbound(flat, { enabled: true, xudpProxyUDP443: "skip" }))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux/xudpProxyUDP443"]);
      expect(outboundRows(outbound(vnext({}), undefined))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux"]);
      expect(validateOutboundDraft(outbound(flat, undefined)).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_MUX_REQUIRED")?.message)
        .toBe('The xdrive transport needs "mux" enabled, with no negative "concurrency" or "xudpConcurrency" and no "xudpProxyUDP443": "skip".');
    });

    it("lets VLESS reverse open its own mux", () => {
      expect(outboundRows(outbound({ ...flat, reverse: { tag: "r" } }, undefined))).toEqual([]);
      expect(outboundRows(outbound({ ...flat, reverse: { tag: "r" } }, { enabled: false }))).toEqual([]);
      // Xray reads reverse only from the flat shape.
      expect(outboundRows(outbound(vnext({ reverse: { tag: "r" } }), undefined))).toEqual(["error XCK_SEMANTIC_XDRIVE_MUX_REQUIRED /mux"]);
    });
  });
});
