import { describe, expect, it } from "bun:test";
import { createDefaultOutbound, getOutboundFieldVisibility, validateOutboundDraft } from "../../src/index.js";
import type { CreateDefaultOutboundOptions, JsonObject, Outbound, ProxyOutbound, StreamSettings } from "../../src/index.js";
import { warpKeys } from "../helpers/masque-keys.js";
import { editOutboundAndBuild, rebuildWithoutSource } from "../helpers/profile-round-trip.js";

const out = (overrides: Partial<CreateDefaultOutboundOptions<"masque">> = {}) => createDefaultOutbound({ protocol: "masque", tag: "masque-out",
  settings: { address: "masque.example.com", port: 443 },
  streamSettings: { network: "masque", security: "tls", tlsSettings: { serverName: "masque.example.com" }, masqueSettings: { user: "alice@example.com", pass: "alice-masque-pass-1" } },
  ...overrides });
const codes = (outbound: Outbound) => validateOutboundDraft(outbound).map((issue) => `${issue.severity} ${issue.code} ${issue.path}`);

describe("MASQUE outbound", () => {
  it("round-trips a MASQUE WARP outbound", () => {
    const raw = { outbounds: [{ tag: "warp-masque", protocol: "masque", settings: { address: "162.159.198.1", port: 443, remoteDNS: ["1.1.1.1", "2606:4700:4700::1111"] },
      streamSettings: { network: "masque", security: "tls", tlsSettings: { serverName: "consumer-masque.cloudflareclient.com", alpn: ["h3"] },
        masqueSettings: { warp: { ...warpKeys(), address: ["172.16.0.2/32", "2606:4700:110:8a36::1/128"] } } } }] };
    const { imported, built } = rebuildWithoutSource(raw);
    expect(imported.unmanaged).toBe(0);
    expect(imported.profile.outbounds?.[0]?.protocol).toBe("masque");
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.outbounds).toEqual(raw.outbounds);
  });

  it("creates MASQUE outbound drafts with the masque transport and TLS and hides mux", () => {
    const draft = createDefaultOutbound({ protocol: "masque" });
    expect(draft).toMatchObject({ protocol: "masque", tag: "masque-outbound", streamSettings: { network: "masque", security: "tls", tlsSettings: {}, masqueSettings: {} } });
    expect(getOutboundFieldVisibility(draft).mux).toBe(false);
    expect(codes(draft)).toEqual(["error XCK_SEMANTIC_MASQUE_SERVER_REQUIRED /settings/address", "error XCK_SEMANTIC_MASQUE_SERVER_REQUIRED /settings/port"]);
  });

  it("accepts a configured MASQUE outbound", () => expect(codes(out())).toEqual([]));

  it("requires TLS and the masque transport", () => {
    expect(codes(out({ streamSettings: { network: "tcp", security: "none" } }))).toEqual([
      "error XCK_SEMANTIC_MASQUE_TRANSPORT_REQUIRED /streamSettings/network", "error XCK_SEMANTIC_MASQUE_TLS_REQUIRED /streamSettings/security"]);
    expect(codes(out({ streamSettings: { method: "masque", security: "tls" } as StreamSettings }))).toEqual([]);
    expect(codes(out({ streamSettings: { method: "tcp", security: "tls" } as StreamSettings }))).toEqual([
      "error XCK_SEMANTIC_MASQUE_TRANSPORT_REQUIRED /streamSettings/method"]);
  });

  it("accepts TLS security in any case, as Xray lowercases it", () => {
    expect(codes(out({ streamSettings: { network: "masque", security: "TLS", tlsSettings: { serverName: "masque.example.com" } } }))).toEqual([]);
  });

  it("requires a non-blank server address and an integer port between 1 and 65535", () => {
    const server = (settings: JsonObject) => codes(out({ settings }));
    expect(server({ address: "   ", port: 443 })).toEqual(["error XCK_SEMANTIC_MASQUE_SERVER_REQUIRED /settings/address"]);
    for (const port of [0, 65536, 443.5]) {
      expect(server({ address: "masque.example.com", port })).toEqual(["error XCK_SEMANTIC_MASQUE_SERVER_REQUIRED /settings/port"]);
    }
  });

  it("rejects mux", () => {
    expect(codes(out({ mux: { enabled: true } }))).toEqual(["error XCK_SEMANTIC_MASQUE_MUX_UNSUPPORTED /mux/enabled"]);
    expect(codes(out({ mux: { enabled: false } }))).toEqual([]);
  });

  it("requires IP remoteDNS", () => {
    expect(codes(out({ settings: { address: "masque.example.com", port: 443, remoteDNS: ["dns.google"] } }))).toEqual(["error XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID /settings/remoteDNS/0"]);
    expect(codes(out({ settings: { address: "masque.example.com", port: 443, remoteDNS: "1.1.1.1" } as JsonObject }))).toEqual(["error XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID /settings/remoteDNS"]);
  });

  it("treats a null remoteDNS as absent, as Xray loads null into []string", () => {
    const settings: JsonObject = { address: "masque.example.com", port: 443, remoteDNS: null };
    expect(codes(out({ settings }))).toEqual([]);
  });

  it("drops a remoteDNS cleared in the model on edit and keeps the other settings", () => {
    const raw = { outbounds: [{ tag: "masque-out", protocol: "masque", settings: { address: "masque.example.com", port: 443, remoteDNS: ["1.1.1.1"] },
      streamSettings: { network: "masque", security: "tls", tlsSettings: { serverName: "masque.example.com" }, masqueSettings: { user: "alice@example.com", pass: "alice-masque-pass-1" } } }] };
    const built = editOutboundAndBuild(raw, (outbound) => {
      const { remoteDNS: _cleared, ...settings } = (outbound as ProxyOutbound).settings ?? {};
      return { ...outbound, settings } as Outbound;
    });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.outbounds).toEqual([{ ...raw.outbounds[0]!, settings: { address: "masque.example.com", port: 443 } }]);
  });

  it("rejects Basic auth and WARP conflicts", () => {
    const stream = (masqueSettings: JsonObject) => out({ streamSettings: { network: "masque", security: "tls", masqueSettings } });
    expect(codes(stream({ user: "a:b" }))).toEqual(["error XCK_SEMANTIC_MASQUE_USER /streamSettings/masqueSettings/user"]);
    expect(codes(stream({ user: "u", headers: { authorization: "Bearer x" } }))).toEqual(["error XCK_SEMANTIC_MASQUE_HEADER /streamSettings/masqueSettings/headers/authorization"]);
    expect(codes(stream({ user: "u", warp: { ...warpKeys(), address: ["172.16.0.2/32"] } }))).toEqual(["error XCK_SEMANTIC_MASQUE_WARP_AUTH_CONFLICT /streamSettings/masqueSettings/warp"]);
  });

  it("validates WARP keys and addresses", () => {
    const warp = (value: JsonObject) => out({ streamSettings: { network: "masque", security: "tls", masqueSettings: { warp: value } } });
    expect(codes(warp({ privateKey: "not base64!", publicKey: "", address: [] }))).toEqual([
      "error XCK_SEMANTIC_MASQUE_WARP_KEY /streamSettings/masqueSettings/warp/privateKey",
      "error XCK_SEMANTIC_MASQUE_WARP_KEY /streamSettings/masqueSettings/warp/publicKey",
      "error XCK_SEMANTIC_MASQUE_WARP_ADDRESS /streamSettings/masqueSettings/warp/address"]);
    expect(codes(warp({ ...warpKeys(), address: ["172.16.0.2", "172.16.0.3/32"] }))).toEqual(["error XCK_SEMANTIC_MASQUE_WARP_ADDRESS /streamSettings/masqueSettings/warp/address/1"]);
  });

  it("rejects the masque transport on other outbounds", () => {
    const vless = createDefaultOutbound({ protocol: "vless", settings: { address: "example.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption: "none" },
      streamSettings: { network: "masque", security: "tls" } });
    expect(codes(vless)).toEqual(["error XCK_SEMANTIC_MASQUE_TRANSPORT_PROTOCOL /streamSettings/network"]);
  });

  it("validates masqueSettings on other outbounds, as Xray builds every present settings block", () => {
    const vless = createDefaultOutbound({ protocol: "vless", settings: { address: "example.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption: "none" },
      streamSettings: { network: "tcp", security: "tls", masqueSettings: { user: "a:b" } } });
    expect(codes(vless)).toEqual(["error XCK_SEMANTIC_MASQUE_USER /streamSettings/masqueSettings/user"]);
  });
});
