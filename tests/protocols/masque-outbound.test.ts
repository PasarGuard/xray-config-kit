import { describe, expect, it } from "bun:test";
import { createDefaultOutbound, getOutboundFieldVisibility, getXrayParityReleases, validateOutboundDraft, xrayParityManifest } from "../../src/index.js";
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

  it("warns about mux for nodes on older releases but does not block it", () => {
    expect(codes(out({ mux: { enabled: true } }))).toEqual(["warning XCK_SEMANTIC_MASQUE_MUX_UNSUPPORTED /mux/enabled"]);
    expect(codes(out({ mux: { enabled: false } }))).toEqual([]);
  });

  it("names the first downloadable release that accepts mux, not a withdrawn one", () => {
    const withdrawn: readonly string[] = xrayParityManifest.source.withdrawnTags;
    const first = getXrayParityReleases().find((release) => !withdrawn.includes(release.tag) && release.structs.MasqueConfig?.some((field) => field.json === "xmux"))!;
    expect(withdrawn).not.toContain(first.tag);
    const message = validateOutboundDraft(out({ mux: { enabled: true } })).find((issue) => issue.code === "XCK_SEMANTIC_MASQUE_MUX_UNSUPPORTED")?.message;
    expect(message).toBe(`"mux" on MASQUE outbounds needs Xray ${first.tag} or newer on every node; older releases refuse it.`);
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

  describe("xmux", () => {
    const masqueSettings = { user: "alice@example.com", pass: "alice-masque-pass-1", xmux: { maxConcurrency: "16-32", hMaxRequestTimes: "600-900", hKeepAlivePeriod: 30 } };
    const raw = { outbounds: [{ tag: "masque-out", protocol: "masque", settings: { address: "masque.example.com", port: 443 },
      streamSettings: { network: "masque", security: "tls", tlsSettings: { serverName: "masque.example.com" }, masqueSettings } }] };
    const withXmux = (outbound: Outbound, xmux: JsonObject | undefined): Outbound => {
      const stream = (outbound as ProxyOutbound).streamSettings!;
      const { xmux: _imported, ...settings } = stream.masqueSettings ?? {};
      return { ...outbound, streamSettings: { ...stream, masqueSettings: xmux ? { ...settings, xmux } : settings } } as Outbound;
    };
    const editedMasqueSettings = (xmux: JsonObject | undefined) =>
      (editOutboundAndBuild(raw, (outbound) => withXmux(outbound, xmux)).config.outbounds?.[0]?.streamSettings as JsonObject).masqueSettings;
    const xmuxCodes = (xmux: JsonObject) => codes(out({ streamSettings: { network: "masque", security: "tls", masqueSettings: { xmux } } }));

    it("round-trips byte for byte", () => {
      const { built } = rebuildWithoutSource(raw);
      expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
      expect(JSON.stringify(built.config.outbounds)).toBe(JSON.stringify(raw.outbounds));
      expect(JSON.stringify(editOutboundAndBuild(raw, (outbound) => outbound).config)).toBe(JSON.stringify(raw));
    });

    it("removes xmux keys and a whole xmux deleted in the model instead of keeping the imported ones", () => {
      expect(editedMasqueSettings({ maxConcurrency: "16-32" })).toEqual({ user: "alice@example.com", pass: "alice-masque-pass-1", xmux: { maxConcurrency: "16-32" } });
      expect(editedMasqueSettings(undefined)).toEqual({ user: "alice@example.com", pass: "alice-masque-pass-1" });
    });

    it("rejects maxConnections together with maxConcurrency when both have a positive upper bound", () => {
      for (const xmux of [{ maxConnections: 2, maxConcurrency: "16-32" }, { maxConnections: "1-3", maxConcurrency: 16 }, { maxConnections: "-1-2", maxConcurrency: "4" }]) {
        expect(xmuxCodes(xmux), JSON.stringify(xmux)).toEqual(["error XCK_SEMANTIC_MASQUE_XMUX_CONFLICT /streamSettings/masqueSettings/xmux"]);
      }
    });

    it("accepts Int32Range numbers and \"a-b\" strings and a zero or negative bound beside the other field", () => {
      for (const xmux of [{}, { maxConcurrency: "1-3" }, { maxConnections: "1-3", hMaxReusableSecs: "1800-3000", hKeepAlivePeriod: 30 },
        { maxConnections: 0, maxConcurrency: "16-32" }, { maxConnections: "0-0", maxConcurrency: 8 }, { maxConnections: "-3--1", maxConcurrency: 8 }, { maxConnections: "", maxConcurrency: 8 }]) {
        expect(xmuxCodes(xmux), JSON.stringify(xmux)).toEqual([]);
      }
    });
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
