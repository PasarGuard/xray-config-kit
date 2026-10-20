import { describe, expect, it } from "bun:test";
import { generateClientLink, generateSubscription, importXrayConfig } from "../../src/index.js";
import type { Inbound, JsonObject, MasqueInbound } from "../../src/index.js";
import { editAndBuild, rebuildWithoutSource } from "../helpers/profile-round-trip.js";

const masqueRaw = { inbounds: [{ tag: "masque-in", port: 443, protocol: "masque",
  settings: { users: [{ email: "alice@example.com", pass: "alice-masque-pass-1", level: 0 }, { email: "bob@example.com", pass: "bob-masque-pass-22" }],
    address: ["10.14.0.1/16", "fd14::1/64"], mtu: 1400, remoteDNS: ["1.1.1.1", "2606:4700:4700::1111"] },
  streamSettings: { network: "masque", security: "tls",
    tlsSettings: { serverName: "masque.example.com", alpn: ["h3", "h2"], certificates: [{ certificateFile: "/etc/xray/masque.crt", keyFile: "/etc/xray/masque.key" }] },
    masqueSettings: { host: "masque.example.com", path: "/.well-known/masque/ip/{target}/{ipproto}/" } },
  sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] } }] };

describe("MASQUE inbound model", () => {
  it("round-trips a MASQUE inbound through import and build", () => {
    const { imported, built } = rebuildWithoutSource(masqueRaw);
    expect(imported.unmanaged).toBe(0);
    expect(imported.profile.inbounds[0]).toMatchObject({ protocol: "masque", address: ["10.14.0.1/16", "fd14::1/64"], mtu: 1400,
      clients: [{ protocol: "masque", email: "alice@example.com", pass: "alice-masque-pass-1", level: 0 }, { protocol: "masque", email: "bob@example.com", pass: "bob-masque-pass-22" }],
      security: { type: "tls" }, transport: { type: "masque", host: "masque.example.com" } });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.inbounds).toEqual(masqueRaw.inbounds);
  });

  it("imports MASQUE declared with streamSettings.method", () => {
    const raw = { inbounds: [{ ...masqueRaw.inbounds[0]!, streamSettings: { ...masqueRaw.inbounds[0]!.streamSettings, network: undefined, method: "masque" } }] };
    expect(importXrayConfig(raw).profile.inbounds[0]).toMatchObject({ protocol: "masque", transport: { type: "masque" } });
  });

  it("reads the Xray clients alias with Xray's precedence and writes users", () => {
    const raw = { inbounds: [{ ...masqueRaw.inbounds[0]!, settings: { users: [{ email: "old@example.com", pass: "old-masque-pass-1" }],
      clients: [{ email: "new@example.com", pass: "new-masque-pass-1" }], address: ["10.14.0.1/16"] } }] };
    const { imported, built } = rebuildWithoutSource(raw);
    expect((imported.profile.inbounds[0] as MasqueInbound).clients.map((client) => client.email)).toEqual(["new@example.com"]);
    expect(built.config.inbounds?.[0]?.settings).toEqual({ users: [{ email: "new@example.com", pass: "new-masque-pass-1" }], address: ["10.14.0.1/16"] });
  });

  it("drops the imported clients alias on edit so it cannot override the compiled users", () => {
    const raw = { inbounds: [{ ...masqueRaw.inbounds[0]!, settings: { clients: [{ email: "alice@example.com", pass: "alice-masque-pass-1" }], address: ["10.14.0.1/16"] } }] };
    const built = editAndBuild(raw, (inbound) => ({ ...inbound, clients: [...(inbound as MasqueInbound).clients, { protocol: "masque", email: "carol@example.com", pass: "carol-masque-pass-3" }] }) as Inbound);
    expect(built.config.inbounds?.[0]?.settings).toEqual({ users: [{ email: "alice@example.com", pass: "alice-masque-pass-1" }, { email: "carol@example.com", pass: "carol-masque-pass-3" }], address: ["10.14.0.1/16"] });
  });

  it("drops disabled MASQUE clients from compiled users", () => {
    const built = editAndBuild(masqueRaw, (inbound) => ({ ...inbound, clients: (inbound as MasqueInbound).clients.map((client, index) => index === 1 ? { ...client, enabled: false } : client) }) as Inbound);
    expect((built.config.inbounds?.[0]?.settings as JsonObject).users).toEqual([{ email: "alice@example.com", pass: "alice-masque-pass-1", level: 0 }]);
  });

  it("removes a deleted MASQUE header instead of keeping the imported one", () => {
    const raw = { inbounds: [{ ...masqueRaw.inbounds[0]!, streamSettings: { ...masqueRaw.inbounds[0]!.streamSettings, masqueSettings: { headers: { "X-A": "1", "X-B": "2" } } } }] };
    const built = editAndBuild(raw, (inbound) => ({ ...inbound, transport: { type: "masque", headers: { "X-A": "1" } } }) as Inbound);
    expect((built.config.inbounds?.[0]?.streamSettings as JsonObject).masqueSettings).toEqual({ headers: { "X-A": "1" } });
  });

  it("keeps MASQUE with REALITY security unmanaged, like Xray rejects it", () => {
    const raw = { inbounds: [{ ...masqueRaw.inbounds[0]!, streamSettings: { network: "masque", security: "reality", realitySettings: {} } }] };
    const imported = importXrayConfig(raw);
    expect(imported.profile.inbounds[0]?.protocol).toBe("unmanaged");
    expect(imported.issues.map((issue) => issue.code)).toContain("XCK_IMPORT_UNMANAGED_INBOUND");
  });

  it("has no share-link format for MASQUE clients", () => {
    const profile = importXrayConfig(masqueRaw).profile;
    expect(() => generateClientLink(profile, { inboundTag: "masque-in", clientId: "alice@example.com" })).toThrow('MASQUE inbound "masque-in" has no client link format.');
    expect(generateSubscription(profile, { format: "links" }).issues.map((issue) => issue.code)).toEqual(["XCK_SUBSCRIPTION_LINK_FAILED", "XCK_SUBSCRIPTION_LINK_FAILED"]);
  });

  it("generates no xray-json client outbounds for MASQUE clients", () => {
    const subscription = generateSubscription(importXrayConfig(masqueRaw).profile, { format: "xray-json" });
    expect(subscription.entries).toBe(0);
    expect(subscription.issues.map((issue) => issue.suggestion)).toEqual(["MASQUE client outbounds are not generated by this kit.", "MASQUE client outbounds are not generated by this kit."]);
  });
});
