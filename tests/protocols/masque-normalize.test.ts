import { describe, expect, it } from "bun:test";
import { buildXrayConfig, createDefaultInbound, createProfile, importXrayConfig, normalizeProfile, validateProfile } from "../../src/index.js";
import type { Profile } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("normalizeProfile for MASQUE fields", () => {
  it("drops a leaked remoteDNS from non-MASQUE inbounds before strict validation", () => {
    const profile = { schemaVersion: "xck.v1", inbounds: [{ kind: "inbound", protocol: "vless", tag: "vless-in", port: 443, clients: [],
      security: { type: "none" }, transport: { type: "tcp" }, decryption: "none", remoteDNS: ["1.1.1.1"] }],
      outbounds: [{ protocol: "freedom", tag: "direct" }] } as unknown as Profile;
    const normalized = normalizeProfile(profile);
    expect(normalized.inbounds[0]).not.toHaveProperty("remoteDNS");
    expect(validateProfile(normalized).ok).toBe(true);
    const built = buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.inbounds?.[0]?.settings).not.toHaveProperty("remoteDNS");
  });

  it("keeps MASQUE remoteDNS and drops it only when empty", () => {
    const masque = createDefaultInbound({ protocol: "masque", tag: "masque-in", port: 443 });
    expect(normalizeProfile(createProfile({ inbounds: [{ ...masque, remoteDNS: ["1.1.1.1"] }] })).inbounds[0]).toMatchObject({ remoteDNS: ["1.1.1.1"] });
    expect(normalizeProfile(createProfile({ inbounds: [{ ...masque, remoteDNS: [] }] })).inbounds[0]).not.toHaveProperty("remoteDNS");
  });

  it("builds an unchanged import with an empty MASQUE remoteDNS to the raw source verbatim", () => {
    const raw = { inbounds: [{ tag: "masque-in", port: 443, protocol: "masque",
      settings: { users: [{ email: "alice@example.com", pass: "alice-masque-pass-1" }], address: ["10.14.0.1/16"], remoteDNS: [] },
      streamSettings: { network: "masque", security: "tls", tlsSettings: { serverName: "masque.example.com" } } }] };
    const built = buildXrayConfig(importXrayConfig(raw).profile, { xrayVersion: latestGeneratedRelease.version });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config).toEqual(raw);
  });
});
