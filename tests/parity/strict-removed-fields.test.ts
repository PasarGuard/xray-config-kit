import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import type { Issue, JsonObject } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("strict removed-field warnings", () => {
  const wireguard = (extra: JsonObject) => ({ outbounds: [{ tag: "warp-wg", protocol: "wireguard", settings: {
    secretKey: "cGFzc3dvcmQ=", address: ["172.16.0.2/32"],
    peers: [{ publicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", endpoint: "engage.cloudflareclient.com:2408" }], ...extra } }] });
  const rows = (issues: Issue[]) => issues.map((issue) => [issue.code, issue.severity, issue.path]);

  it("warns for WireGuard keys that only older generated releases accept", () => {
    const result = validateStrictXrayConfig(wireguard({ workers: 2, domainStrategy: "ForceIPv4" }), { releaseTag: latestGeneratedRelease.tag });
    expect(result.ok).toBe(true);
    expect(rows(result.issues)).toEqual([
      ["XCK_XRAY_STRICT_REMOVED_FIELD", "warning", "/outbounds/1/settings/workers"],
      ["XCK_XRAY_STRICT_REMOVED_FIELD", "warning", "/outbounds/1/settings/domainStrategy"]
    ]);
    expect(result.issues[0]?.message).toContain("v26.5.3");
    expect(result.issues[0]?.message).toContain(latestGeneratedRelease.tag);
    expect(result.issues[1]?.message).toContain("v26.9.8");
  });

  it("does not warn while the selected release still accepts the key", () => {
    expect(validateStrictXrayConfig(wireguard({ workers: 2, domainStrategy: "ForceIPv4" }), { releaseTag: "v26.5.3" }).issues).toEqual([]);
  });

  it("keeps never-generated fields as errors next to removed-field warnings", () => {
    const result = validateStrictXrayConfig(wireguard({ workers: 2, notAField: true }), { releaseTag: latestGeneratedRelease.tag });
    expect(result.ok).toBe(false);
    expect(rows(result.issues)).toEqual([
      ["XCK_XRAY_STRICT_REMOVED_FIELD", "warning", "/outbounds/1/settings/workers"],
      ["XCK_XRAY_STRICT_UNKNOWN_FIELD", "error", "/outbounds/1/settings/notAField"]
    ]);
  });

  it("does not call a key removed when only a later release added it", () => {
    expect(rows(validateStrictXrayConfig(wireguard({ remoteDNS: ["1.1.1.1"] }), { releaseTag: "v26.7.28" }).issues))
      .toEqual([["XCK_XRAY_STRICT_UNKNOWN_FIELD", "error", "/outbounds/1/settings/remoteDNS"]]);
  });

  it("reports removed keys as warnings in permissive mode too", () => {
    const result = validateStrictXrayConfig(wireguard({ workers: 2, notAField: true }), { releaseTag: latestGeneratedRelease.tag, mode: "permissive" });
    expect(rows(result.issues)).toEqual([
      ["XCK_XRAY_STRICT_REMOVED_FIELD", "warning", "/outbounds/1/settings/workers"],
      ["XCK_XRAY_STRICT_UNKNOWN_FIELD", "warning", "/outbounds/1/settings/notAField"]
    ]);
  });

  it("applies to nested stream structs", () => {
    const result = validateStrictXrayConfig({ inbounds: [{ protocol: "vless", tag: "v", port: 443, settings: { clients: [], decryption: "none" },
      streamSettings: { network: "tcp", security: "tls", tlsSettings: { echForceQuery: "full" } } }] }, { releaseTag: latestGeneratedRelease.tag });
    expect(rows(result.issues)).toEqual([["XCK_XRAY_STRICT_REMOVED_FIELD", "warning", "/inbounds/1/streamSettings/tlsSettings/echForceQuery"]]);
    expect(result.issues[0]?.message).toContain("v26.5.3");
  });
});
