import { describe, expect, it } from "bun:test";
import {
  createDefaultInbound,
  createDefaultInboundForProtocol,
  getInboundFieldVisibility,
  getInboundFormCapabilities,
  validateInboundDraft
} from "../../src/index.js";
import type { Inbound } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("MASQUE and XDrive form helpers", () => {
  const errors = (inbound: Inbound) => validateInboundDraft(inbound).filter((issue) => issue.severity === "error").map((issue) => `${issue.code} ${issue.path}`);

  it("creates a valid default MASQUE inbound", () => {
    const inbound = createDefaultInbound({ protocol: "masque", tag: "masque-in", port: 443 });
    expect(inbound).toEqual({ kind: "inbound", protocol: "masque", tag: "masque-in", port: 443,
      clients: [{ protocol: "masque", email: "user", pass: "change-me-masque-password" }], address: ["10.14.0.1/16", "fd14::1/64"],
      security: { type: "tls", serverName: "", alpn: ["h3", "h2"] }, transport: { type: "masque" } });
    expect(validateInboundDraft(inbound)).toEqual([]);
    expect(createDefaultInbound({ protocol: "masque", clientDefaults: "empty" }).clients).toEqual([]);
  });

  it("keeps MASQUE on TLS and the masque transport from the protocol picker", () => {
    const inbound = createDefaultInboundForProtocol({ protocol: "masque", transport: "tcp", security: "reality", clientDefaults: "empty" });
    expect(inbound).toMatchObject({ protocol: "masque", security: { type: "tls" }, transport: { type: "masque" }, clients: [] });
  });

  it("keeps the masque transport off other protocols", () => {
    const unsafe = (options: unknown) => createDefaultInbound(options as Parameters<typeof createDefaultInbound>[0]);
    expect(() => unsafe({ protocol: "vless", transport: "masque" })).toThrow("The masque transport can only be used by the masque inbound.");
    expect(() => unsafe({ protocol: "masque", security: "none" })).toThrow("masque default inbound always uses TLS and the masque transport.");
    for (const protocol of ["vless", "vmess", "trojan", "shadowsocks"] as const) {
      expect(createDefaultInboundForProtocol({ protocol, transport: "masque" })).toMatchObject({ protocol, transport: { type: "tcp" } });
    }
  });

  it("seeds XDrive with the Google Drive shape and flags the fields to fill", () => {
    const inbound = createDefaultInbound({ protocol: "vless", tag: "vless-xdrive", transport: "xdrive", security: "tls", clientDefaults: "empty" });
    expect(inbound.transport).toEqual({ type: "xdrive", service: "Google Drive", remoteFolder: "", secrets: ["", "", ""] });
    // The default decryption "none" is a placeholder too: XDrive needs a VLESS Encryption pair.
    expect(errors(inbound)).toEqual([
      "XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED /transport/remoteFolder",
      "XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /transport/secrets",
      "XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION /decryption"
    ]);
  });

  it("keeps the xdrive transport on VLESS", () => {
    const unsafe = (options: unknown) => createDefaultInbound(options as Parameters<typeof createDefaultInbound>[0]);
    for (const protocol of ["vmess", "trojan", "shadowsocks"] as const) {
      expect(() => unsafe({ protocol, transport: "xdrive" })).toThrow("The xdrive transport can only be used by the VLESS inbound.");
      expect(createDefaultInboundForProtocol({ protocol, transport: "xdrive" })).toMatchObject({ protocol, transport: { type: "tcp" } });
    }
    expect(createDefaultInboundForProtocol({ protocol: "vless", transport: "xdrive" })).toMatchObject({ protocol: "vless", transport: { type: "xdrive" } });
  });

  it("exposes MASQUE and XDrive capabilities for the latest release", () => {
    const caps = getInboundFormCapabilities({ xrayVersion: latestGeneratedRelease.version });
    expect(caps.protocols.masque).toBe(true);
    expect(caps.protocolOrder).toContain("masque");
    expect(caps.transports).toMatchObject({ masque: true, xdrive: true });
    expect(caps.transportSettingsFieldOrderByType.masque).toEqual(["host", "path", "user", "pass", "headers", "warp", "xmux"]);
    expect(caps.transportSettingsFieldOrderByType.xdrive).toEqual(["remoteFolder", "service", "secrets", "segmentBytes", "flushIntervalMs", "pollIntervalMs", "maxPollIntervalMs", "sessionTtlSeconds", "concurrency", "eagerWindowMs", "holeTimeoutMs", "template", "xmux"]);
    expect(caps.settingsFieldOrderByProtocol.masque).toEqual(["users", "clients", "address", "mtu"]);
    expect(caps.transportsByProtocol.masque).toEqual(["masque"]);
    expect(caps.transportsByProtocol.vless).toEqual(["tcp", "grpc", "xhttp", "ws", "httpupgrade", "kcp", "xdrive"]);
    // Xray runs the xdrive transport only under VLESS.
    for (const protocol of ["vmess", "trojan", "shadowsocks"]) {
      expect(caps.transportsByProtocol[protocol]).toEqual(["tcp", "grpc", "xhttp", "ws", "httpupgrade", "kcp"]);
    }
    expect(caps.securitiesByProtocol.masque).toEqual(["tls"]);
    expect(caps.securitiesByProtocol.vless).toEqual(["none", "tls", "reality"]);
    expect(caps.clientLinks.masque).toBe(false);
  });

  it("follows the selected release for MASQUE and XDrive capabilities", () => {
    const v26_9_30 = getInboundFormCapabilities({ xrayVersion: "26.9.30" });
    expect(v26_9_30.transportSettingsFieldOrderByType.masque).toEqual(["host", "path", "user", "pass", "headers"]);
    const v26_7_28 = getInboundFormCapabilities({ xrayVersion: "26.7.28" });
    expect(v26_7_28.protocols.masque).toBeUndefined();
    expect(v26_7_28.protocolOrder).not.toContain("masque");
    expect(v26_7_28.transportsByProtocol.vless).toEqual(["tcp", "grpc", "xhttp", "ws", "httpupgrade", "kcp"]);
    expect(v26_7_28.transportSettingsFieldOrderByType.masque).toEqual([]);
  });

  it("shows MASQUE settings, TLS, advanced stream and sniffing for MASQUE drafts", () => {
    expect(getInboundFieldVisibility(createDefaultInbound({ protocol: "masque" }))).toEqual({
      clients: true, accounts: false, wireguardPeers: false, tun: false, dokodemo: false, stream: true, tls: true, reality: false,
      shadowsocks: false, sniffing: true, advancedStream: true, masque: true });
  });
});
