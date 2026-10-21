import { describe, expect, it } from "bun:test";
import {
  buildXrayConfig,
  createDefaultOutbound,
  createProfile,
  validateInboundDraft,
  validateOutboundDraft,
  XDRIVE_DEFAULTS,
  XDRIVE_LIMITS,
  XDRIVE_SERVICES
} from "../../src/index.js";
import type { Inbound, Issue, JsonObject, JsonValue, StreamAdvanced, StreamSettings, XDriveTransport } from "../../src/index.js";
import { vlessEncryptionPair } from "../helpers/vless-encryption.js";

const inbound = (transport: Partial<XDriveTransport>): Inbound => ({
  kind: "inbound",
  protocol: "vless",
  tag: "vless-xdrive",
  port: 443,
  clients: [],
  security: { type: "tls", serverName: "drive.example.com" },
  decryption: vlessEncryptionPair.decryption,
  transport: { type: "xdrive", service: "local", remoteFolder: "/var/lib/xray/xdrive", ...transport }
});
const codes = (issues: Issue[]) => issues.map((issue) => `${issue.severity} ${issue.code} ${issue.path}`).filter((row) => row.includes("XDRIVE"));
const outbound = (streamSettings: StreamSettings) => createDefaultOutbound({
  protocol: "vless",
  tag: "drive-out",
  settings: { address: "www.googleapis.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption: vlessEncryptionPair.encryption },
  streamSettings,
  mux: { enabled: true }
});

describe("XDrive validation", () => {
  it("exports XDrive services, Xray defaults and caps", () => {
    expect(XDRIVE_SERVICES).toEqual(["local", "Google Drive", "google-drive", "template"]);
    expect(XDRIVE_DEFAULTS).toEqual({ segmentBytes: 524288, flushIntervalMs: 20, pollIntervalMs: 50, maxPollIntervalMs: 500, sessionTtlSeconds: 300, concurrency: 8, eagerWindowMs: 2000, holeTimeoutMs: 30000 });
    expect(XDRIVE_LIMITS).toEqual({ segmentBytes: 16777216, concurrency: 64 });
  });

  it("accepts a local XDrive stream", () => expect(codes(validateInboundDraft(inbound({})))).toEqual([]));

  it("rejects unknown or empty services", () => {
    expect(codes(validateInboundDraft(inbound({ service: "Dropbox" })))).toEqual(["error XCK_SEMANTIC_XDRIVE_SERVICE /transport/service"]);
    expect(codes(validateInboundDraft(inbound({ service: "" })))).toEqual(["error XCK_SEMANTIC_XDRIVE_SERVICE /transport/service"]);
    expect(validateInboundDraft(inbound({ service: "Dropbox" })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_SERVICE")?.message)
      .toBe('XDrive service must be "local", "Google Drive", "google-drive", or "template".');
  });

  it("requires remoteFolder for local and both Google Drive spellings", () => {
    expect(codes(validateInboundDraft(inbound({ remoteFolder: "" })))).toEqual(["error XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED /transport/remoteFolder"]);
    for (const service of ["Google Drive", "google-drive"]) {
      expect(codes(validateInboundDraft(inbound({ service, remoteFolder: "", secrets: ["id", "secret", "refresh"] }))))
        .toEqual(["error XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED /transport/remoteFolder"]);
    }
  });

  // Newer Xray renames "Google Drive" to "google-drive" and still reads the old spelling, which older clients need.
  for (const service of ["Google Drive", "google-drive"]) {
    it(`requires exactly three secrets for "${service}"`, () => {
      const drive = { service, remoteFolder: "1AbC" };
      expect(codes(validateInboundDraft(inbound({ ...drive, secrets: ["id", "secret"] })))).toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /transport/secrets"]);
      expect(codes(validateInboundDraft(inbound({ ...drive, secrets: ["id", "", "refresh"] })))).toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /transport/secrets"]);
      // No deprecation warning for either spelling: the kit cannot know which Xray release the other side runs.
      expect(codes(validateInboundDraft(inbound({ ...drive, secrets: ["id", "secret", "refresh"] })))).toEqual([]);
      expect(validateInboundDraft(inbound({ ...drive, secrets: ["id", "secret", "refresh"] })).filter((issue) => issue.severity === "error")).toEqual([]);
    });
  }

  it("requires a template object for the template service", () => {
    expect(codes(validateInboundDraft(inbound({ service: "template", remoteFolder: undefined })))).toEqual(["error XCK_SEMANTIC_XDRIVE_TEMPLATE_REQUIRED /transport/template"]);
    expect(codes(validateInboundDraft(inbound({ service: "template", remoteFolder: undefined, template: { flatten: true } })))).toEqual([]);
  });

  it("warns when Xray would cap segmentBytes or concurrency", () => {
    expect(codes(validateInboundDraft(inbound({ segmentBytes: 16777217, concurrency: 65 })))).toEqual([
      "warning XCK_SEMANTIC_XDRIVE_SEGMENT_BYTES_CAPPED /transport/segmentBytes",
      "warning XCK_SEMANTIC_XDRIVE_CONCURRENCY_CAPPED /transport/concurrency"
    ]);
    expect(validateInboundDraft(inbound({ segmentBytes: 16777217, concurrency: 65 })).filter((issue) => issue.code.endsWith("_CAPPED")).map((issue) => issue.message))
      .toEqual(["Xray caps segmentBytes at 16777216 (16 MiB).", "Xray caps concurrency at 64."]);
    expect(codes(validateInboundDraft(inbound({ segmentBytes: 16777216, concurrency: 64 })))).toEqual([]);
  });

  it("validates outbound xdriveSettings, including a stale block on another network", () => {
    expect(codes(validateOutboundDraft(outbound({ network: "xdrive", security: "tls", xdriveSettings: { service: "Google Drive", remoteFolder: "1AbC", secrets: [] } }))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /streamSettings/xdriveSettings/secrets"]);
    expect(codes(validateOutboundDraft(outbound({ network: "tcp", xdriveSettings: { service: "bogus" } }))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_SERVICE /streamSettings/xdriveSettings/service"]);
    expect(codes(validateOutboundDraft(outbound({ method: "xdrive", security: "tls" } as StreamSettings))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_SERVICE /streamSettings/xdriveSettings/service"]);
  });

  it("skips remoteFolder on a stale xdriveSettings block, as Xray checks it only when the transport runs", () => {
    expect(codes(validateOutboundDraft(outbound({ network: "tcp", xdriveSettings: { service: "local" } })))).toEqual([]);
    expect(codes(validateOutboundDraft(outbound({ network: "tcp", xdriveSettings: { service: "Google Drive" } }))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /streamSettings/xdriveSettings/secrets"]);
    expect(codes(validateOutboundDraft(outbound({ network: "tcp", xdriveSettings: { service: "google-drive" } }))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /streamSettings/xdriveSettings/secrets"]);
    expect(codes(validateOutboundDraft(outbound({ network: "xdrive", security: "tls", xdriveSettings: { service: "local" } }))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED /streamSettings/xdriveSettings/remoteFolder"]);
  });

  describe("xmux", () => {
    const conflicts: Record<string, JsonValue>[] = [{ maxConnections: 2, maxConcurrency: "16-32" }, { maxConnections: "1-3", maxConcurrency: 16 }, { maxConnections: "-1-2", maxConcurrency: "4" }];
    const accepted: Record<string, JsonValue>[] = [{}, { maxConcurrency: "16-32" }, { maxConnections: 4, hMaxReusableSecs: "1800-3000", hKeepAlivePeriod: 30 }, { maxConnections: 0, maxConcurrency: "16-32" },
      { maxConnections: "-3--1", maxConcurrency: 8 }, { cMaxReuseTimes: 64, hMaxRequestTimes: "600-900" }];

    it("rejects maxConnections with maxConcurrency on the inbound transport, as Xray does", () => {
      for (const xmux of conflicts) {
        expect(codes(validateInboundDraft(inbound({ xmux }))), JSON.stringify(xmux)).toEqual(["error XCK_SEMANTIC_XDRIVE_XMUX_CONFLICT /transport/xmux"]);
      }
      expect(validateInboundDraft(inbound({ xmux: conflicts[0] })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_XMUX_CONFLICT")?.message)
        .toBe("XDrive xmux cannot set both maxConnections and maxConcurrency.");
    });

    it("accepts xmux on both sides, including an empty one that takes Xray's defaults", () => {
      for (const xmux of accepted) {
        expect(codes(validateInboundDraft(inbound({ xmux }))), JSON.stringify(xmux)).toEqual([]);
        expect(codes(validateOutboundDraft(outbound({ network: "xdrive", security: "tls", xdriveSettings: { service: "local", remoteFolder: "/srv/xdrive", xmux } }))), JSON.stringify(xmux)).toEqual([]);
      }
    });

    it("rejects the conflict on outbounds, including a stale xdriveSettings block that Xray still builds", () => {
      const xmux = conflicts[0]!;
      expect(codes(validateOutboundDraft(outbound({ network: "xdrive", security: "tls", xdriveSettings: { service: "local", remoteFolder: "/srv/xdrive", xmux } }))))
        .toEqual(["error XCK_SEMANTIC_XDRIVE_XMUX_CONFLICT /streamSettings/xdriveSettings/xmux"]);
      expect(codes(validateOutboundDraft(outbound({ network: "tcp", xdriveSettings: { service: "local", xmux } }))))
        .toEqual(["error XCK_SEMANTIC_XDRIVE_XMUX_CONFLICT /streamSettings/xdriveSettings/xmux"]);
    });

    it("skips the conflict for releases that ignore XDrive xmux", () => {
      const xmux = conflicts[0]!;
      expect(codes(validateInboundDraft(inbound({ xmux }), { xrayVersion: "26.10.17" }))).toEqual([]);
      expect(codes(validateOutboundDraft(outbound({ network: "xdrive", security: "tls", xdriveSettings: { service: "local", remoteFolder: "/srv/xdrive", xmux } }), { xrayVersion: "26.10.17" }))).toEqual([]);
    });
  });

  describe("XDrive over h3", () => {
    const drive = { service: "google-drive", remoteFolder: "1AbC", secrets: ["id", "secret", "refresh"] };
    const noise = { type: "noise", settings: { noise: [{ rand: "50-100" }] } };
    const salamander = { type: "salamander", settings: { password: "p" } };
    const h3Inbound = (alpn: ("h2" | "h3" | "http/1.1")[], transport: Partial<XDriveTransport>, streamAdvanced: StreamAdvanced): Inbound =>
      ({ ...inbound({ ...drive, ...transport }), security: { type: "tls", serverName: "drive.example.com", alpn }, streamAdvanced }) as Inbound;
    const h3Outbound = (tlsSettings: JsonObject, finalmask: JsonObject | undefined, service = "google-drive") => outbound({
      network: "xdrive", security: "tls", tlsSettings, xdriveSettings: { ...drive, service }, ...(finalmask ? { finalmask } : {})
    } as StreamSettings);

    it("allows only the noise udp mask to Google Drive over h3, for both service spellings", () => {
      for (const service of ["google-drive", "Google Drive"]) {
        expect(codes(validateInboundDraft(h3Inbound(["h3"], { service }, { finalmask: { udp: [noise, salamander] } })))).toEqual(["error XCK_SEMANTIC_XDRIVE_H3_UDP_MASK /streamAdvanced/finalmask/udp/1/type"]);
        expect(codes(validateInboundDraft(h3Inbound(["h3"], { service }, { finalmask: { udp: [noise, { ...noise, type: "Noise" }] } })))).toEqual([]);
      }
      expect(validateInboundDraft(h3Inbound(["h3"], {}, { finalmask: { udp: [salamander] } })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_H3_UDP_MASK")?.message)
        .toBe('XDrive over h3 to Google Drive only works with the "noise" udp mask, not "salamander".');
    });

    it("leaves udp masks alone without h3-only alpn or for other services", () => {
      const finalmask = { udp: [salamander] };
      expect(codes(validateInboundDraft(h3Inbound(["h3", "h2"], {}, { finalmask })))).toEqual([]);
      expect(codes(validateInboundDraft(h3Inbound(["h2"], {}, { finalmask })))).toEqual([]);
      expect(codes(validateInboundDraft(h3Inbound(["h3"], { service: "local", remoteFolder: "/srv/xdrive", secrets: undefined }, { finalmask })))).toEqual([]);
      expect(codes(validateInboundDraft(h3Inbound(["h3"], { service: "template", remoteFolder: undefined, secrets: undefined, template: { flatten: true } }, { finalmask })))).toEqual([]);
    });

    it("rejects brutal congestion over h3 for every service, from modelled or raw quicParams", () => {
      expect(codes(validateInboundDraft(h3Inbound(["h3"], {}, { quicParams: { congestion: "brutal", brutalUp: "10 mbps" } }))))
        .toEqual(["error XCK_SEMANTIC_XDRIVE_H3_CONGESTION /streamAdvanced/quicParams/congestion"]);
      expect(codes(validateInboundDraft(h3Inbound(["h3"], { service: "local", remoteFolder: "/srv/xdrive", secrets: undefined }, { finalmask: { quicParams: { congestion: "Force-Brutal" } } }))))
        .toEqual(["error XCK_SEMANTIC_XDRIVE_H3_CONGESTION /streamAdvanced/finalmask/quicParams/congestion"]);
      expect(codes(validateInboundDraft(h3Inbound(["h3"], {}, { quicParams: { congestion: "bbr" } })))).toEqual([]);
      expect(codes(validateInboundDraft(h3Inbound(["h3", "h2"], {}, { quicParams: { congestion: "brutal" } })))).toEqual([]);
      expect(validateInboundDraft(h3Inbound(["h3"], {}, { quicParams: { congestion: "brutal" } })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_H3_CONGESTION")?.message)
        .toBe('XDrive over h3 cannot use "brutal" congestion; brutal is for Hysteria servers.');
    });

    it("checks outbound streams, including an alpn string", () => {
      expect(codes(validateOutboundDraft(h3Outbound({ alpn: ["h3"] }, { udp: [salamander], quicParams: { congestion: "brutal" } })))).toEqual([
        "error XCK_SEMANTIC_XDRIVE_H3_UDP_MASK /streamSettings/finalmask/udp/0/type",
        "error XCK_SEMANTIC_XDRIVE_H3_CONGESTION /streamSettings/finalmask/quicParams/congestion"
      ]);
      expect(codes(validateOutboundDraft(h3Outbound({ alpn: "h3" }, { udp: [salamander] }, "Google Drive")))).toEqual(["error XCK_SEMANTIC_XDRIVE_H3_UDP_MASK /streamSettings/finalmask/udp/0/type"]);
      expect(codes(validateOutboundDraft(h3Outbound({ alpn: ["h3"] }, { udp: [noise], quicParams: { congestion: "bbr" } })))).toEqual([]);
      expect(codes(validateOutboundDraft(h3Outbound({ alpn: "h3,h2" }, { udp: [salamander], quicParams: { congestion: "brutal" } })))).toEqual([]);
      expect(codes(validateOutboundDraft(h3Outbound({ alpn: ["h3"] }, undefined)))).toEqual([]);
    });

    it("skips the h3 rules for releases without XDrive h3", () => {
      expect(codes(validateInboundDraft(h3Inbound(["h3"], {}, { finalmask: { udp: [salamander] }, quicParams: { congestion: "brutal" } }), { xrayVersion: "26.10.17" }))).toEqual([]);
      expect(codes(validateOutboundDraft(h3Outbound({ alpn: ["h3"] }, { udp: [salamander], quicParams: { congestion: "brutal" } }), { xrayVersion: "26.10.17" }))).toEqual([]);
    });
  });

  it("rejects XDrive when the selected Xray predates it and keeps REALITY off XDrive", () => {
    const old = buildXrayConfig(createProfile({ inbounds: [inbound({})] }), { xrayVersion: "26.7.28" });
    expect(old.config).toEqual({});
    expect(old.issues.map((issue) => `${issue.code} ${issue.path}`)).toContain("XCK_COMPAT_FEATURE_UNSUPPORTED /inbounds/1/transport/type");
    const reality = { ...inbound({}), security: { type: "reality", serverNames: ["example.com"], privateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", shortIds: ["a1b2c3d4"], target: "example.com:443" } } as Inbound;
    expect(validateInboundDraft(reality).map((issue) => issue.code)).toContain("XCK_COMPAT_REALITY_TRANSPORT");
  });
});
