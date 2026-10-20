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
import type { Inbound, Issue, StreamSettings, XDriveTransport } from "../../src/index.js";

const inbound = (transport: Partial<XDriveTransport>): Inbound => ({
  kind: "inbound",
  protocol: "vless",
  tag: "vless-xdrive",
  port: 443,
  clients: [],
  security: { type: "tls", serverName: "drive.example.com" },
  decryption: "none",
  transport: { type: "xdrive", service: "local", remoteFolder: "/var/lib/xray/xdrive", ...transport }
});
const codes = (issues: Issue[]) => issues.map((issue) => `${issue.severity} ${issue.code} ${issue.path}`).filter((row) => row.includes("XDRIVE"));
const outbound = (streamSettings: StreamSettings) => createDefaultOutbound({
  protocol: "vless",
  tag: "drive-out",
  settings: { address: "www.googleapis.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption: "none" },
  streamSettings
});

describe("XDrive validation", () => {
  it("exports XDrive services, Xray defaults and caps", () => {
    expect(XDRIVE_SERVICES).toEqual(["local", "Google Drive", "template"]);
    expect(XDRIVE_DEFAULTS).toEqual({ segmentBytes: 524288, flushIntervalMs: 20, pollIntervalMs: 50, maxPollIntervalMs: 500, sessionTtlSeconds: 300, concurrency: 8, eagerWindowMs: 2000, holeTimeoutMs: 30000 });
    expect(XDRIVE_LIMITS).toEqual({ segmentBytes: 16777216, concurrency: 64 });
  });

  it("accepts a local XDrive stream", () => expect(codes(validateInboundDraft(inbound({})))).toEqual([]));

  it("rejects unknown or empty services", () => {
    expect(codes(validateInboundDraft(inbound({ service: "Dropbox" })))).toEqual(["error XCK_SEMANTIC_XDRIVE_SERVICE /transport/service"]);
    expect(codes(validateInboundDraft(inbound({ service: "" })))).toEqual(["error XCK_SEMANTIC_XDRIVE_SERVICE /transport/service"]);
    expect(validateInboundDraft(inbound({ service: "Dropbox" })).find((issue) => issue.code === "XCK_SEMANTIC_XDRIVE_SERVICE")?.message)
      .toBe('XDrive service must be "local", "Google Drive", or "template".');
  });

  it("requires remoteFolder for local and Google Drive", () => {
    expect(codes(validateInboundDraft(inbound({ remoteFolder: "" })))).toEqual(["error XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED /transport/remoteFolder"]);
  });

  it("requires exactly three Google Drive secrets", () => {
    const drive = { service: "Google Drive", remoteFolder: "1AbC" };
    expect(codes(validateInboundDraft(inbound({ ...drive, secrets: ["id", "secret"] })))).toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /transport/secrets"]);
    expect(codes(validateInboundDraft(inbound({ ...drive, secrets: ["id", "", "refresh"] })))).toEqual(["error XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS /transport/secrets"]);
    expect(codes(validateInboundDraft(inbound({ ...drive, secrets: ["id", "secret", "refresh"] })))).toEqual([]);
  });

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
    expect(codes(validateOutboundDraft(outbound({ network: "xdrive", security: "tls", xdriveSettings: { service: "local" } }))))
      .toEqual(["error XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED /streamSettings/xdriveSettings/remoteFolder"]);
  });

  it("rejects XDrive when the selected Xray predates it and keeps REALITY off XDrive", () => {
    const old = buildXrayConfig(createProfile({ inbounds: [inbound({})] }), { xrayVersion: "26.7.28" });
    expect(old.config).toEqual({});
    expect(old.issues.map((issue) => `${issue.code} ${issue.path}`)).toContain("XCK_COMPAT_FEATURE_UNSUPPORTED /inbounds/1/transport/type");
    const reality = { ...inbound({}), security: { type: "reality", serverNames: ["example.com"], privateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", shortIds: ["a1b2c3d4"], target: "example.com:443" } } as Inbound;
    expect(validateInboundDraft(reality).map((issue) => issue.code)).toContain("XCK_COMPAT_REALITY_TRANSPORT");
  });
});
