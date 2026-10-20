import { describe, expect, it } from "bun:test";
import { importXrayConfig } from "../../src/index.js";
import type { Inbound, JsonObject, Outbound } from "../../src/index.js";
import { editAndBuild, editOutboundAndBuild, rebuildWithoutSource } from "../helpers/profile-round-trip.js";

const vlessClient = { id: "11111111-1111-4111-8111-111111111111", email: "alice" };
const driveSettings = {
  service: "Google Drive",
  remoteFolder: "1AbCdEfGhIjKlMnOp",
  secrets: ["client-id.apps.googleusercontent.com", "client-secret", "refresh-token"],
  segmentBytes: 1048576,
  flushIntervalMs: 20,
  pollIntervalMs: 50,
  maxPollIntervalMs: 500,
  sessionTtlSeconds: 300,
  concurrency: 16,
  eagerWindowMs: 2000,
  holeTimeoutMs: 30000
};
const vlessInbound = (streamSettings: JsonObject) => ({
  tag: "vless-xdrive",
  port: 443,
  protocol: "vless",
  settings: { clients: [vlessClient], decryption: "none" },
  streamSettings
});

describe("XDrive transport model", () => {
  it("round-trips a VLESS inbound with an XDrive Google Drive stream", () => {
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" }, xdriveSettings: driveSettings })] };
    const { imported, built } = rebuildWithoutSource(raw);
    expect(imported.unmanaged).toBe(0);
    expect(imported.profile.inbounds[0]).toMatchObject({ protocol: "vless", transport: { type: "xdrive", ...driveSettings } });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.inbounds).toEqual(raw.inbounds);
  });

  it("round-trips the XDrive template service with a nested template object", () => {
    const template = {
      flatten: true,
      concurrency: 4,
      auth: { type: "oauth2", tokenUrl: "https://auth.example.com/token", form: { grant_type: "refresh_token" } },
      put: { method: "PUT", url: "https://store.example.com/{name}" }
    };
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "tls", tlsSettings: { serverName: "store.example.com" }, xdriveSettings: { service: "template", remoteFolder: "xray", template } })] };
    const { imported, built } = rebuildWithoutSource(raw);
    expect(imported.profile.inbounds[0]).toMatchObject({ transport: { type: "xdrive", service: "template", remoteFolder: "xray", template } });
    expect(built.config.inbounds).toEqual(raw.inbounds);
  });

  it("keeps streamSettings.method when an imported XDrive inbound is edited", () => {
    const raw = { inbounds: [vlessInbound({ method: "xdrive", security: "none", xdriveSettings: { service: "local", remoteFolder: "/var/lib/xray/xdrive" } })] };
    expect(importXrayConfig(raw).profile.inbounds[0]).toMatchObject({ transport: { type: "xdrive", service: "local" } });
    const built = editAndBuild(raw, (inbound) => ({ ...inbound, port: 8443 }) as Inbound);
    const stream = built.config.inbounds?.[0]?.streamSettings as JsonObject;
    expect(built.config.inbounds?.[0]?.port).toBe(8443);
    expect(stream.method).toBe("xdrive");
    expect(stream).not.toHaveProperty("network");
    expect(stream.xdriveSettings).toEqual({ service: "local", remoteFolder: "/var/lib/xray/xdrive" });
  });

  it("drops stale xdriveSettings when an imported XDrive inbound switches to tcp", () => {
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" }, xdriveSettings: driveSettings })] };
    const stream = editAndBuild(raw, (inbound) => ({ ...inbound, transport: { type: "tcp" } }) as Inbound).config.inbounds?.[0]?.streamSettings as JsonObject;
    expect(stream.network).toBe("tcp");
    expect(stream).not.toHaveProperty("xdriveSettings");
  });

  it("replaces the XDrive template wholesale on edit", () => {
    const put = { method: "PUT", url: "https://store.example.com/{name}" };
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "none", xdriveSettings: { service: "template", template: { put, get: { method: "GET", url: "https://store.example.com/{name}" } } } })] };
    const built = editAndBuild(raw, (inbound) => ({ ...inbound, transport: { type: "xdrive", service: "template", template: { put } } }) as Inbound);
    expect((built.config.inbounds?.[0]?.streamSettings as JsonObject).xdriveSettings).toEqual({ service: "template", template: { put } });
  });

  it("keeps a VLESS outbound with an XDrive stream editable and unchanged", () => {
    const outboundSettings = { address: "www.googleapis.com", port: 443, id: vlessClient.id, encryption: "none" };
    const streamSettings = { network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" }, xdriveSettings: driveSettings };
    const raw = { outbounds: [{ tag: "drive-out", protocol: "vless", settings: outboundSettings, streamSettings }] };
    expect(importXrayConfig(raw).unmanaged).toBe(0);
    // The tag stays the same so the edited outbound is merged with its kept source (a tag change skips the merge).
    const built = editOutboundAndBuild(raw, (outbound) => ({ ...outbound, settings: { ...outboundSettings, port: 8443 } }) as Outbound);
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.outbounds).toEqual([{ tag: "drive-out", protocol: "vless", settings: { ...outboundSettings, port: 8443 }, streamSettings }]);
  });
});
