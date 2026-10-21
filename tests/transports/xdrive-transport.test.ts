import { describe, expect, it } from "bun:test";
import { importXrayConfig } from "../../src/index.js";
import type { Inbound, JsonObject, Outbound, XDriveTransport } from "../../src/index.js";
import { editAndBuild, editOutboundAndBuild, rebuildWithoutSource } from "../helpers/profile-round-trip.js";
import { vlessEncryptionPair } from "../helpers/vless-encryption.js";

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
  settings: { clients: [vlessClient], decryption: vlessEncryptionPair.decryption },
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

  it("drops stale Google Drive secrets when an imported XDrive inbound switches to local", () => {
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" }, xdriveSettings: driveSettings })] };
    const built = editAndBuild(raw, (inbound) => {
      if (inbound.protocol !== "vless") throw new Error("expected the imported VLESS inbound");
      const { secrets: _secrets, ...transport } = inbound.transport as XDriveTransport;
      return { ...inbound, transport: { ...transport, service: "local", remoteFolder: "/var/lib/xray/xdrive" } } as Inbound;
    });
    const { secrets: _secrets, ...driveWithoutSecrets } = driveSettings;
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect((built.config.inbounds?.[0]?.streamSettings as JsonObject).xdriveSettings)
      .toEqual({ ...driveWithoutSecrets, service: "local", remoteFolder: "/var/lib/xray/xdrive" });
  });

  it("replaces the XDrive template wholesale on edit", () => {
    const put = { method: "PUT", url: "https://store.example.com/{name}" };
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "none", xdriveSettings: { service: "template", template: { put, get: { method: "GET", url: "https://store.example.com/{name}" } } } })] };
    const built = editAndBuild(raw, (inbound) => ({ ...inbound, transport: { type: "xdrive", service: "template", template: { put } } }) as Inbound);
    expect((built.config.inbounds?.[0]?.streamSettings as JsonObject).xdriveSettings).toEqual({ service: "template", template: { put } });
  });

  describe("xmux", () => {
    const xmux = { maxConcurrency: "16-32", cMaxReuseTimes: 64, hMaxRequestTimes: "600-900", hMaxReusableSecs: "1800-3000", hKeepAlivePeriod: 30 };
    const raw = { inbounds: [vlessInbound({ network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" }, xdriveSettings: { ...driveSettings, xmux } })] };
    const xdriveSettings = (built: { readonly config: { readonly inbounds?: readonly { readonly streamSettings?: unknown }[] } }) =>
      (built.config.inbounds?.[0]?.streamSettings as JsonObject).xdriveSettings;

    it("round-trips XDrive xmux on the inbound transport byte for byte", () => {
      const { imported, built } = rebuildWithoutSource(raw);
      expect(imported.profile.inbounds[0]).toMatchObject({ transport: { type: "xdrive", xmux } });
      expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
      expect(built.config.inbounds).toEqual(raw.inbounds);
    });

    it("keeps XDrive xmux when the imported inbound is renamed", () => {
      // A tag change skips the source merge, so only the model can carry xmux.
      const built = editAndBuild(raw, (inbound) => ({ ...inbound, tag: "vless-xdrive-renamed" }) as Inbound);
      expect(built.config.inbounds?.[0]?.tag).toBe("vless-xdrive-renamed");
      expect(xdriveSettings(built)).toEqual({ ...driveSettings, xmux });
    });

    it("removes xmux keys and a whole xmux deleted in the model instead of keeping the imported ones", () => {
      const withXmux = (next: Record<string, string | number> | undefined) => (inbound: Inbound) => {
        const { xmux: _imported, ...transport } = (inbound as Extract<Inbound, { protocol: "vless" }>).transport as XDriveTransport;
        return { ...inbound, transport: next ? { ...transport, xmux: next } : transport } as Inbound;
      };
      expect(xdriveSettings(editAndBuild(raw, withXmux({ maxConnections: 2 })))).toEqual({ ...driveSettings, xmux: { maxConnections: 2 } });
      expect(xdriveSettings(editAndBuild(raw, withXmux(undefined)))).toEqual(driveSettings);
    });

    it("keeps XDrive xmux on an edited VLESS outbound", () => {
      const outboundSettings = { address: "www.googleapis.com", port: 443, id: vlessClient.id, encryption: vlessEncryptionPair.encryption };
      const streamSettings = { network: "xdrive", security: "tls", xdriveSettings: { ...driveSettings, xmux } };
      const outboundRaw = { outbounds: [{ tag: "drive-out", protocol: "vless", settings: outboundSettings, streamSettings, mux: { enabled: true } }] };
      const built = editOutboundAndBuild(outboundRaw, (outbound) => ({ ...outbound, tag: "drive-out-2" }) as Outbound);
      expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
      expect(built.config.outbounds?.[0]?.streamSettings).toEqual(streamSettings);
    });
  });

  it("keeps a VLESS outbound with an XDrive stream editable and unchanged", () => {
    const outboundSettings = { address: "www.googleapis.com", port: 443, id: vlessClient.id, encryption: vlessEncryptionPair.encryption };
    const streamSettings = { network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" }, xdriveSettings: driveSettings };
    const mux = { enabled: true };
    const raw = { outbounds: [{ tag: "drive-out", protocol: "vless", settings: outboundSettings, streamSettings, mux }] };
    expect(importXrayConfig(raw).unmanaged).toBe(0);
    // The tag stays the same so the edited outbound is merged with its kept source (a tag change skips the merge).
    const built = editOutboundAndBuild(raw, (outbound) => ({ ...outbound, settings: { ...outboundSettings, port: 8443 } }) as Outbound);
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.config.outbounds).toEqual([{ tag: "drive-out", protocol: "vless", settings: { ...outboundSettings, port: 8443 }, streamSettings, mux }]);
  });
});
