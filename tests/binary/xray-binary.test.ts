import { describe, expect, it } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildXrayConfig,
  createDefaultInboundForProtocol,
  createProfile,
  generateVlessEncryption,
  generateWireGuardKeyPair,
  resolveXrayParityRelease,
  validateStrictXrayConfig
} from "../../src/index.js";
import type { Inbound, JsonObject, Outbound, Profile, XDriveTransport, XrayConfig } from "../../src/index.js";
import { testXrayConfig } from "../../src/node/index.js";
import { acceptedIpRules, rejectedIpRules } from "../helpers/ip-rules.js";
import { warpKeys } from "../helpers/masque-keys.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

const binaryPath = process.env.XRAY_BINARY;
const xrayVersion = process.env.XRAY_VERSION;
// Gates read parity data, never a version literal or the binary itself. "masque" in the inbound protocols means Xray
// v26.9.30 or later, XDriveConfig exists from the same release, MasqueWarpConfig exists from the release after that, and
// an "xmux" field on MasqueConfig marks the release that added MASQUE xmux. Xray's XDrive VLESS rules (validateXDrive:
// VLESS Encryption, no flow, one port, mux) are code that parity data cannot show; they arrived in that same xmux release,
// so their negative control needs both XDriveConfig and the xmux marker. The "google-drive" service spelling is also code
// that parity data cannot show; older releases reject it, so that test runs only on the newest generated release. Without
// XRAY_VERSION the MASQUE, XDrive and finalmask filter tests skip; the maybeIt tests need only XRAY_BINARY and then validate against the
// newest generated parity data. An "xmux" field on XDriveConfig marks the release that added XDrive xmux and XDrive over
// h3 (one Xray change), so the h3 rules share that gate. A "filter" entry in the finalmask loaders marks the filter mask.
const binaryRelease = binaryPath && xrayVersion ? resolveXrayParityRelease({ xrayVersion }).release : undefined;
const hasMasque = binaryRelease?.inboundProtocols.some((entry) => entry.protocol === "masque") === true;
const hasXDrive = binaryRelease?.structs.XDriveConfig !== undefined;
const hasWarp = binaryRelease?.structs.MasqueWarpConfig !== undefined;
const hasMasqueXmux = binaryRelease?.structs.MasqueConfig?.some((field) => field.json === "xmux") === true;
const hasXDriveXmux = binaryRelease?.structs.XDriveConfig?.some((field) => field.json === "xmux") === true;
const maybeIt = binaryPath ? it : it.skip;
const masqueIt = hasMasque ? it : it.skip;
const xdriveIt = hasXDrive ? it : it.skip;
const xdriveRulesIt = hasXDrive && hasMasqueXmux ? it : it.skip;
const xdriveNewestIt = hasXDrive && binaryRelease?.tag === latestGeneratedRelease.tag ? it : it.skip;
const warpIt = hasMasque && hasWarp ? it : it.skip;
const xmuxIt = hasMasque && hasMasqueXmux ? it : it.skip;
const xdriveXmuxIt = hasXDriveXmux ? it : it.skip;
const maskLoaders = binaryRelease ? Object.entries(binaryRelease.jsonLoaders).filter(([name]) => name.endsWith("maskLoader")) : [];
const hasFinalmaskFilter = maskLoaders.some(([, entries]) => entries.some((entry) => entry.protocol === "filter"));
const filterIt = hasFinalmaskFilter ? it : it.skip;
const beforeFilterIt = maskLoaders.length > 0 && !hasFinalmaskFilter ? it : it.skip;
const xdriveH3It = hasXDriveXmux ? it : it.skip;
// The release with MASQUE xmux but without XDrive xmux knows "google-drive" but not the h3 rules.
const xdriveBeforeH3It = hasMasqueXmux && hasXDrive && !hasXDriveXmux ? it : it.skip;

const key32 = "OEQIJdY9VnmJ78XX_hyUZueFyqvtdmCWY8e4NJ6B-lk";
const publicKey32 = "0UsWoTj6Ad7JKR_FsQ9p_r05ZXhtRSnWlw53kpwgT34";

function buildOrThrow(profile: Profile): XrayConfig {
  const built = buildXrayConfig(profile, { xrayVersion });
  const buildErrors = built.issues.filter((issue) => issue.severity === "error");
  if (buildErrors.length > 0) {
    throw new Error(buildErrors.map((issue) => `${issue.code} ${issue.path}: ${issue.message}`).join("\n"));
  }
  return built.config;
}

/** Runs `xray run -test` and returns whether it accepted the config, with its output. */
async function xrayVerdict(config: XrayConfig | JsonObject): Promise<{ readonly ok: boolean; readonly output: string }> {
  const result = await testXrayConfig(config, { binaryPath, timeoutMs: 30_000 });
  return { ok: result.ok, output: result.stdout + result.stderr };
}

async function expectXrayAccepts(config: XrayConfig | JsonObject): Promise<void> {
  const result = await testXrayConfig(config, { binaryPath, timeoutMs: 30_000 });
  if (!result.ok) throw new Error(result.stdout + result.stderr);
  expect(result.ok).toBe(true);
}

describe("real Xray binary", () => {
  maybeIt("accepts generated VLESS REALITY TCP config", async () => {
    const profile = createProfile({
      presets: ["dns-simple"],
      inbounds: [
        {
          kind: "inbound",
          protocol: "vless",
          tag: "vless-reality",
          listen: "0.0.0.0",
          port: 443,
          clients: [
            {
              protocol: "vless",
              id: "11111111-1111-4111-8111-111111111111",
              email: "alice",
              flow: "xtls-rprx-vision"
            }
          ],
          security: {
            type: "reality",
            serverNames: ["www.example.com"],
            privateKey: key32,
            publicKey: publicKey32,
            shortIds: ["a1b2c3d4"],
            target: "www.example.com:443",
            fingerprint: "chrome",
            spiderX: "/"
          },
          transport: {
            type: "tcp",
            header: { type: "none" }
          },
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls"]
          }
        }
      ]
    });

    await expectXrayAccepts(buildOrThrow(profile));
  });

  // Runs for every release: newer releases dropped these keys and Xray ignores them, so the kit may only warn.
  maybeIt("accepts WireGuard outbound keys that only older releases read", async () => {
    const keys = generateWireGuardKeyPair();
    const config = { outbounds: [{ tag: "warp-wg", protocol: "wireguard", settings: {
      secretKey: keys.privateKey,
      address: ["172.16.0.2/32"],
      peers: [{ publicKey: keys.publicKey, endpoint: "engage.cloudflareclient.com:2408" }],
      workers: 2,
      domainStrategy: "ForceIPv4"
    } }] };

    expect(validateStrictXrayConfig(config, { xrayVersion }).issues.filter((issue) => issue.severity === "error")).toEqual([]);
    await expectXrayAccepts(config);
  });
});

describe("real Xray binary: MASQUE and XDrive", () => {
  const masqueInbound = (address?: string[]): Inbound => {
    const inbound = createDefaultInboundForProtocol({ protocol: "masque", tag: "masque-in", port: 8443 });
    return { ...inbound, ...(address ? { address } : {}), security: { type: "tls", serverName: "masque.example.com", alpn: ["h3", "h2"] } } as Inbound;
  };
  const xdriveInbound = (decryption: string, transport: XDriveTransport = { type: "xdrive", service: "local", remoteFolder: join(tmpdir(), "xck-xdrive-binary") }): Inbound => ({
    ...createDefaultInboundForProtocol({ protocol: "vless", tag: "vless-xdrive", port: 8444, security: "none" }),
    decryption,
    transport
  }) as Inbound;
  const masqueOutbound = (masqueSettings: JsonObject): Outbound => ({
    protocol: "masque",
    tag: "masque-out",
    settings: { address: "masque.example.com", port: 443, remoteDNS: ["1.1.1.1"] },
    streamSettings: { network: "masque", security: "tls", tlsSettings: { serverName: "masque.example.com", alpn: ["h2"] }, masqueSettings }
  });

  masqueIt("accepts the default MASQUE inbound", async () => {
    await expectXrayAccepts(buildOrThrow(createProfile({ inbounds: [masqueInbound()] })));
  });

  masqueIt("rejects a MASQUE subnet address exactly like the kit does", async () => {
    const built = buildXrayConfig(createProfile({ inbounds: [masqueInbound(["10.0.0.0/24"])] }), { xrayVersion, mode: "permissive" });
    expect(built.issues.map((issue) => issue.code)).toContain("XCK_SEMANTIC_MASQUE_ADDRESS_NOT_HOST");

    const result = await testXrayConfig(built.config, { binaryPath, timeoutMs: 30_000 });
    expect(result.ok).toBe(false);
    expect(result.stdout + result.stderr).toContain("is not a host address");
  });

  xdriveIt("accepts VLESS inbound and outbound XDrive streams", async () => {
    // XDrive needs VLESS Encryption on both sides and mux on the outbound; the kit generates the pair like "xray vlessenc".
    const { decryption, encryption } = (await generateVlessEncryption()).x25519;
    const outbound: Outbound = {
      protocol: "vless",
      tag: "vless-xdrive-out",
      settings: { address: "www.googleapis.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption },
      streamSettings: {
        network: "xdrive",
        security: "tls",
        tlsSettings: { serverName: "www.googleapis.com" },
        xdriveSettings: { service: "Google Drive", remoteFolder: "1AbCdEf", secrets: ["id", "secret", "refresh"] }
      },
      mux: { enabled: true }
    };

    await expectXrayAccepts(buildOrThrow(createProfile({ inbounds: [xdriveInbound(decryption)], outbounds: [outbound] })));
  });

  xdriveNewestIt("accepts a VLESS XDrive inbound with the google-drive service spelling", async () => {
    const { decryption } = (await generateVlessEncryption()).x25519;
    const inbound = xdriveInbound(decryption, { type: "xdrive", service: "google-drive", remoteFolder: "1AbCdEf", secrets: ["id", "secret", "refresh"] });
    await expectXrayAccepts(buildOrThrow(createProfile({ inbounds: [inbound] })));
  });

  xdriveRulesIt("rejects an XDrive VLESS inbound without VLESS Encryption exactly like the kit does", async () => {
    const built = buildXrayConfig(createProfile({ inbounds: [xdriveInbound("none")] }), { xrayVersion, mode: "permissive" });
    expect(built.issues.map((issue) => issue.code)).toContain("XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION");

    const result = await testXrayConfig(built.config, { binaryPath, timeoutMs: 30_000 });
    expect(result.ok).toBe(false);
    expect(result.stdout + result.stderr).toContain('the xdrive transport needs VLESS "decryption"');
  });

  masqueIt("accepts a MASQUE outbound with Basic auth and a templated path", async () => {
    const outbound = masqueOutbound({ path: "/.well-known/masque/ip/{target}/{ipproto}/", user: "alice@example.com", pass: "alice-masque-pass-1" });
    await expectXrayAccepts(buildOrThrow(createProfile({ outbounds: [outbound] })));
  });

  warpIt("accepts a MASQUE WARP outbound with generated P-256 keys", async () => {
    const outbound = masqueOutbound({ warp: { ...warpKeys(), address: ["172.16.0.2/32", "2606:4700:110:8a36::1/128"] } });
    await expectXrayAccepts(buildOrThrow(createProfile({ outbounds: [outbound] })));
  });

  xmuxIt("accepts a MASQUE outbound with an xmux Int32Range string", async () => {
    await expectXrayAccepts(buildOrThrow(createProfile({ outbounds: [masqueOutbound({ xmux: { maxConcurrency: "16-32" } })] })));
  });

  xmuxIt("accepts a MASQUE outbound with mux enabled and the kit only warns", async () => {
    const outbound: Outbound = { ...masqueOutbound({}), mux: { enabled: true } };
    const built = buildXrayConfig(createProfile({ outbounds: [outbound] }), { xrayVersion, mode: "permissive" });
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect(built.issues.map((issue) => issue.code)).toContain("XCK_SEMANTIC_MASQUE_MUX_UNSUPPORTED");
    await expectXrayAccepts(buildOrThrow(createProfile({ outbounds: [outbound] })));
  });

  xmuxIt("rejects MASQUE xmux with both maxConnections and maxConcurrency exactly like the kit does", async () => {
    const outbound = masqueOutbound({ xmux: { maxConnections: 2, maxConcurrency: "16-32" } });
    const built = buildXrayConfig(createProfile({ outbounds: [outbound] }), { xrayVersion, mode: "permissive" });
    expect(built.issues.map((issue) => issue.code)).toContain("XCK_SEMANTIC_MASQUE_XMUX_CONFLICT");

    const result = await testXrayConfig(built.config, { binaryPath, timeoutMs: 30_000 });
    expect(result.ok).toBe(false);
    expect(result.stdout + result.stderr).toContain("maxConnections cannot be specified together with maxConcurrency");
  });

  describe("XDrive xmux", () => {
    const localTransport = (xmux: JsonObject): XDriveTransport => ({ type: "xdrive", service: "local", remoteFolder: join(tmpdir(), "xck-xdrive-binary"), xmux: xmux as XDriveTransport["xmux"] });
    const accepted = [{}, { maxConcurrency: "16-32" }, { maxConnections: 4, hMaxReusableSecs: "1800-3000", hKeepAlivePeriod: 30 }, { maxConnections: 0, maxConcurrency: "16-32" },
      { maxConnections: "-3--1", maxConcurrency: 8 }, { cMaxReuseTimes: 64, hMaxRequestTimes: "600-900" }];
    const conflicts = [{ maxConnections: 2, maxConcurrency: "16-32" }, { maxConnections: "1-3", maxConcurrency: 16 }, { maxConnections: "-1-2", maxConcurrency: "4" }];

    xdriveXmuxIt("accepts every XDrive xmux the kit accepts, on the inbound and the outbound", async () => {
      const { decryption, encryption } = (await generateVlessEncryption()).x25519;
      for (const xmux of accepted) {
        const outbound: Outbound = {
          protocol: "vless",
          tag: "vless-xdrive-out",
          settings: { address: "www.googleapis.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption },
          streamSettings: { network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com" },
            xdriveSettings: { service: "google-drive", remoteFolder: "1AbCdEf", secrets: ["id", "secret", "refresh"], xmux } },
          mux: { enabled: true }
        };
        const verdict = await xrayVerdict(buildOrThrow(createProfile({ inbounds: [xdriveInbound(decryption, localTransport(xmux))], outbounds: [outbound] })));
        expect(verdict.ok, `${JSON.stringify(xmux)}: ${verdict.output}`).toBe(true);
      }
    });

    xdriveXmuxIt("rejects XDrive xmux with both maxConnections and maxConcurrency exactly like the kit does", async () => {
      const { decryption } = (await generateVlessEncryption()).x25519;
      for (const xmux of conflicts) {
        const built = buildXrayConfig(createProfile({ inbounds: [xdriveInbound(decryption, localTransport(xmux))] }), { xrayVersion, mode: "permissive" });
        expect(built.issues.map((issue) => issue.code), JSON.stringify(xmux)).toContain("XCK_SEMANTIC_XDRIVE_XMUX_CONFLICT");
        const verdict = await xrayVerdict(built.config);
        expect(verdict.ok, JSON.stringify(xmux)).toBe(false);
        expect(verdict.output).toContain("maxConnections cannot be specified together with maxConcurrency");
      }
    });
  });

  describe("XDrive over h3", () => {
    const drive = { service: "google-drive", remoteFolder: "1AbCdEf", secrets: ["id", "secret", "refresh"] };
    const noise = { type: "noise", settings: { noise: [{ rand: "50-100" }] } };
    const salamander = { type: "salamander", settings: { password: "p" } };
    const h3Outbound = (encryption: string, finalmask: JsonObject): Outbound => ({
      protocol: "vless",
      tag: "vless-xdrive-h3",
      settings: { address: "www.googleapis.com", port: 443, id: "11111111-1111-4111-8111-111111111111", encryption },
      streamSettings: { network: "xdrive", security: "tls", tlsSettings: { serverName: "www.googleapis.com", alpn: ["h3"] }, xdriveSettings: drive, finalmask },
      mux: { enabled: true }
    });
    const expectBothReject = async (profile: Profile, code: string, xrayText: string) => {
      const built = buildXrayConfig(profile, { xrayVersion, mode: "permissive" });
      expect(built.issues.map((issue) => issue.code)).toContain(code);
      const verdict = await xrayVerdict(built.config);
      expect(verdict.ok).toBe(false);
      expect(verdict.output).toContain(xrayText);
    };

    xdriveH3It("accepts the noise udp mask and bbr congestion to Google Drive over h3", async () => {
      const { encryption } = (await generateVlessEncryption()).x25519;
      await expectXrayAccepts(buildOrThrow(createProfile({ outbounds: [h3Outbound(encryption, { udp: [noise], quicParams: { congestion: "bbr" } })] })));
    });

    xdriveH3It("rejects another udp mask to Google Drive over h3 exactly like the kit does, on both sides", async () => {
      const { decryption, encryption } = (await generateVlessEncryption()).x25519;
      const text = 'over h3 to Google Drive the only "udp" mask that works is "noise"';
      await expectBothReject(createProfile({ outbounds: [h3Outbound(encryption, { udp: [noise, salamander] })] }), "XCK_SEMANTIC_XDRIVE_H3_UDP_MASK", text);
      const inbound = { ...xdriveInbound(decryption, { type: "xdrive", ...drive }), security: { type: "tls", serverName: "drive.example.com", alpn: ["h3"] },
        streamAdvanced: { finalmask: { udp: [salamander] } } } as Inbound;
      await expectBothReject(createProfile({ inbounds: [inbound] }), "XCK_SEMANTIC_XDRIVE_H3_UDP_MASK", text);
    });

    xdriveBeforeH3It("accepts any udp mask and brutal over h3 before XDrive h3, and the kit does not flag them", async () => {
      const { encryption } = (await generateVlessEncryption()).x25519;
      const profile = createProfile({ outbounds: [h3Outbound(encryption, { udp: [salamander], quicParams: { congestion: "brutal", brutalUp: "10 mbps" } })] });
      const built = buildXrayConfig(profile, { xrayVersion, mode: "permissive" });
      expect(built.issues.map((issue) => issue.code).filter((code) => code.startsWith("XCK_SEMANTIC_XDRIVE_H3"))).toEqual([]);
      await expectXrayAccepts(built.config);
    });

    xdriveH3It("rejects brutal congestion over h3 exactly like the kit does", async () => {
      const { encryption } = (await generateVlessEncryption()).x25519;
      for (const congestion of ["brutal", "force-brutal"]) {
        await expectBothReject(createProfile({ outbounds: [h3Outbound(encryption, { quicParams: { congestion, brutalUp: "10 mbps" } })] }),
          "XCK_SEMANTIC_XDRIVE_H3_CONGESTION", "brutal is for Hysteria servers");
      }
    });
  });
});

describe("real Xray binary: finalmask filter", () => {
  const filterInbound = (finalmask: JsonObject): Inbound => ({
    ...createDefaultInboundForProtocol({ protocol: "vless", tag: "vless-filter", port: 8445, security: "none" }),
    streamAdvanced: { finalmask }
  }) as Inbound;
  const filter = (settings: JsonObject) => ({ type: "filter", settings });

  filterIt("accepts tcp and udp filter masks with every IP rule the kit accepts", async () => {
    const finalmask = { tcp: [filter({ blockedSourceIPs: acceptedIpRules })], udp: [filter({ allowedSourceIPs: acceptedIpRules })] };
    await expectXrayAccepts(buildOrThrow(createProfile({ inbounds: [filterInbound(finalmask)] })));
  });

  filterIt("rejects each IP rule exactly like the kit does", async () => {
    for (const rule of rejectedIpRules) {
      const built = buildXrayConfig(createProfile({ inbounds: [filterInbound({ tcp: [filter({ blockedSourceIPs: [rule] })] })] }), { xrayVersion, mode: "permissive" });
      expect(built.issues.map((issue) => issue.code), JSON.stringify(rule)).toContain("XCK_SEMANTIC_FINALMASK_FILTER_IP_RULE");
      const verdict = await xrayVerdict(built.config);
      expect(verdict.ok, JSON.stringify(rule)).toBe(false);
      expect(verdict.output).toContain('invalid "blockedSourceIPs"');
    }
  });

  beforeFilterIt("rejects the filter mask before Xray added it, and so does the kit", async () => {
    const built = buildXrayConfig(createProfile({ inbounds: [filterInbound({ tcp: [filter({ blockedSourceIPs: ["192.0.2.0/24"] })] })] }), { xrayVersion, mode: "permissive" });
    expect(built.issues.map((issue) => issue.code)).toContain("XCK_SEMANTIC_FINALMASK_FILTER_UNSUPPORTED");
    expect(validateStrictXrayConfig(built.config, { xrayVersion }).issues.map((issue) => issue.code)).toContain("XCK_XRAY_STRICT_UNKNOWN_FINALMASK");
    const verdict = await xrayVerdict(built.config);
    expect(verdict.ok).toBe(false);
    expect(verdict.output).toContain("unknown config id: filter");
  });
});
