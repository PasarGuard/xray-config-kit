import { describe, expect, it } from "bun:test";
import {
  buildXrayConfig,
  createProfile,
  expandMasquePathTemplate,
  MASQUE_DEFAULTS,
  MASQUE_LIMITS,
  validateInboundDraft
} from "../../src/index.js";
import type { Inbound, MasqueInbound, MasqueTransport } from "../../src/index.js";
import { masqueSettingsIssues } from "../../src/core/validate-masque-xdrive.js";

const masque = (overrides: Partial<MasqueInbound> = {}): MasqueInbound => ({ kind: "inbound", protocol: "masque", tag: "masque-in", port: 443,
  clients: [{ protocol: "masque", email: "alice@example.com", pass: "alice-masque-pass-1" }], address: ["10.14.0.1/16", "fd14::1/64"],
  security: { type: "tls", serverName: "masque.example.com", alpn: ["h3", "h2"] }, transport: { type: "masque" }, ...overrides });
const codes = (inbound: Inbound) => validateInboundDraft(inbound).map((issue) => `${issue.severity} ${issue.code} ${issue.path}`);
/** Every path variable Xray expands, with its expansion. */
const pathVariables = [
  ["{target}", "*"],
  ["{ipproto}", "*"],
  ["{?target,ipproto}", "?target=*&ipproto=*"],
  ["{?ipproto,target}", "?ipproto=*&target=*"],
  ["{&target,ipproto}", "&target=*&ipproto=*"],
  ["{&ipproto,target}", "&ipproto=*&target=*"]
] as const;

describe("MASQUE validation", () => {
  it("exports MASQUE defaults and expands path templates like Xray", () => {
    expect(MASQUE_DEFAULTS.path).toBe("/.well-known/masque/ip/*/*/");
    expect(MASQUE_LIMITS).toEqual({ minMtu: 1280, maxMtu: 65535 });
    expect(expandMasquePathTemplate("/.well-known/masque/ip/{target}/{ipproto}/")).toBe("/.well-known/masque/ip/*/*/");
    for (const [variable, expansion] of pathVariables) expect(expandMasquePathTemplate(`/m${variable}`), variable).toBe(`/m${expansion}`);
  });

  it("accepts a well-formed MASQUE inbound", () => expect(codes(masque())).toEqual([]));

  it("rejects subnet, broadcast and too-small address prefixes", () => {
    for (const entry of ["10.0.0.0/24", "10.0.0.255/24", "10.0.0.1/31"]) {
      expect(codes(masque({ address: [entry] })), entry).toEqual(["error XCK_SEMANTIC_MASQUE_ADDRESS_NOT_HOST /address/0"]);
    }
    expect(validateInboundDraft(masque({ address: ["10.0.0.0/24"] }))[0]?.suggestion).toContain("10.0.0.1/24");
    expect(codes(masque({ address: ["fd00::1/127"] }))).toEqual(["error XCK_SEMANTIC_MASQUE_ADDRESS_POOL_EMPTY /address/0"]);
    expect(codes(masque({ address: ["10.0.0.1/24"] }))).toEqual([]);
    expect(codes(masque({ address: ["fd00::1/64"] }))).toEqual([]);
  });

  it("rejects missing, malformed and duplicate-family addresses", () => {
    expect(codes(masque({ address: [] }))).toEqual(["error XCK_SEMANTIC_MASQUE_ADDRESS_REQUIRED /address"]);
    expect(codes(masque({ address: ["10.0.0.1"] }))).toEqual(["error XCK_SEMANTIC_MASQUE_ADDRESS_INVALID /address/0"]);
    expect(codes(masque({ address: ["::ffff:10.0.0.1/120"] }))).toEqual(["error XCK_SEMANTIC_MASQUE_ADDRESS_INVALID /address/0"]);
    expect(codes(masque({ address: ["10.0.0.1/24", "10.1.0.1/24"] }))).toEqual(["error XCK_SEMANTIC_MASQUE_ADDRESS_FAMILY_DUPLICATE /address/1"]);
  });

  it("enforces MTU 0 or 1280-65535", () => {
    expect(codes(masque({ mtu: 1000 }))).toEqual(["error XCK_SEMANTIC_MASQUE_MTU /mtu"]);
    expect(codes(masque({ mtu: 65536 }))).toEqual(["error XCK_SEMANTIC_MASQUE_MTU /mtu"]);
    for (const mtu of [0, 1280, 65535]) expect(codes(masque({ mtu })), String(mtu)).toEqual([]);
  });

  it("requires TLS", () => expect(codes(masque({ security: { type: "none" } }))).toEqual(["error XCK_SEMANTIC_MASQUE_TLS_REQUIRED /security"]));

  it("requires a colon-free email per client and rejects case-insensitive duplicates", () => {
    expect(codes(masque({ clients: [{ protocol: "masque", pass: "alice-masque-pass-1" }] }))).toEqual(["error XCK_SEMANTIC_MASQUE_CLIENT_EMAIL /clients/0/email"]);
    expect(codes(masque({ clients: [{ protocol: "masque", email: "a:b", pass: "alice-masque-pass-1" }] }))).toEqual(["error XCK_SEMANTIC_MASQUE_CLIENT_EMAIL /clients/0/email"]);
    expect(codes(masque({ clients: [
      { protocol: "masque", email: "Alice@example.com", pass: "alice-masque-pass-1" },
      { protocol: "masque", email: "alice@example.com", pass: "other-masque-pass-2" }] }))).toEqual(["error XCK_SEMANTIC_DUPLICATE_CLIENT /clients/1"]);
  });

  it("names the duplicated email in the MASQUE duplicate-client message", () => {
    const [issue] = validateInboundDraft(masque({ clients: [
      { protocol: "masque", email: "Alice@example.com", pass: "alice-masque-pass-1" },
      { protocol: "masque", email: "alice@example.com", pass: "other-masque-pass-2" }] }));
    expect(issue?.message).toBe("Client email \"alice@example.com\" is duplicated within the same inbound (MASQUE compares emails case-insensitively).");
    expect(issue?.suggestion).toBe("Give each MASQUE client a unique email. First occurrence is /inbounds/1/clients/0.");
  });

  it("flags short passwords and empty client lists", () => {
    expect(codes(masque({ clients: [{ protocol: "masque", email: "alice@example.com", pass: "short" }] }))).toEqual(["warning XCK_SECURITY_WEAK_CLIENT_SECRET /clients/0/pass"]);
    expect(codes(masque({ clients: [] }))).toEqual(["warning XCK_SEMANTIC_MISSING_CLIENTS /clients"]);
  });

  it("requires IP remoteDNS entries", () => {
    expect(codes(masque({ remoteDNS: ["dns.google"] }))).toEqual(["error XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID /remoteDNS/0"]);
    expect(codes(masque({ remoteDNS: ["1.1.1.1", "2606:4700:4700::1111"] }))).toEqual([]);
  });

  it("validates the masque transport path, host and headers", () => {
    const transport = (extra: Partial<MasqueTransport>) => masque({ transport: { type: "masque", ...extra } });
    expect(codes(transport({ path: "masque" }))).toEqual(["error XCK_SEMANTIC_MASQUE_PATH /transport/path"]);
    expect(codes(transport({ path: "/m/{foo}" }))).toEqual(["error XCK_SEMANTIC_MASQUE_PATH /transport/path"]);
    for (const [variable] of pathVariables) expect(codes(transport({ path: `/m${variable}` })), variable).toEqual([]);
    expect(codes(transport({ host: "https://masque.example.com" }))).toEqual(["error XCK_SEMANTIC_MASQUE_HOST /transport/host"]);
    expect(codes(transport({ headers: { Host: "x", "Capsule-Protocol": "?1", "Bad Header": "x" } }))).toEqual([
      "error XCK_SEMANTIC_MASQUE_HEADER /transport/headers/Host",
      "error XCK_SEMANTIC_MASQUE_HEADER /transport/headers/Capsule-Protocol",
      "error XCK_SEMANTIC_MASQUE_HEADER /transport/headers/Bad Header"
    ]);
    expect(codes(transport({ headers: { "a/b~c": "x" } }))).toEqual(["error XCK_SEMANTIC_MASQUE_HEADER /transport/headers/a~1b~0c"]);
  });

  it("accepts WARP keys wrapped over several lines, as Go's base64 decoder does", () => {
    const key = "d2FycC1wcml2YXRlLWtleS1wbGFjZWhvbGRlci0zMmI=";
    const warp = (privateKey: string) => masqueSettingsIssues({ warp: { privateKey, publicKey: key, address: ["172.16.0.2/32"] } }, "/s", "client");
    expect(warp(`${key.slice(0, 20)}\r\n${key.slice(20)}\n`)).toEqual([]);
    expect(warp(`${key.slice(0, 20)} ${key.slice(20)}`).map((issue) => `${issue.code} ${issue.path}`)).toEqual(["XCK_SEMANTIC_MASQUE_WARP_KEY /s/warp/privateKey"]);
  });

  it("warns about client-only masque fields on an inbound", () => {
    expect(codes(masque({ transport: { type: "masque", user: "u", pass: "p" } }))).toEqual([
      "warning XCK_SEMANTIC_MASQUE_CLIENT_ONLY_FIELD /transport/user",
      "warning XCK_SEMANTIC_MASQUE_CLIENT_ONLY_FIELD /transport/pass"
    ]);
  });

  it("rejects the masque transport on other protocols", () => {
    const vless = { kind: "inbound", protocol: "vless", tag: "v", port: 443, clients: [], security: { type: "tls" }, transport: { type: "masque" }, decryption: "none" } as Inbound;
    expect(codes(vless)).toContain("error XCK_SEMANTIC_MASQUE_TRANSPORT_PROTOCOL /transport/type");
  });

  it("rejects MASQUE when the selected Xray predates it", () => {
    const built = buildXrayConfig(createProfile({ inbounds: [masque()] }), { xrayVersion: "26.7.28" });
    expect(built.config).toEqual({});
    expect(built.issues.map((issue) => `${issue.code} ${issue.path}`)).toEqual(expect.arrayContaining([
      "XCK_COMPAT_FEATURE_UNSUPPORTED /inbounds/1/protocol", "XCK_COMPAT_FEATURE_UNSUPPORTED /inbounds/1/transport/type"]));
  });
});
