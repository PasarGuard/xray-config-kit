import { describe, expect, it } from "bun:test";
import { getXrayParityReleases, importXrayConfig, validateInboundDraft, validateOutboundDraft, validateStrictXrayConfig, xrayParityManifest } from "../../src/index.js";
import type { Inbound, Issue, JsonObject, Outbound } from "../../src/index.js";
import { xrayIpRuleProblem } from "../../src/core/validate-finalmask.js";
import { acceptedIpRules, rejectedIpRules } from "../helpers/ip-rules.js";
import { rebuildWithoutSource } from "../helpers/profile-round-trip.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

const filterMask = (settings: JsonValueLike) => ({ type: "filter", settings });
type JsonValueLike = JsonObject | string | null;

const inbound = (finalmask: JsonObject): Inbound => ({
  kind: "inbound",
  protocol: "vless",
  tag: "vless-filter",
  port: 443,
  clients: [],
  decryption: "none",
  security: { type: "none" },
  transport: { type: "tcp" },
  streamAdvanced: { finalmask }
}) as Inbound;
const outbound = (finalmask: JsonObject): Outbound => ({
  protocol: "freedom",
  tag: "direct",
  settings: {},
  streamSettings: { network: "tcp", finalmask }
}) as Outbound;
const codes = (issues: Issue[]) => issues.map((issue) => `${issue.severity} ${issue.code} ${issue.path}`).filter((row) => row.includes("FINALMASK"));
const firstFilterRelease = getXrayParityReleases().find((release) =>
  !(xrayParityManifest.source.withdrawnTags as readonly string[]).includes(release.tag)
  && Object.entries(release.jsonLoaders).some(([name, entries]) => name.endsWith(":tcpmaskLoader") && entries.some((entry) => entry.protocol === "filter")))!;

describe("finalmask filter", () => {
  it("parses IP rules like Xray's geodata.ParseIPRules", () => {
    for (const rule of acceptedIpRules) expect(xrayIpRuleProblem(rule), JSON.stringify(rule)).toBeUndefined();
    for (const rule of rejectedIpRules) expect(xrayIpRuleProblem(rule), JSON.stringify(rule)).toBeString();
    expect(xrayIpRuleProblem("192.0.2.0/33")).toBe("the CIDR prefix length 33 exceeds 32");
    expect(xrayIpRuleProblem("::ffff:1.2.3.4/96")).toBe("the CIDR prefix length 96 exceeds 32");
    expect(xrayIpRuleProblem("ext::cn")).toBe("the geo file name is empty");
  });

  it("accepts filter masks on both sides with IP rules Xray parses", () => {
    const finalmask = { tcp: [filterMask({ blockedSourceIPs: acceptedIpRules })], udp: [filterMask({ allowedSourceIPs: ["10.0.0.0/8", "geoip:private"], blockedSourceIPs: null })] };
    expect(codes(validateInboundDraft(inbound(finalmask)))).toEqual([]);
    expect(codes(validateOutboundDraft(outbound(finalmask)))).toEqual([]);
    expect(codes(validateInboundDraft(inbound({ tcp: [{ type: "filter" }, filterMask(null), filterMask({})] })))).toEqual([]);
  });

  it("rejects each IP rule Xray refuses, with the entry's path", () => {
    for (const rule of rejectedIpRules) {
      expect(codes(validateInboundDraft(inbound({ tcp: [filterMask({ blockedSourceIPs: ["10.0.0.0/8", rule] })] }))), JSON.stringify(rule))
        .toEqual(["error XCK_SEMANTIC_FINALMASK_FILTER_IP_RULE /streamAdvanced/finalmask/tcp/0/settings/blockedSourceIPs/1"]);
    }
    expect(codes(validateOutboundDraft(outbound({ udp: [{ type: "noise" }, { type: "Filter", settings: { allowedSourceIPs: ["192.0.2.0/33"] } }] }))))
      .toEqual(["error XCK_SEMANTIC_FINALMASK_FILTER_IP_RULE /streamSettings/finalmask/udp/1/settings/allowedSourceIPs/0"]);
    expect(validateInboundDraft(inbound({ tcp: [filterMask({ blockedSourceIPs: ["192.0.2.0/33"] })] })).find((issue) => issue.code === "XCK_SEMANTIC_FINALMASK_FILTER_IP_RULE")?.message)
      .toBe('Finalmask filter blockedSourceIPs entry "192.0.2.0/33" is not a valid IP rule: the CIDR prefix length 33 exceeds 32.');
  });

  it("rejects filter settings that do not have Xray's shape", () => {
    expect(codes(validateInboundDraft(inbound({ tcp: [filterMask("10.0.0.0/8")] })))).toEqual(["error XCK_SEMANTIC_FINALMASK_FILTER_SETTINGS /streamAdvanced/finalmask/tcp/0/settings"]);
    expect(codes(validateInboundDraft(inbound({ tcp: [filterMask({ blockedSourceIPs: "10.0.0.0/8" })] }))))
      .toEqual(["error XCK_SEMANTIC_FINALMASK_FILTER_SETTINGS /streamAdvanced/finalmask/tcp/0/settings/blockedSourceIPs"]);
    expect(codes(validateInboundDraft(inbound({ tcp: [filterMask({ allowedSourceIPs: [24] })] }))))
      .toEqual(["error XCK_SEMANTIC_FINALMASK_FILTER_IP_RULE /streamAdvanced/finalmask/tcp/0/settings/allowedSourceIPs/0"]);
  });

  it("leaves other mask types alone, including ones the kit does not know", () => {
    const finalmask = { tcp: [{ type: "fragment", settings: { packets: "tlshello" } }, { type: "bogus-mask" }], udp: [{ type: "salamander", settings: { password: "p" } }] };
    expect(codes(validateInboundDraft(inbound(finalmask)))).toEqual([]);
    expect(validateStrictXrayConfig({ inbounds: [{ protocol: "vless", tag: "in", port: 443, settings: { clients: [], decryption: "none" }, streamSettings: { network: "tcp", finalmask } }] },
      { releaseTag: latestGeneratedRelease.tag }).issues).toEqual([]);
  });

  it("reports that filter needs a newer Xray when validating for an older release", () => {
    const finalmask = { tcp: [filterMask({ blockedSourceIPs: ["192.0.2.0/24"] })], udp: [filterMask({ blockedSourceIPs: ["192.0.2.0/33"] })] };
    expect(codes(validateInboundDraft(inbound(finalmask), { xrayVersion: "26.10.17" }))).toEqual([
      "error XCK_SEMANTIC_FINALMASK_FILTER_UNSUPPORTED /streamAdvanced/finalmask/tcp/0/type",
      "error XCK_SEMANTIC_FINALMASK_FILTER_UNSUPPORTED /streamAdvanced/finalmask/udp/0/type"
    ]);
    expect(validateOutboundDraft(outbound(finalmask), { xrayVersion: "26.9.30" }).find((issue) => issue.code === "XCK_SEMANTIC_FINALMASK_FILTER_UNSUPPORTED")?.message)
      .toBe(`The finalmask "filter" mask needs Xray ${firstFilterRelease.tag} or newer.`);
  });

  it("keeps filter masks through import and build", () => {
    const streamSettings = { network: "tcp", security: "none", finalmask: { tcp: [filterMask({ blockedSourceIPs: ["192.0.2.0/24", "geoip:private"] })], udp: [filterMask({ allowedSourceIPs: ["10.0.0.0/8"] })] } };
    const raw = { inbounds: [{ tag: "vless-filter", port: 443, protocol: "vless", settings: { clients: [], decryption: "none" }, streamSettings }] };
    const { built } = rebuildWithoutSource(raw);
    expect(built.issues.filter((issue) => issue.severity === "error")).toEqual([]);
    expect((built.config.inbounds?.[0]?.streamSettings as JsonObject).finalmask).toEqual(streamSettings.finalmask);
    expect(importXrayConfig(raw).profile.inbounds[0]).toMatchObject({ streamAdvanced: { finalmask: streamSettings.finalmask } });
  });

  describe("strict JSON", () => {
    const config = (finalmask: JsonObject) => ({ inbounds: [{ protocol: "vless", tag: "in", port: 443, settings: { clients: [], decryption: "none" }, streamSettings: { network: "tcp", finalmask } }] });
    const summary = (issues: Issue[]) => issues.map((issue) => `${issue.code} ${issue.severity} ${issue.path}`);

    it("accepts tcp and udp filter masks in the latest release and checks their settings keys", () => {
      const finalmask = { tcp: [filterMask({ blockedSourceIPs: ["192.0.2.0/24"], allowedSourceIPs: [] })], udp: [{ type: "FILTER", settings: { allowedSourceIPs: ["10.0.0.0/8"] } }] };
      expect(validateStrictXrayConfig(config(finalmask), { releaseTag: latestGeneratedRelease.tag }).issues).toEqual([]);
      expect(summary(validateStrictXrayConfig(config({ tcp: [filterMask({ blockedIPs: ["192.0.2.0/24"] })] }), { releaseTag: latestGeneratedRelease.tag }).issues))
        .toEqual(["XCK_XRAY_STRICT_UNKNOWN_FIELD error /inbounds/1/streamSettings/finalmask/tcp/0/settings/blockedIPs"]);
    });

    it("rejects filter masks for releases whose loaders do not have them", () => {
      const result = validateStrictXrayConfig(config({ tcp: [filterMask({ blockedSourceIPs: ["192.0.2.0/24"] })], udp: [filterMask({})] }), { releaseTag: "v26.10.17" });
      expect(result.ok).toBe(false);
      expect(summary(result.issues)).toEqual([
        "XCK_XRAY_STRICT_UNKNOWN_FINALMASK error /inbounds/1/streamSettings/finalmask/tcp/0/type",
        "XCK_XRAY_STRICT_UNKNOWN_FINALMASK error /inbounds/1/streamSettings/finalmask/udp/0/type"
      ]);
      expect(result.issues[0]?.message).toBe(`Finalmask tcp mask "filter" is not accepted by v26.10.17; it needs Xray ${firstFilterRelease.tag} or newer.`);
    });

    it("reports only the unknown finalmask key for a release without finalmask", () => {
      expect(summary(validateStrictXrayConfig(config({ tcp: [filterMask({})] }), { releaseTag: "v25.10.15" }).issues))
        .toEqual(["XCK_XRAY_STRICT_UNKNOWN_FIELD error /inbounds/1/streamSettings/finalmask"]);
    });
  });
});
