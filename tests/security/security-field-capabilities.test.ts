import { describe, expect, it } from "bun:test";
import { getInboundFormCapabilities } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("inbound form security field capabilities track real per-release struct fields", () => {
  it("does not report echForceQuery as supported once removed from TLSConfig (v26.6.22+)", () => {
    const v26_6_22 = getInboundFormCapabilities({ xrayVersion: "26.6.22" });
    expect(v26_6_22.securityFields.tls.echForceQuery).toBeFalsy();
    expect(v26_6_22.securityFieldDefinitions.tls.echForceQuery).toBeUndefined();
    expect(v26_6_22.securityFieldOrderByType.tls).not.toContain("echForceQuery");

    const latest = getInboundFormCapabilities({ xrayVersion: latestGeneratedRelease.version });
    expect(latest.securityFields.tls.echForceQuery).toBeFalsy();
    expect(latest.securityFieldDefinitions.tls.echForceQuery).toBeUndefined();
  });

  it("still reports echForceQuery as supported on releases where TLSConfig genuinely has it", () => {
    const v26_5_3 = getInboundFormCapabilities({ xrayVersion: "26.5.3" });
    expect(v26_5_3.securityFields.tls.echForceQuery).toBe(true);
    expect(v26_5_3.securityFieldDefinitions.tls.echForceQuery).toBeDefined();
  });

  it("does not report pinnedPeerCertSha256/verifyPeerCertByName as supported before they existed (v25.10.15)", () => {
    const v25_10_15 = getInboundFormCapabilities({ xrayVersion: "25.10.15" });
    expect(v25_10_15.securityFields.tls.pinnedPeerCertSha256).toBeFalsy();
    expect(v25_10_15.securityFields.tls.verifyPeerCertByName).toBeFalsy();
    expect(v25_10_15.securityFieldDefinitions.tls.pinnedPeerCertSha256).toBeUndefined();
    expect(v25_10_15.securityFieldDefinitions.tls.verifyPeerCertByName).toBeUndefined();
  });

  it("still reports pinnedPeerCertSha256/verifyPeerCertByName as supported once they exist (v26.4.25+)", () => {
    const v26_4_25 = getInboundFormCapabilities({ xrayVersion: "26.4.25" });
    expect(v26_4_25.securityFields.tls.pinnedPeerCertSha256).toBe(true);
    expect(v26_4_25.securityFields.tls.verifyPeerCertByName).toBe(true);
  });
});
