import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, getXrayParityReleases, xrayParityManifest } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray parity manifest", () => {
  it("tracks selected xray-core releases from infra/conf", () => {
    const releases = getXrayParityReleases();

    expect(releases.map((release) => release.tag)).toEqual(["v25.10.15", "v26.4.25", "v26.5.3"]);
    expect(xrayParityManifest.source.selectedTags).toEqual(["v25.10.15", "v26.4.25", "v26.5.3"]);
  });

  it("captures loader protocols, top-level sections, and stream aliases", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });

    expect(release.topLevelKeys).toContain("reverse");
    expect(release.topLevelKeys).toContain("transport");
    expect(release.inboundProtocols.map((entry) => entry.protocol)).toEqual([
      "dokodemo-door",
      "http",
      "hysteria",
      "mixed",
      "shadowsocks",
      "socks",
      "trojan",
      "tun",
      "tunnel",
      "vless",
      "vmess",
      "wireguard"
    ]);
    expect(release.outboundProtocols.map((entry) => entry.protocol)).toContain("hysteria");
    expect(release.transportAliases.xhttp).toBe("splithttp");
    expect(release.transportAliases.quic).toBeUndefined();
  });
});
