import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, getXrayParityReleases } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray json loader manifest coverage", () => {
  it("keeps inbound and outbound loader cache entries aligned with public protocol lists", () => {
    for (const release of getXrayParityReleases()) {
      const inboundLoader = release.jsonLoaders["infra/conf/xray.go:inboundConfigLoader"] ?? [];
      const outboundLoader = release.jsonLoaders["infra/conf/xray.go:outboundConfigLoader"] ?? [];

      expect(inboundLoader, `${release.tag} inbound loader`).toEqual(release.inboundProtocols);
      expect(outboundLoader, `${release.tag} outbound loader`).toEqual(release.outboundProtocols);
    }
  });

  it("has struct definitions for every generated JSON loader target", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    const missing = Object.values(release.jsonLoaders)
      .flat()
      .filter((entry) => release.structs[entry.config] === undefined)
      .map((entry) => `${entry.protocol}:${entry.config}`);

    expect(missing).toEqual([]);
  });

  it("captures transport header and finalmask loaders separately from stream network aliases", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    const tcpHeader = release.jsonLoaders["infra/conf/transport_internet.go:tcpHeaderLoader"] ?? [];
    const tcpMask = release.jsonLoaders["infra/conf/transport_internet.go:tcpmaskLoader"] ?? [];
    const udpMask = release.jsonLoaders["infra/conf/transport_internet.go:udpmaskLoader"] ?? [];

    expect(tcpHeader.map((entry) => entry.protocol)).toEqual(expect.arrayContaining(["http", "none"]));
    expect(tcpMask.map((entry) => entry.protocol)).toEqual(expect.arrayContaining(["fragment", "header-custom", "sudoku"]));
    expect(udpMask.map((entry) => entry.protocol)).toEqual(expect.arrayContaining([
      "header-dns",
      "mkcp-aes128gcm",
      "mkcp-original",
      "noise",
      "salamander",
      "xdns"
    ]));
    expect(Object.keys(release.transportAliases)).toEqual(expect.arrayContaining(["tcp", "raw", "xhttp", "grpc"]));
  });
});
