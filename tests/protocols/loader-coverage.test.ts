import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray protocol loader coverage", () => {
  it("accepts every inbound protocol registered by xray-core for the latest generated release", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    for (const entry of release.inboundProtocols) {
      const result = validateStrictXrayConfig({
        inbounds: [
          {
            protocol: entry.protocol,
            tag: `in-${entry.protocol}`,
            ...(entry.protocol === "tun" ? {} : { port: 10000 }),
            settings: {}
          }
        ]
      }, { releaseTag: release.tag });

      expect(result.ok, `${entry.protocol}: ${result.issues.map((issue) => issue.message).join("; ")}`).toBe(true);
    }
  });

  it("accepts every outbound protocol registered by xray-core for the latest generated release", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    for (const entry of release.outboundProtocols) {
      const result = validateStrictXrayConfig({
        outbounds: [
          {
            protocol: entry.protocol,
            tag: `out-${entry.protocol}`,
            settings: {}
          }
        ]
      }, { releaseTag: release.tag });

      expect(result.ok, `${entry.protocol}: ${result.issues.map((issue) => issue.message).join("; ")}`).toBe(true);
    }
  });
});
