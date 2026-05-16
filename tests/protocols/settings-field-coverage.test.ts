import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray protocol settings field coverage", () => {
  it("rejects unknown settings fields for every inbound loader struct", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });

    for (const entry of release.inboundProtocols) {
      const result = validateStrictXrayConfig({
        inbounds: [
          {
            protocol: entry.protocol,
            tag: `in-${entry.protocol}`,
            ...(entry.protocol === "tun" ? {} : { port: 10000 }),
            settings: {
              notFromXray: true
            }
          }
        ]
      }, { releaseTag: release.tag });

      expect(result.ok, entry.protocol).toBe(false);
      expect(result.issues.map((issue) => issue.path), entry.protocol).toContain("/inbounds/1/settings/notFromXray");
    }
  });

  it("rejects unknown settings fields for every outbound loader struct", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });

    for (const entry of release.outboundProtocols) {
      const result = validateStrictXrayConfig({
        outbounds: [
          {
            protocol: entry.protocol,
            tag: `out-${entry.protocol}`,
            settings: {
              notFromXray: true
            }
          }
        ]
      }, { releaseTag: release.tag });

      expect(result.ok, entry.protocol).toBe(false);
      expect(result.issues.map((issue) => issue.path), entry.protocol).toContain("/outbounds/1/settings/notFromXray");
    }
  });
});
