import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray transport alias coverage", () => {
  it("accepts every transport alias registered by the selected xray-core release", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    for (const network of Object.keys(release.transportAliases)) {
      const result = validateStrictXrayConfig({
        inbounds: [
          {
            protocol: "vless",
            tag: `vless-${network}`,
            port: 443,
            settings: { clients: [], decryption: "none" },
            streamSettings: {
              network,
              security: "none"
            }
          }
        ]
      }, { releaseTag: release.tag });

      expect(result.ok, `${network}: ${result.issues.map((issue) => issue.message).join("; ")}`).toBe(true);
    }
  });
});
