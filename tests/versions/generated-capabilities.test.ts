import { describe, expect, it } from "bun:test";
import { generatedXrayCapabilitiesByTag } from "../../src/adapters/xray/generated-capabilities.js";
import { getCapabilities, getXrayParityReleases, type XrayCapabilities } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

const capabilitiesByTag = generatedXrayCapabilitiesByTag as Readonly<Record<string, XrayCapabilities>>;

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

describe("generated Xray adapter capabilities", () => {
  it("matches manifest protocols, transports, security, fingerprints, and ALPN for every release", () => {
    for (const release of getXrayParityReleases()) {
      const capabilities = capabilitiesByTag[release.tag];
      if (!capabilities) throw new Error(`Missing generated capabilities for ${release.tag}.`);

      const protocols = uniqueSorted([
        ...release.inboundProtocols.map((entry) => entry.protocol),
        ...release.outboundProtocols.map((entry) => entry.protocol)
      ]);
      const transports = Object.keys(release.transportAliases).sort();
      const securities = release.securityTypes.filter((item) => item !== "xtls").sort();

      expect(capabilities.protocols).toEqual(protocols);
      expect(capabilities.transports).toEqual(transports);
      expect(capabilities.securities).toEqual(securities);
      expect([...capabilities.fingerprints].sort()).toEqual([...release.fingerprints].sort());
      expect([...capabilities.alpn].sort()).toEqual([...release.alpn].sort());

      for (const feature of [...protocols, ...transports, ...securities]) {
        expect(
          capabilities.compatibilityMatrix[feature],
          `${release.tag} generated matrix should support ${feature}`
        ).toMatchObject({ supported: true });
      }
    }
  });

  it("defaults public capabilities to the latest generated release", () => {
    expect(getCapabilities()).toEqual(capabilitiesByTag[latestGeneratedRelease.tag]);
  });
});
