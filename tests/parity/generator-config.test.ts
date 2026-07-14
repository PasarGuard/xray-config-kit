import { describe, expect, it } from "bun:test";
import parityConfig from "../../xray-parity.config.ts";
import { xrayParityManifest } from "../../src/index.js";

describe("xray parity generator config", () => {
  it("records the codegen config, release inputs, and output intent in the generated manifest", () => {
    const generatedReleaseInputs: readonly string[] = xrayParityManifest.source.releaseInputs;
    const configuredReleases: readonly string[] = parityConfig.releases;

    expect(xrayParityManifest.source.config).toBe("xray-parity.config.ts");
    expect(generatedReleaseInputs).toEqual(configuredReleases);
    expect(xrayParityManifest.source.selectedTags).toEqual(["v25.10.15", "v26.4.25", "v26.5.3", "v26.6.22"]);
    expect(xrayParityManifest.source.tags).toEqual(["v25.10.15", "v26.4.25", "v26.5.3", "v26.6.22", "v26.6.27"]);
    expect(parityConfig.outputs).toEqual({
      capabilities: "src/adapters/xray/generated-capabilities.ts",
      ciMatrix: ".github/xray-ci-matrix.json",
      manifest: "src/xray-json/parity-manifest.ts",
      testHelpers: "tests/helpers/xray-releases.ts",
      types: "src/xray-json/parity-types.ts"
    });
  });
});
