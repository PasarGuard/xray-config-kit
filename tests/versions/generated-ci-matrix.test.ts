import { describe, expect, it } from "bun:test";
import parityConfig from "../../xray-parity.config.ts";
import { xrayParityManifest } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

type XrayCiMatrix = {
  readonly include: readonly {
    readonly "xray-release": string;
  }[];
};

describe("generated Xray CI matrix", () => {
  it("lists every generated, downloadable release and ends with the newest generated one", async () => {
    const matrix = await Bun.file(new URL("../../.github/xray-ci-matrix.json", import.meta.url)).json() as XrayCiMatrix;
    const matrixReleases = matrix.include.map((item) => item["xray-release"]);
    const withdrawn: readonly string[] = parityConfig.withdrawnReleases;
    const generatedTags: readonly string[] = xrayParityManifest.source.tags;

    // Withdrawn releases have no downloadable binary, so CI skips them while parity data keeps them. Rows are concrete
    // tags ("latest" is resolved by the generator), and release.yml installs the last row.
    expect(matrixReleases).toEqual(generatedTags.filter((tag) => !withdrawn.includes(tag)));
    for (const release of withdrawn) {
      expect(matrixReleases).not.toContain(release);
      expect(generatedTags).toContain(release);
    }
    expect(matrixReleases).not.toContain("latest");
    expect(matrixReleases.at(-1)).toBe(latestGeneratedRelease.tag);
    expect(xrayParityManifest.source.releaseInputs).toEqual(parityConfig.releases);
    expect(xrayParityManifest.source.tags).not.toContain("latest");
  });
});
