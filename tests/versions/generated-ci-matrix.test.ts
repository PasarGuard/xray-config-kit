import { describe, expect, it } from "bun:test";
import parityConfig from "../../xray-parity.config.ts";
import { xrayParityManifest } from "../../src/index.js";

type XrayCiMatrix = {
  readonly include: readonly {
    readonly "xray-release": string;
  }[];
};

describe("generated Xray CI matrix", () => {
  it("mirrors configured release inputs and keeps latest as a binary-test row", async () => {
    const matrix = await Bun.file(new URL("../../.github/xray-ci-matrix.json", import.meta.url)).json() as XrayCiMatrix;
    const matrixReleases = matrix.include.map((item) => item["xray-release"]);

    expect(matrixReleases).toEqual(parityConfig.releases);
    expect(matrixReleases).toContain("latest");
    expect(xrayParityManifest.source.releaseInputs).toEqual(parityConfig.releases);
    expect(xrayParityManifest.source.tags).not.toContain("latest");
  });
});
