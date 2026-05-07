import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray top-level app sections", () => {
  it("accepts every top-level key declared by xray-core Config", () => {
    const release = getXrayParityRelease({ releaseTag: latestGeneratedRelease.tag });
    const config = Object.fromEntries(release.topLevelKeys.map((key) => {
      if (key === "inbounds" || key === "outbounds") return [key, []];
      return [key, {}];
    }));

    const result = validateStrictXrayConfig(config, { releaseTag: release.tag });

    expect(result.ok, result.issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ")).toBe(true);
  });
});
