import { describe, expect, it } from "bun:test";
import { getXrayParityRelease, resolveXrayParityRelease } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

function versionAfter(version: string): string {
  const [major = 0] = version.split(".").map((part) => Number(part));
  return `${major + 1}.0.0`;
}

describe("xray parity release selection", () => {
  it("selects exact and nearest lower selected releases", () => {
    expect(getXrayParityRelease({ xrayVersion: "25.10.15" }).tag).toBe("v25.10.15");
    expect(getXrayParityRelease({ xrayVersion: "26.4.25" }).tag).toBe("v26.4.25");
    expect(getXrayParityRelease({ xrayVersion: "26.5.3" }).tag).toBe("v26.5.3");
    expect(resolveXrayParityRelease({ xrayVersion: "26.5.0" })).toMatchObject({
      ok: true,
      release: { tag: "v26.4.25" },
      issue: { code: "XCK_XRAY_PARITY_VERSION_APPROXIMATED", severity: "warning" }
    });
  });

  it("rejects versions newer than generated parity data", () => {
    const newerThanGenerated = versionAfter(latestGeneratedRelease.version);
    const resolved = resolveXrayParityRelease({ xrayVersion: newerThanGenerated });

    expect(resolved).toMatchObject({
      ok: false,
      issue: { code: "XCK_XRAY_PARITY_VERSION_UNGENERATED", severity: "error" }
    });
    expect(() => getXrayParityRelease({ xrayVersion: newerThanGenerated })).toThrow(RangeError);
  });
});
