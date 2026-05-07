import { describe, expect, it } from "bun:test";
import {
  buildXrayConfig,
  createProfile,
  getCapabilities,
  validateProfile,
  validateStrictXrayConfig
} from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

function issueCodes(issues: readonly { readonly code: string }[]): string[] {
  return issues.map((issue) => issue.code);
}

function versionAfter(version: string): string {
  const [major = 0] = version.split(".").map((part) => Number(part));
  return `${major + 1}.0.0`;
}

describe("newer-than-generated Xray version handling", () => {
  it("rejects newer-than-generated versions across strict, profile, build, and capability APIs", () => {
    const newerThanGenerated = versionAfter(latestGeneratedRelease.version);
    const profile = createProfile({ name: "newer-than-generated-release" });
    const strict = validateStrictXrayConfig({}, { xrayVersion: newerThanGenerated });
    const profileValidation = validateProfile(profile, { xrayVersion: newerThanGenerated });
    const built = buildXrayConfig(profile, { xrayVersion: newerThanGenerated, mode: "permissive" });

    expect(strict.ok).toBe(false);
    expect(issueCodes(strict.issues)).toContain("XCK_XRAY_PARITY_VERSION_UNGENERATED");
    expect(profileValidation.ok).toBe(false);
    expect(issueCodes(profileValidation.issues)).toContain("XCK_XRAY_PARITY_VERSION_UNGENERATED");
    expect(built.config).toEqual({});
    expect(issueCodes(built.issues)).toContain("XCK_XRAY_PARITY_VERSION_UNGENERATED");
    expect(() => getCapabilities({ xrayVersion: newerThanGenerated })).toThrow(RangeError);
  });

  it("resolves non-exact in-range versions to nearest lower generated parity with warnings", () => {
    const inRangeVersion = "26.5.0";
    const profile = createProfile({ name: "in-range-release" });
    const strict = validateStrictXrayConfig({}, { xrayVersion: inRangeVersion });
    const profileValidation = validateProfile(profile, { xrayVersion: inRangeVersion });
    const built = buildXrayConfig(profile, { xrayVersion: inRangeVersion, mode: "permissive" });

    expect(strict.ok).toBe(true);
    expect(strict.release.tag).toBe("v26.4.25");
    expect(issueCodes(strict.issues)).toContain("XCK_XRAY_PARITY_VERSION_APPROXIMATED");
    expect(profileValidation.ok).toBe(true);
    expect(issueCodes(profileValidation.issues)).toContain("XCK_XRAY_PARITY_VERSION_APPROXIMATED");
    expect(issueCodes(built.issues)).toContain("XCK_XRAY_PARITY_VERSION_APPROXIMATED");
  });
});
