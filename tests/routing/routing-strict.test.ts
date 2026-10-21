import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { presetCatalog } from "../../src/presets/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray routing strict parity", () => {
  it("accepts router fields and raw rule bodies that xray-core loads dynamically", () => {
    const result = validateStrictXrayConfig({
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
          {
            type: "field",
            ruleTag: "block-private",
            ip: ["geoip:private"],
            outboundTag: "block"
          }
        ],
        balancers: [
          {
            tag: "balanced",
            selector: ["proxy-"],
            fallbackTag: "direct"
          }
        ]
      },
      outbounds: [
        { protocol: "blackhole", tag: "block", settings: {} },
        { protocol: "freedom", tag: "direct", settings: {} }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => issue.message).join("; ")).toBe(true);
  });

  it("rejects unknown router wrapper fields while preserving raw rule flexibility", () => {
    const result = validateStrictXrayConfig({
      routing: {
        rules: [
          {
            type: "field",
            kitOnlyInsideRawRule: true
          }
        ],
        kitOnlyRoutingWrapper: true
      }
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(["/routing/kitOnlyRoutingWrapper"]);
  });
});

describe("routing presets", () => {
  it("routes Iran domains with a geosite code the stock Xray geo files have", () => {
    // geosite:ir exists only in third-party geosite files; Xray release zips ship category-ir.
    const rules = presetCatalog["regional-ir-direct"].profile.routing?.rules ?? [];
    expect(rules.map((rule) => [rule.domain, rule.ip])).toEqual([[["geosite:category-ir"], undefined], [undefined, ["geoip:ir"]]]);
  });
});
