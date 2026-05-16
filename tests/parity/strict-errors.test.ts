import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("strict xray json error surface", () => {
  it("requires the root config, inbound list, and outbound list to use Xray JSON shapes", () => {
    const root = validateStrictXrayConfig(null, { releaseTag: latestGeneratedRelease.tag });
    expect(root.ok).toBe(false);
    expect(root.issues.map((issue) => issue.code)).toContain("XCK_XRAY_STRICT_EXPECTED_OBJECT");

    const lists = validateStrictXrayConfig({
      inbounds: {},
      outbounds: {}
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(lists.ok).toBe(false);
    expect(lists.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/inbounds",
      "/outbounds"
    ]));
    expect(lists.issues.every((issue) => issue.code === "XCK_XRAY_STRICT_EXPECTED_ARRAY")).toBe(true);
  });

  it("reports missing and unknown detour protocols separately for each direction", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        { tag: "missing", port: 10000, settings: {} },
        { protocol: "not-xray-in", tag: "bad-in", port: 10001, settings: {} }
      ],
      outbounds: [
        { tag: "missing-out", settings: {} },
        { protocol: "not-xray-out", tag: "bad-out", settings: {} }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.code)).toEqual(expect.arrayContaining([
      "XCK_XRAY_STRICT_MISSING_PROTOCOL",
      "XCK_XRAY_STRICT_UNKNOWN_INBOUND_PROTOCOL",
      "XCK_XRAY_STRICT_UNKNOWN_OUTBOUND_PROTOCOL"
    ]));
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/inbounds/1/protocol",
      "/inbounds/2/protocol",
      "/outbounds/1/protocol",
      "/outbounds/2/protocol"
    ]));
  });

  it("rejects unknown detour envelope fields and non-object settings", () => {
    const result = validateStrictXrayConfig({
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          strayEnvelope: true,
          settings: "not-object"
        }
      ],
      outbounds: [
        {
          protocol: "freedom",
          tag: "direct",
          strayEnvelope: true,
          settings: "not-object",
          mux: "not-object",
          proxySettings: "not-object"
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/inbounds/1/strayEnvelope",
      "/inbounds/1/settings",
      "/outbounds/1/strayEnvelope",
      "/outbounds/1/settings",
      "/outbounds/1/mux",
      "/outbounds/1/proxySettings"
    ]));
  });

  it("downgrades unknown Xray fields to warnings in permissive mode", () => {
    const result = validateStrictXrayConfig({
      unknownTopLevel: true,
      inbounds: [
        {
          protocol: "vless",
          tag: "vless",
          port: 443,
          settings: {
            clients: [],
            decryption: "none",
            kitOnly: true
          },
          streamSettings: {
            network: "xhttp",
            security: "none",
            unknownStreamField: true
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag, mode: "permissive" });

    expect(result.ok).toBe(true);
    expect(result.config).toBeDefined();
    expect(result.issues.map((issue) => issue.severity)).toEqual(["warning", "warning", "warning"]);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/unknownTopLevel",
      "/inbounds/1/settings/kitOnly",
      "/inbounds/1/streamSettings/unknownStreamField"
    ]));
  });
});
