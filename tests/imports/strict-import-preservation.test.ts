import { describe, expect, it } from "bun:test";
import { importXrayConfig, validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray import preservation vs strict parity", () => {
  it("preserves unknown import JSON but strict Xray mode rejects the same unknown fields", () => {
    const raw = {
      unknownTopLevel: { keep: true },
      inbounds: [
        {
          protocol: "unknown-in",
          tag: "raw-in",
          port: 10000,
          settings: { keep: true }
        }
      ],
      outbounds: [
        {
          protocol: "unknown-out",
          tag: "raw-out",
          settings: { keep: true }
        }
      ]
    };

    const imported = importXrayConfig(raw);
    expect(imported.unmanaged).toBe(2);
    expect(imported.profile.unknown?.pointers["/unknownTopLevel"]).toEqual({ keep: true });
    expect(imported.issues.map((issue) => issue.code)).toEqual(expect.arrayContaining([
      "XCK_IMPORT_UNKNOWN_TOP_LEVEL",
      "XCK_IMPORT_UNMANAGED_INBOUND",
      "XCK_IMPORT_UNMANAGED_OUTBOUND"
    ]));

    const strict = validateStrictXrayConfig(raw, { releaseTag: latestGeneratedRelease.tag });
    expect(strict.ok).toBe(false);
    expect(strict.issues.map((issue) => issue.code)).toEqual(expect.arrayContaining([
      "XCK_XRAY_STRICT_UNKNOWN_FIELD",
      "XCK_XRAY_STRICT_UNKNOWN_INBOUND_PROTOCOL",
      "XCK_XRAY_STRICT_UNKNOWN_OUTBOUND_PROTOCOL"
    ]));
  });
});
