import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("xray outbound envelope strict parity", () => {
  it("accepts outbound mux and proxySettings fields declared by xray-core", () => {
    const result = validateStrictXrayConfig({
      outbounds: [
        {
          protocol: "freedom",
          tag: "direct",
          sendThrough: "127.0.0.1",
          settings: {},
          proxySettings: {
            tag: "upstream",
            transportLayer: true
          },
          mux: {
            enabled: true,
            concurrency: 8,
            xudpConcurrency: 16,
            xudpProxyUDP443: "reject"
          },
          targetStrategy: "UseIP"
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => issue.message).join("; ")).toBe(true);
  });

  it("rejects unknown outbound mux and proxySettings fields", () => {
    const result = validateStrictXrayConfig({
      outbounds: [
        {
          protocol: "freedom",
          tag: "direct",
          settings: {},
          proxySettings: {
            notFromXray: true
          },
          mux: {
            notFromXray: true
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "/outbounds/0/proxySettings/notFromXray",
      "/outbounds/0/mux/notFromXray"
    ]));
  });
});
