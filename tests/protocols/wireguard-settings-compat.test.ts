import { describe, expect, it } from "bun:test";
import { validateStrictXrayConfig } from "../../src/index.js";
import { latestGeneratedRelease } from "../helpers/xray-releases.js";

describe("wireguard settings compatibility", () => {
  it("accepts Xray WireGuard DNS and kernelMode settings aliases", () => {
    const result = validateStrictXrayConfig({
      outbounds: [
        {
          tag: "warp",
          protocol: "wireguard",
          settings: {
            secretKey: "Your_Secret_Key",
            DNS: "1.1.1.1",
            address: ["172.16.0.2/32"],
            peers: [
              {
                publicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                endpoint: "engage.cloudflareclient.com:2408"
              }
            ],
            kernelMode: false
          }
        }
      ]
    }, { releaseTag: latestGeneratedRelease.tag });

    expect(result.ok, result.issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ")).toBe(true);
  });
});
