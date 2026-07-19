import type { XrayParityGeneratorConfig } from "./scripts/generate-xray-parity-manifest.js";

export default {
  source: {
    repo: "XTLS/Xray-core",
    pathEnv: "XRAY_CORE_DIR"
  },
  releases: [
    "v25.10.15",
    "v26.4.25",
    "v26.5.3",
    "v26.6.22",
    "v26.6.27",
    "latest"
  ],
  outputs: {
    manifest: "src/xray-json/parity-manifest.ts",
    types: "src/xray-json/parity-types.ts",
    capabilities: "src/adapters/xray/generated-capabilities.ts",
    ciMatrix: ".github/xray-ci-matrix.json",
    testHelpers: "tests/helpers/xray-releases.ts"
  }
} satisfies XrayParityGeneratorConfig;
