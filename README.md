# Xray Config Kit

`xray-config-kit` is a TypeScript-first, version-aware engine for Xray-core configuration JSON.

It is not a panel, database model, process supervisor, or frontend form manager. It provides typed profile schemas, validation, analysis, import, compilation to Xray JSON, diffing, migrations, presets, client link/subscription generation, frontend-safe helpers, and backend-only helpers for testing configs with real Xray binaries.

The root export is browser-safe. Import `xray-config-kit/node` only on the backend.

## Environment Variables

Copy `.env.example` to `.env` and configure the required environment variables for development and testing.

## Current Scope

- Xray adapters: generated capability and compatibility behavior from selected Xray-core releases, with CI binary checks against those releases and upstream latest.
- Xray-first parity layer: generated manifest from Xray `infra/conf` selected releases and strict Xray JSON validation.
- Editable inbound models: VMess, VLESS, Trojan, Shadowsocks, Hysteria, HTTP, Mixed/SOCKS, Dokodemo/Tunnel, TUN, WireGuard.
- Transports: TCP/RAW, gRPC, XHTTP/SplitHTTP, WebSocket, HTTPUpgrade, mKCP, Hysteria.
- Security: none, expanded TLS, REALITY where compatible.
- Advanced stream settings: explicit `sockopt`, `finalmask`, `quicParams`, and raw stream patches.
- Importers: raw Xray JSON into editable typed nodes where supported, with unmanaged preservation for unknown sections.
- Outbounds: typed core outbounds plus raw-preserving proxy outbounds for HTTP, SOCKS, Shadowsocks, VMess, VLESS, Trojan, Hysteria, WireGuard, and Loopback.
- Exporters: VMess/VLESS/Trojan/Shadowsocks links, WireGuard config text, link subscriptions, and Xray JSON outbound subscriptions.
- Frontend helpers: default inbound drafts, capability flags, field visibility, and draft validation.

## Example

```ts
import {
  buildXrayConfig,
  createProfile,
  generateClientLink,
  validateProfile,
} from "xray-config-kit";

const profile = createProfile({
  presets: ["dns-simple", "routing-private-direct"],
  inbounds: [
    {
      kind: "inbound",
      protocol: "vless",
      tag: "vless-reality",
      port: 443,
      clients: [{ protocol: "vless", id: "11111111-1111-4111-8111-111111111111", email: "alice" }],
      security: {
        type: "reality",
        serverNames: ["www.example.com"],
        privateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        shortIds: ["a1b2c3d4"],
        target: "www.example.com:443",
      },
      transport: { type: "tcp", header: { type: "none" } },
    },
  ],
});

const validation = validateProfile(profile, { xrayVersion: "26.5.3" });
const built = buildXrayConfig(profile, { xrayVersion: "26.5.3" });
const link = generateClientLink(profile, {
  inboundTag: "vless-reality",
  clientId: "alice",
  host: "edge.example.com",
});
```

## Frontend Flow

Use the browser-safe root export:

```ts
import {
  createDefaultInbound,
  getInboundFieldVisibility,
  getInboundFormCapabilities,
  validateInboundDraft,
} from "xray-config-kit";

const capabilities = getInboundFormCapabilities({ xrayVersion: "26.5.3" });
const draft = createDefaultInbound({ protocol: "vless", transport: "xhttp", security: "reality" });
const visible = getInboundFieldVisibility(draft, capabilities);
const issues = validateInboundDraft(draft, { mode: "permissive" });
```

Frontend code should own form drafts, validation display, live JSON preview, and diffs. It should not own raw Xray JSON as the primary state.

## Backend Flow

Use the root export for final compile and `xray-config-kit/node` for binary checks:

```ts
import { buildXrayConfig, validateProfile } from "xray-config-kit";
import { testXrayConfig } from "xray-config-kit/node";

const validation = validateProfile(profile, { mode: "strict", xrayVersion: "26.5.3" });
const built = buildXrayConfig(profile, { mode: "strict", xrayVersion: "26.5.3" });
const test = await testXrayConfig(built.config, { binaryPath: process.env.XRAY_BINARY });
```

The host application should handle atomic writes, backups, service restart/reload, health checks, and rollback. Those process-control responsibilities are intentionally outside the frontend-safe package boundary.

## Xray-First Strict Validation

Use strict Xray validation when the input is raw Xray JSON and must match Xray-core exactly for a selected release:

```ts
import { validateStrictXrayConfig } from "xray-config-kit";

const result = validateStrictXrayConfig(config, { xrayVersion: "26.5.3" });
if (!result.ok) {
  console.log(result.issues);
}
```

The parity manifest, strict types, adapter capabilities, test helpers, and CI matrix are generated from `xray-core/infra/conf` using the root `xray-parity.config.ts` codegen config:

```powershell
bun run generate:parity
```

Configure the Xray core directory in your `.env` file (see `.env.example`). The config controls the source repo, release list, and generated outputs:

```ts
export default {
  source: { repo: "XTLS/Xray-core", pathEnv: "XRAY_CORE_DIR" },
  releases: ["v25.10.15", "v26.4.25", "v26.5.3", "latest"],
  outputs: {
    manifest: "src/xray-json/parity-manifest.ts",
    types: "src/xray-json/parity-types.ts",
    capabilities: "src/adapters/xray/generated-capabilities.ts",
    ciMatrix: ".github/xray-ci-matrix.json",
    testHelpers: "tests/helpers/xray-releases.ts"
  }
};
```

Omitting `xrayVersion` uses the latest generated release. Requesting a version newer than the generated parity data returns `XCK_XRAY_PARITY_VERSION_UNGENERATED`; fetch Xray-core tags and run `bun run generate:parity` to add the new release data. Non-exact in-range versions resolve to the nearest lower generated release and emit a compatibility warning.

## Exports

- `xray-config-kit`: browser-safe core APIs.
- `xray-config-kit/frontend`: explicit browser-safe alias.
- `xray-config-kit/schemas`: Zod schemas and generated JSON Schema helper.
- `xray-config-kit/presets`: preset catalog and preset application helper.
- `xray-config-kit/adapters`: adapter registry and compatibility matrix.
- `xray-config-kit/xray-json`: low-level Xray JSON helper types.
- `xray-config-kit/exporters/client-links`: client link helpers.
- `xray-config-kit/exporters/subscriptions`: subscription helpers.
- `xray-config-kit/exporters/wireguard`: WireGuard config helper.
- `xray-config-kit/testing`: browser-safe golden fixture helpers.
- `xray-config-kit/node`: backend-only Xray binary discovery and `xray run -test` wrapper.

## Real Binary Tests

Set environment variables in your `.env` file to run the optional integration test:

```powershell
bun run test
```

See `.env.example` for required variables.
