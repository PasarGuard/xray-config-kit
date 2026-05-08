# PasarGuard Xray Config Kit

Browser-safe TypeScript helpers for generating, validating, importing, analyzing, and exporting Xray-core configuration JSON.

## Package

```ts
import {
  createDefaultInbound,
  createDefaultXrayCoreConfigJson,
  generateClientLink,
  validateStrictXrayConfig
} from "@pasarguard/xray-config-kit";
```

## Commands

```powershell
bun install
bun run typecheck
bun run build
bun test
```

## Exports

- `@pasarguard/xray-config-kit`
- `@pasarguard/xray-config-kit/frontend`
- `@pasarguard/xray-config-kit/generators`
- `@pasarguard/xray-config-kit/exporters/uris`
- `@pasarguard/xray-config-kit/node`

Use the root export in frontend code. Use `/node` only in backend code.
