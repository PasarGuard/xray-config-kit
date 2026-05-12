import { getXrayParityRelease, type XrayParityLoaderEntry, type XrayParityStructField } from "../../xray-json/parity.js";

export type XrayGeneratedFormField = XrayParityStructField;

export type XrayOutboundFormMetadata = {
  readonly protocols: readonly XrayParityLoaderEntry[];
  readonly envelopeFields: readonly XrayGeneratedFormField[];
  readonly streamFields: readonly XrayGeneratedFormField[];
  readonly muxFields: readonly XrayGeneratedFormField[];
  readonly proxySettingsFields: readonly XrayGeneratedFormField[];
  readonly settingsFieldsByProtocol: Readonly<Record<string, readonly XrayGeneratedFormField[]>>;
};

/** Inbound detour + per-protocol settings, derived from the same Xray parity structs as outbounds. */
export type XrayInboundFormMetadata = {
  readonly protocols: readonly XrayParityLoaderEntry[];
  readonly envelopeFields: readonly XrayGeneratedFormField[];
  readonly streamFields: readonly XrayGeneratedFormField[];
  readonly securityFieldsByType: Readonly<Record<string, readonly XrayGeneratedFormField[]>>;
  /** Per `Transport.type` — parity structs for `tcpSettings`, `grpcSettings`, etc. */
  readonly transportSettingsByType: Readonly<Record<string, readonly XrayGeneratedFormField[]>>;
  readonly settingsFieldsByProtocol: Readonly<Record<string, readonly XrayGeneratedFormField[]>>;
};

/** Kit `Transport.type` → Xray parity struct name in `release.structs` (stream network settings). */
export const TRANSPORT_TYPE_TO_PARITY_STRUCT: Readonly<Record<string, string>> = {
  tcp: "TCPConfig",
  grpc: "GRPCConfig",
  xhttp: "SplitHTTPConfig",
  ws: "WebSocketConfig",
  httpupgrade: "HttpUpgradeConfig",
  kcp: "KCPConfig",
  hysteria: "HysteriaConfig"
} as const;

type VersionOptions = {
  readonly xrayVersion?: string;
};

function uniqueFields(fields: readonly XrayGeneratedFormField[]): XrayGeneratedFormField[] {
  const seen = new Set<string>();
  const output: XrayGeneratedFormField[] = [];
  for (const field of fields) {
    if (seen.has(field.json)) continue;
    seen.add(field.json);
    output.push(field);
  }
  return output;
}

function structFields(structs: Readonly<Record<string, readonly XrayGeneratedFormField[]>>, name: string): readonly XrayGeneratedFormField[] {
  return structs[name] ?? [];
}

export function fieldFlags(fields: readonly XrayGeneratedFormField[]): Record<string, boolean> {
  return Object.fromEntries(fields.map((field) => [field.json, true]));
}

export function fieldDefinitions(fields: readonly XrayGeneratedFormField[]): Record<string, XrayGeneratedFormField> {
  return Object.fromEntries(fields.map((field) => [field.json, field]));
}

export function getGeneratedRoutingRuleFields(options: VersionOptions = {}): readonly XrayGeneratedFormField[] {
  const release = getXrayParityRelease(options);
  return uniqueFields([
    ...structFields(release.structs, "RouterRule"),
    ...structFields(release.structs, "RawFieldRule"),
    { json: "type", go: "Type", type: "string" }
  ]);
}

export function getGeneratedOutboundFormMetadata(options: VersionOptions = {}): XrayOutboundFormMetadata {
  const release = getXrayParityRelease(options);
  const settingsFieldsByProtocol = Object.fromEntries(release.outboundProtocols.map((entry) => [
    entry.protocol,
    structFields(release.structs, entry.config)
  ]));

  return {
    protocols: release.outboundProtocols,
    envelopeFields: structFields(release.structs, "OutboundDetourConfig"),
    streamFields: release.streamFields,
    muxFields: structFields(release.structs, "MuxConfig"),
    proxySettingsFields: structFields(release.structs, "ProxyConfig"),
    settingsFieldsByProtocol
  };
}

export function getGeneratedInboundFormMetadata(options: VersionOptions = {}): XrayInboundFormMetadata {
  const release = getXrayParityRelease(options);
  const settingsFieldsByProtocol = Object.fromEntries(release.inboundProtocols.map((entry) => [
    entry.protocol,
    structFields(release.structs, entry.config)
  ]));

  const transportSettingsByType = Object.fromEntries(
    Object.entries(TRANSPORT_TYPE_TO_PARITY_STRUCT).map(([transportType, structName]) => [
      transportType,
      structFields(release.structs, structName)
    ])
  );

  return {
    protocols: release.inboundProtocols,
    envelopeFields: structFields(release.structs, "InboundDetourConfig"),
    streamFields: release.streamFields,
    securityFieldsByType: {
      tls: structFields(release.structs, "TLSConfig"),
      reality: structFields(release.structs, "REALITYConfig")
    },
    transportSettingsByType,
    settingsFieldsByProtocol
  };
}

export function getGeneratedRoutingBalancerFields(options: VersionOptions = {}): readonly XrayGeneratedFormField[] {
  const release = getXrayParityRelease(options);
  return uniqueFields(structFields(release.structs, "BalancingRule"));
}

export function getGeneratedBalancingStrategyFields(options: VersionOptions = {}): readonly XrayGeneratedFormField[] {
  const release = getXrayParityRelease(options);
  return structFields(release.structs, "StrategyConfig");
}
