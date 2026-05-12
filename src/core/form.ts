import {
  fieldDefinitions,
  fieldFlags,
  getGeneratedInboundFormMetadata,
  getGeneratedOutboundFormMetadata,
  getGeneratedRoutingRuleFields,
  type XrayGeneratedFormField
} from "../adapters/xray/form-metadata.js";
import { getCapabilities } from "../adapters/xray/registry.js";
import { validateProfile } from "./validate.js";
import type {
  Inbound,
  InboundPort,
  Issue,
  JsonObject,
  Outbound,
  ProxyOutboundProtocol,
  Profile,
  RoutingBalancer,
  RoutingRule,
  Security,
  Transport,
  ValidateOptions,
  FreedomOutbound,
  BlackholeOutbound,
  DnsOutbound,
  ProxyOutbound,
  FreedomOutboundSettings,
  BlackholeOutboundSettings,
  DnsOutboundSettings,
  HttpOutboundSettings,
  SocksOutboundSettings,
  ShadowsocksOutboundSettings,
  VmessOutboundSettings,
  VlessOutboundSettings,
  TrojanOutboundSettings,
  WireGuardOutboundSettings,
  LoopbackOutboundSettings,
  StreamSettings,
  MuxSettings,
  ProxySettings
} from "./types.js";

const placeholderUuid = "00000000-0000-4000-8000-000000000000";
const placeholderKey32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

type CreateDefaultInboundBaseOptions<Protocol extends Exclude<Inbound["protocol"], "unmanaged">> = {
  readonly protocol: Protocol;
  readonly tag?: string;
  readonly listen?: string;
  readonly port?: InboundPort;
  readonly clientDefaults?: CreateDefaultInboundClientDefaults;
};

export type CreateDefaultInboundClientDefaults = "placeholder" | "empty";

export type CreateDefaultInboundOptions =
  | (CreateDefaultInboundBaseOptions<"vmess"> & {
      readonly transport?: Transport["type"];
      readonly security?: "none" | "tls";
    })
  | (CreateDefaultInboundBaseOptions<"vless"> & {
      readonly transport?: Transport["type"];
      readonly security?: Security["type"];
    })
  | (CreateDefaultInboundBaseOptions<"trojan"> & {
      readonly transport?: Transport["type"];
      readonly security?: Security["type"];
    })
  | (CreateDefaultInboundBaseOptions<"shadowsocks"> & {
      readonly transport?: Transport["type"];
      readonly security?: "none" | "tls";
    })
  | (CreateDefaultInboundBaseOptions<"hysteria"> & {
      readonly security?: "none" | "tls";
    })
  | CreateDefaultInboundBaseOptions<"http">
  | CreateDefaultInboundBaseOptions<"mixed">
  | CreateDefaultInboundBaseOptions<"socks">
  | CreateDefaultInboundBaseOptions<"dokodemo-door">
  | CreateDefaultInboundBaseOptions<"tunnel">
  | CreateDefaultInboundBaseOptions<"tun">
  | CreateDefaultInboundBaseOptions<"wireguard">;

type UnsafeCreateDefaultInboundOptions = CreateDefaultInboundBaseOptions<Exclude<Inbound["protocol"], "unmanaged">> & {
  readonly transport?: Transport["type"];
  readonly security?: Security["type"];
};

type CreateDefaultInboundOptionsFor<Protocol extends Exclude<Inbound["protocol"], "unmanaged">> =
  Extract<CreateDefaultInboundOptions, { readonly protocol: Protocol }>;

type ExactCreateDefaultInboundOptions<Options extends CreateDefaultInboundOptions> =
  Options & Record<Exclude<keyof Options, keyof CreateDefaultInboundOptionsFor<Options["protocol"]>>, never>;

type InboundForProtocol<Protocol extends Exclude<Inbound["protocol"], "unmanaged">> =
  Inbound extends infer Candidate
    ? Candidate extends { readonly protocol: infer CandidateProtocol }
      ? Protocol extends CandidateProtocol
        ? Candidate
        : never
      : never
    : never;

export type InboundFormCapabilities = {
  readonly protocols: Record<string, boolean>;
  readonly protocolConfigs: Record<string, string>;
  readonly protocolOrder: readonly string[];
  readonly transports: Record<string, boolean>;
  readonly securities: Record<string, boolean>;
  readonly securityFields: Record<string, Record<string, boolean>>;
  readonly securityFieldDefinitions: Record<string, Record<string, XrayGeneratedFormField>>;
  readonly securityFieldOrderByType: Readonly<Record<string, readonly string[]>>;
  readonly transportSettingsFields: Record<string, Record<string, boolean>>;
  readonly transportSettingsFieldDefinitions: Record<string, Record<string, XrayGeneratedFormField>>;
  readonly transportSettingsFieldOrderByType: Readonly<Record<string, readonly string[]>>;
  readonly settingsFields: Record<string, Record<string, boolean>>;
  readonly settingsFieldDefinitions: Record<string, Record<string, XrayGeneratedFormField>>;
  readonly settingsFieldOrderByProtocol: Readonly<Record<string, readonly string[]>>;
  readonly clientLinks: Record<string, boolean>;
};

export type InboundFieldVisibility = {
  readonly clients: boolean;
  readonly accounts: boolean;
  readonly wireguardPeers: boolean;
  readonly tun: boolean;
  readonly dokodemo: boolean;
  readonly stream: boolean;
  readonly tls: boolean;
  readonly reality: boolean;
  readonly shadowsocks: boolean;
  readonly sniffing: boolean;
  readonly advancedStream: boolean;
};

export type RoutingRuleFieldKey = string;

export type FormVersionOptions = {
  readonly xrayVersion?: string;
};

export type ProfileTagSource = Pick<Profile, "inbounds" | "outbounds" | "routing">;

export type RoutingRuleFormCapabilities = {
  readonly fields: Record<string, boolean>;
  readonly fieldDefinitions: Record<string, XrayGeneratedFormField>;
  /** Parity order for stable form layout (JSON keys). */
  readonly fieldOrder: readonly string[];
  readonly networks: Record<string, boolean>;
  readonly protocols: Record<string, boolean>;
  readonly inboundTags: string[];
  readonly outboundTags: string[];
  readonly balancerTags: string[];
};

export type RoutingRuleFormCapabilitiesOptions = FormVersionOptions & {
  readonly profile?: ProfileTagSource;
};

export type RoutingRuleFieldVisibility = Record<string, boolean>;

export type OutboundFormCapabilities = {
  readonly protocols: Record<string, boolean>;
  readonly protocolConfigs: Record<string, string>;
  readonly envelopeFields: Record<string, boolean>;
  readonly envelopeFieldDefinitions: Record<string, XrayGeneratedFormField>;
  /** JSON keys in parity order for envelope (e.g. sendThrough, streamSettings). */
  readonly envelopeFieldOrder: readonly string[];
  readonly settingsFields: Record<string, Record<string, boolean>>;
  readonly settingsFieldDefinitions: Record<string, Record<string, XrayGeneratedFormField>>;
  /** JSON keys per protocol in parity order for outbound `settings`. */
  readonly settingsFieldOrderByProtocol: Readonly<Record<string, readonly string[]>>;
  readonly streamFields: Record<string, boolean>;
  readonly streamFieldDefinitions: Record<string, XrayGeneratedFormField>;
  readonly streamFieldOrder: readonly string[];
  readonly muxFields: Record<string, boolean>;
  readonly muxFieldDefinitions: Record<string, XrayGeneratedFormField>;
  readonly proxySettingsFields: Record<string, boolean>;
  readonly proxySettingsFieldDefinitions: Record<string, XrayGeneratedFormField>;
};

export type OutboundFieldVisibility = {
  readonly settings: boolean;
  readonly streamSettings: boolean;
  readonly mux: boolean;
  readonly proxySettings: boolean;
  readonly raw: boolean;
};

export type CreateDefaultRoutingRuleOptions = Omit<RoutingRule, "type"> & {
  readonly type?: "field";
};

export type CreateDefaultRoutingBalancerOptions = Partial<RoutingBalancer>;

// Type-safe outbound settings based on protocol
type OutboundSettingsForProtocol<P extends Exclude<Outbound["protocol"], "unmanaged"> | "direct" | "block"> =
  P extends "freedom" | "direct" ? FreedomOutboundSettings :
  P extends "blackhole" | "block" ? BlackholeOutboundSettings :
  P extends "dns" ? DnsOutboundSettings :
  P extends "http" ? HttpOutboundSettings :
  P extends "socks" ? SocksOutboundSettings :
  P extends "shadowsocks" ? ShadowsocksOutboundSettings :
  P extends "vmess" ? VmessOutboundSettings :
  P extends "vless" ? VlessOutboundSettings :
  P extends "trojan" ? TrojanOutboundSettings :
  P extends "wireguard" ? WireGuardOutboundSettings :
  P extends "loopback" ? LoopbackOutboundSettings :
  JsonObject; // Fallback for any other protocols

export type CreateDefaultOutboundOptions<P extends Exclude<Outbound["protocol"], "unmanaged"> | "direct" | "block" = Exclude<Outbound["protocol"], "unmanaged"> | "direct" | "block"> = {
  readonly protocol: P;
  readonly tag?: string;
  readonly settings?: OutboundSettingsForProtocol<P>;
  readonly streamSettings?: StreamSettings;
  readonly mux?: MuxSettings;
  readonly proxySettings?: ProxySettings;
  readonly sendThrough?: string;
  readonly targetStrategy?: string;
};

function defaultTransport(type: Transport["type"] = "tcp"): Transport {
  if (type === "grpc") return { type: "grpc", serviceName: "" };
  if (type === "xhttp") return { type: "xhttp", path: "/", mode: "auto" };
  if (type === "ws") return { type: "ws", path: "/" };
  if (type === "httpupgrade") return { type: "httpupgrade", path: "/" };
  if (type === "kcp") return { type: "kcp" };
  if (type === "hysteria") return { type: "hysteria", version: 2, udpIdleTimeout: 60 };
  return { type: "tcp", header: { type: "none" } };
}

function defaultSecurity(type: Security["type"] = "none"): Security {
  if (type === "tls") return { type: "tls", serverName: "" };
  if (type === "reality") {
    return {
      type: "reality",
      serverNames: ["example.com"],
      privateKey: placeholderKey32,
      publicKey: placeholderKey32,
      shortIds: ["a1b2c3d4"],
      target: "example.com:443",
      fingerprint: "chrome",
      spiderX: "/"
    };
  }
  return { type: "none" };
}

function defaultNonRealitySecurity(type: "none" | "tls" = "none"): Extract<Security, { type: "none" | "tls" }> {
  if (type === "tls") return { type: "tls", serverName: "" };
  return { type: "none" };
}

function assertCreateDefaultInboundOptions(options: CreateDefaultInboundOptions): void {
  const unsafe = options as UnsafeCreateDefaultInboundOptions;
  const protocol = unsafe.protocol;
  const hasStreamSecurity = unsafe.security !== undefined;
  const hasTransport = unsafe.transport !== undefined;

  if (
    protocol === "http" ||
    protocol === "mixed" ||
    protocol === "socks" ||
    protocol === "dokodemo-door" ||
    protocol === "tunnel" ||
    protocol === "tun" ||
    protocol === "wireguard"
  ) {
    if (hasStreamSecurity) throw new TypeError(`${protocol} default inbound does not support stream security options.`);
    if (hasTransport) throw new TypeError(`${protocol} default inbound does not support transport options.`);
  }

  if (protocol === "vmess" && unsafe.security === "reality") {
    throw new TypeError("VMess default inbound supports only none or TLS security.");
  }

  if ((protocol === "shadowsocks" || protocol === "hysteria") && unsafe.security === "reality") {
    throw new TypeError(`${protocol} default inbound supports only none or TLS security.`);
  }

  if (protocol === "hysteria" && hasTransport) {
    throw new TypeError("Hysteria default inbound uses the hysteria transport and does not accept a transport option.");
  }
}

function normalizeDefaultInboundListen(listen: string | undefined): { listen?: string } {
  if (listen === undefined) return {};
  const t = listen.trim();
  if (t === "" || t === "0.0.0.0" || t === "::" || t === "[::]") return {};
  return { listen: t };
}

function defaultInboundPort(port: InboundPort | undefined): { port?: InboundPort } {
  if (port === undefined) return {};
  return { port };
}

const defaultInboundProtocols = [
  "vmess",
  "vless",
  "trojan",
  "shadowsocks",
  "hysteria",
  "http",
  "mixed",
  "socks",
  "dokodemo-door",
  "tunnel",
  "tun",
  "wireguard"
] as const satisfies readonly Exclude<Inbound["protocol"], "unmanaged">[];

function isDefaultInboundProtocol(protocol: string): protocol is Exclude<Inbound["protocol"], "unmanaged"> {
  return (defaultInboundProtocols as readonly string[]).includes(protocol);
}

const inboundSecurityFieldKeysByType = {
  tls: [
    "serverName",
    "alpn",
    "fingerprint",
    "allowInsecure",
    "enableSessionResumption",
    "disableSystemRoot",
    "minVersion",
    "maxVersion",
    "cipherSuites",
    "rejectUnknownSni",
    "curvePreferences",
    "masterKeyLog",
    "pinnedPeerCertSha256",
    "verifyPeerCertByName",
    "echServerKeys",
    "echConfigList",
    "echForceQuery",
    "echSockopt"
  ],
  reality: [
    "serverNames",
    "privateKey",
    "publicKey",
    "shortIds",
    "target",
    "fingerprint",
    "spiderX",
    "mldsa65Seed",
    "mldsa65Verify",
    "maxTimeDiff",
    "show"
  ]
} as const satisfies Readonly<Record<"tls" | "reality", readonly string[]>>;

function inboundSecurityFields(type: "tls" | "reality", rows: readonly XrayGeneratedFormField[]): readonly XrayGeneratedFormField[] {
  const byKey = new Map(rows.map((row) => [row.json, row]));
  return inboundSecurityFieldKeysByType[type].map((key) => {
    if (key === "target") return { json: "target", go: "Target", type: "string" };
    const field = byKey.get(key);
    return field ?? { json: key, go: key, type: "string" };
  });
}

export type CreateDefaultInboundForProtocolOptions = {
  readonly protocol: Exclude<Inbound["protocol"], "unmanaged">;
  readonly tag?: string;
  readonly listen?: string;
  readonly port?: InboundPort;
  readonly transport?: Transport["type"];
  readonly security?: Security["type"];
  readonly clientDefaults?: CreateDefaultInboundClientDefaults;
};

export function createDefaultInboundForProtocol(options: CreateDefaultInboundForProtocolOptions): Exclude<Inbound, { protocol: "unmanaged" }> {
  const base = {
    tag: options.tag,
    listen: options.listen,
    port: options.port,
    clientDefaults: options.clientDefaults
  };

  if (options.protocol === "vmess") {
    return createDefaultInbound({
      protocol: "vmess",
      ...base,
      transport: options.transport,
      security: options.security === "tls" ? "tls" : "none"
    });
  }

  if (options.protocol === "vless") {
    return createDefaultInbound({
      protocol: "vless",
      ...base,
      transport: options.transport,
      security: options.security
    });
  }

  if (options.protocol === "trojan") {
    return createDefaultInbound({
      protocol: "trojan",
      ...base,
      transport: options.transport,
      security: options.security
    });
  }

  if (options.protocol === "shadowsocks") {
    return createDefaultInbound({
      protocol: "shadowsocks",
      ...base,
      transport: options.transport,
      security: options.security === "tls" ? "tls" : "none"
    });
  }

  if (options.protocol === "hysteria") {
    return createDefaultInbound({
      protocol: "hysteria",
      ...base,
      security: options.security === "none" ? "none" : "tls"
    });
  }

  return createDefaultInbound({
    protocol: options.protocol as "http" | "mixed" | "socks" | "dokodemo-door" | "tunnel" | "tun" | "wireguard",
    ...base
  });
}

export function createDefaultInbound<const Options extends CreateDefaultInboundOptions>(
  options: ExactCreateDefaultInboundOptions<Options>
): InboundForProtocol<Options["protocol"]> {
  const typedOptions = options as CreateDefaultInboundOptions;
  assertCreateDefaultInboundOptions(typedOptions);

  const tag = typedOptions.tag ?? "";
  const listenFields = normalizeDefaultInboundListen(typedOptions.listen);
  const portFields = defaultInboundPort(typedOptions.port);

  if (typedOptions.protocol === "vmess") {
    return {
      kind: "inbound",
      protocol: "vmess",
      tag,
      ...listenFields,
      ...portFields,
      clients: typedOptions.clientDefaults === "empty"
        ? []
        : [{ protocol: "vmess", id: placeholderUuid, security: "auto", email: "user" }],
      security: typedOptions.security === "tls" ? { type: "tls", serverName: "" } : { type: "none" },
      transport: defaultTransport(typedOptions.transport)
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "vless") {
    return {
      kind: "inbound",
      protocol: "vless",
      tag,
      ...listenFields,
      ...portFields,
      clients: typedOptions.clientDefaults === "empty"
        ? []
        : [{ protocol: "vless", id: placeholderUuid, email: "user" }],
      security: defaultSecurity(typedOptions.security),
      transport: defaultTransport(typedOptions.transport),
      decryption: "none"
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "trojan") {
    return {
      kind: "inbound",
      protocol: "trojan",
      tag,
      ...listenFields,
      ...portFields,
      clients: typedOptions.clientDefaults === "empty"
        ? []
        : [{ protocol: "trojan", password: "change-me-trojan-password", email: "user" }],
      security: defaultSecurity(typedOptions.security === "reality" ? "reality" : typedOptions.security ?? "tls"),
      transport: defaultTransport(typedOptions.transport)
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "shadowsocks") {
    const usesStreamSettings = typedOptions.security !== undefined || typedOptions.transport !== undefined;
    const useEmptyClients = typedOptions.clientDefaults === "empty";
    const inbound: Extract<Inbound, { protocol: "shadowsocks" }> = {
      kind: "inbound",
      protocol: "shadowsocks",
      tag,
      ...listenFields,
      ...portFields,
      method: useEmptyClients ? undefined : "2022-blake3-aes-256-gcm",
      password: useEmptyClients ? undefined : "change-me-server-password",
      network: "tcp,udp",
      clients: useEmptyClients ? [] : [{ protocol: "shadowsocks", password: "change-me-client-password", email: "user" }]
    };
    if (!usesStreamSettings) return inbound as InboundForProtocol<Options["protocol"]>;
    return {
      ...inbound,
      security: defaultNonRealitySecurity(typedOptions.security),
      transport: defaultTransport(typedOptions.transport)
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "hysteria") {
    return {
      kind: "inbound",
      protocol: "hysteria",
      tag,
      ...listenFields,
      ...portFields,
      version: 2,
      clients: typedOptions.clientDefaults === "empty"
        ? []
        : [{ protocol: "hysteria", auth: "change-me-hysteria-auth", email: "user" }],
      security: typedOptions.security === "none" ? { type: "none" } : { type: "tls", serverName: "" },
      transport: { type: "hysteria", version: 2, udpIdleTimeout: 60 }
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "http") {
    return {
      kind: "inbound",
      protocol: "http",
      tag,
      ...listenFields,
      ...portFields,
      accounts: [{ user: "user", pass: "change-me-http-password" }]
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "mixed" || typedOptions.protocol === "socks") {
    return {
      kind: "inbound",
      protocol: typedOptions.protocol,
      tag,
      ...listenFields,
      ...portFields,
      auth: "password",
      accounts: [{ user: "user", pass: "change-me-socks-password" }],
      udp: true,
      ip: "127.0.0.1"
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "dokodemo-door" || typedOptions.protocol === "tunnel") {
    return {
      kind: "inbound",
      protocol: typedOptions.protocol,
      tag,
      ...listenFields,
      ...portFields,
      network: "tcp"
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "tun") {
    return {
      kind: "inbound",
      protocol: "tun",
      tag,
      ...listenFields,
      name: "xray0",
      mtu: 1500,
      gateway: ["198.18.0.1/15"],
      dns: ["1.1.1.1"],
      autoOutboundsInterface: "auto"
    } as InboundForProtocol<Options["protocol"]>;
  }

  return {
    kind: "inbound",
    protocol: "wireguard",
    tag,
    ...listenFields,
    ...portFields,
    secretKey: placeholderKey32,
    publicKey: placeholderKey32,
    address: ["10.0.0.1/24"],
    peers: [
      {
        publicKey: placeholderKey32,
        allowedIPs: ["10.0.0.2/32"],
        keepAlive: 25
      }
    ],
    mtu: 1420,
    noKernelTun: false
  } as InboundForProtocol<Options["protocol"]>;
}

export function getInboundFormCapabilities(options: { readonly xrayVersion?: string } = {}): InboundFormCapabilities {
  const capabilities = getCapabilities(options);
  const metadata = getGeneratedInboundFormMetadata(options);
  const protocolRows = metadata.protocols.filter((entry) => isDefaultInboundProtocol(entry.protocol));
  const securityFieldRowsByType = Object.fromEntries(
    Object.entries(metadata.securityFieldsByType).map(([type, rows]) => [
      type,
      type === "tls" || type === "reality" ? inboundSecurityFields(type, rows) : rows
    ])
  );
  const settingsFieldOrderByProtocol = Object.fromEntries(
    Object.entries(metadata.settingsFieldsByProtocol).map(([protocol, rows]) => [protocol, rows.map((row) => row.json)])
  );
  const securityFieldOrderByType = Object.fromEntries(
    Object.entries(securityFieldRowsByType).map(([type, rows]) => [type, rows.map((row) => row.json)])
  );
  const transportFieldRowsByType = metadata.transportSettingsByType;
  const transportSettingsFieldOrderByType = Object.fromEntries(
    Object.entries(transportFieldRowsByType).map(([type, rows]) => [type, rows.map((row) => row.json)])
  );
  return {
    protocols: Object.fromEntries(protocolRows.map((entry) => [entry.protocol, true])),
    protocolConfigs: Object.fromEntries(protocolRows.map((entry) => [entry.protocol, entry.config])),
    protocolOrder: protocolRows.map((entry) => entry.protocol),
    transports: Object.fromEntries(capabilities.transports.map((item) => [item, true])),
    securities: Object.fromEntries(capabilities.securities.map((item) => [item, true])),
    securityFields: Object.fromEntries(Object.entries(securityFieldRowsByType).map(([type, rows]) => [
      type,
      fieldFlags(rows)
    ])),
    securityFieldDefinitions: Object.fromEntries(Object.entries(securityFieldRowsByType).map(([type, rows]) => [
      type,
      fieldDefinitions(rows)
    ])),
    securityFieldOrderByType,
    transportSettingsFields: Object.fromEntries(Object.entries(transportFieldRowsByType).map(([type, rows]) => [
      type,
      fieldFlags(rows)
    ])),
    transportSettingsFieldDefinitions: Object.fromEntries(Object.entries(transportFieldRowsByType).map(([type, rows]) => [
      type,
      fieldDefinitions(rows)
    ])),
    transportSettingsFieldOrderByType,
    settingsFields: Object.fromEntries(Object.entries(metadata.settingsFieldsByProtocol).map(([protocol, rows]) => [
      protocol,
      fieldFlags(rows)
    ])),
    settingsFieldDefinitions: Object.fromEntries(Object.entries(metadata.settingsFieldsByProtocol).map(([protocol, rows]) => [
      protocol,
      fieldDefinitions(rows)
    ])),
    settingsFieldOrderByProtocol,
    clientLinks: {
      vmess: capabilities.protocols.includes("vmess"),
      vless: capabilities.protocols.includes("vless"),
      trojan: capabilities.protocols.includes("trojan"),
      shadowsocks: capabilities.protocols.includes("shadowsocks"),
      hysteria: false,
      wireguard: capabilities.protocols.includes("wireguard")
    }
  };
}

export function getInboundFieldVisibility(draft: Inbound, _capabilities: InboundFormCapabilities = getInboundFormCapabilities()): InboundFieldVisibility {
  const stream = draft.protocol === "vmess" || draft.protocol === "vless" || draft.protocol === "trojan" || draft.protocol === "shadowsocks" || draft.protocol === "hysteria";
  const security = "security" in draft ? draft.security : undefined;
  return {
    clients: "clients" in draft,
    accounts: draft.protocol === "http" || draft.protocol === "mixed" || draft.protocol === "socks",
    wireguardPeers: draft.protocol === "wireguard",
    tun: draft.protocol === "tun",
    dokodemo: draft.protocol === "dokodemo-door" || draft.protocol === "tunnel",
    stream,
    tls: security?.type === "tls",
    reality: security?.type === "reality",
    shadowsocks: draft.protocol === "shadowsocks",
    sniffing: draft.protocol !== "wireguard",
    advancedStream: stream
  };
}

function uniqueStrings(values: readonly (string | undefined)[]): string[] {
  return [...new Set(values.filter((value): value is string => typeof value === "string" && value.length > 0))];
}

function resolveRoutingCapabilityInput(input?: ProfileTagSource | RoutingRuleFormCapabilitiesOptions): RoutingRuleFormCapabilitiesOptions {
  if (!input) return {};
  if ("profile" in input || "xrayVersion" in input) return input as RoutingRuleFormCapabilitiesOptions;
  return { profile: input as ProfileTagSource };
}

export function createDefaultRoutingRule(options: CreateDefaultRoutingRuleOptions = {}): RoutingRule {
  const rule: RoutingRule = {
    type: "field",
    ...options
  };
  if (rule.outboundTag === undefined && rule.balancerTag === undefined) {
    return { ...rule, outboundTag: "direct" };
  }
  return rule;
}

export function createDefaultRoutingBalancer(options: CreateDefaultRoutingBalancerOptions = {}): RoutingBalancer {
  return {
    tag: options.tag ?? "balanced",
    selector: options.selector ?? ["proxy-"],
    strategy: options.strategy,
    fallbackTag: options.fallbackTag
  };
}

export function getRoutingRuleFormCapabilities(input?: ProfileTagSource | RoutingRuleFormCapabilitiesOptions): RoutingRuleFormCapabilities {
  const options = resolveRoutingCapabilityInput(input);
  const fields = getGeneratedRoutingRuleFields(options);
  const profile = options.profile;
  return {
    fields: fieldFlags(fields),
    fieldDefinitions: fieldDefinitions(fields),
    fieldOrder: fields.map((field) => field.json),
    networks: {
      tcp: true,
      udp: true,
      unix: true,
      "tcp,udp": true
    },
    protocols: {
      http: true,
      tls: true,
      bittorrent: true
    },
    inboundTags: uniqueStrings(profile?.inbounds?.map((inbound) => inbound.tag) ?? []),
    outboundTags: uniqueStrings(profile?.outbounds?.map((outbound) => outbound.tag) ?? []),
    balancerTags: uniqueStrings(profile?.routing?.balancers?.map((balancer) => balancer.tag) ?? [])
  };
}

export function getRoutingRuleFieldVisibility(_draft: RoutingRule, capabilities: RoutingRuleFormCapabilities = getRoutingRuleFormCapabilities()): RoutingRuleFieldVisibility {
  return capabilities.fields;
}

export function createDefaultOutbound<P extends Exclude<Outbound["protocol"], "unmanaged"> | "direct" | "block">(options: CreateDefaultOutboundOptions<P>): Exclude<Outbound, { protocol: "unmanaged" }> {
  const protocol = options.protocol === "direct"
    ? "freedom"
    : options.protocol === "block"
      ? "blackhole"
      : options.protocol;
  const tag = options.tag ?? (protocol === "freedom" ? "direct" : protocol === "blackhole" ? "block" : `${protocol}-outbound`);
  const envelope = {
    sendThrough: options.sendThrough,
    streamSettings: options.streamSettings,
    proxySettings: options.proxySettings,
    mux: options.mux,
    targetStrategy: options.targetStrategy
  };

  if (protocol === "freedom") {
    return {
      protocol,
      tag,
      settings: options.settings,
      ...envelope
    } as FreedomOutbound;
  }

  if (protocol === "blackhole") {
    return {
      protocol,
      tag,
      settings: options.settings,
      ...envelope
    } as BlackholeOutbound;
  }

  if (protocol === "dns") {
    return {
      protocol,
      tag,
      settings: options.settings,
      ...envelope
    } as DnsOutbound;
  }

  return {
    protocol: protocol as ProxyOutboundProtocol,
    tag,
    settings: options.settings ?? {},
    raw: [],
    ...envelope
  } as ProxyOutbound;
}

export function getOutboundFormCapabilities(options: FormVersionOptions = {}): OutboundFormCapabilities {
  const metadata = getGeneratedOutboundFormMetadata(options);
  const settingsFieldOrderByProtocol = Object.fromEntries(
    Object.entries(metadata.settingsFieldsByProtocol).map(([protocol, rows]) => [protocol, rows.map((row) => row.json)])
  );

  return {
    protocols: Object.fromEntries(metadata.protocols.map((entry) => [entry.protocol, true])),
    protocolConfigs: Object.fromEntries(metadata.protocols.map((entry) => [entry.protocol, entry.config])),
    envelopeFields: fieldFlags(metadata.envelopeFields),
    envelopeFieldDefinitions: fieldDefinitions(metadata.envelopeFields),
    envelopeFieldOrder: metadata.envelopeFields.map((field) => field.json),
    settingsFields: Object.fromEntries(Object.entries(metadata.settingsFieldsByProtocol).map(([protocol, rows]) => [
      protocol,
      fieldFlags(rows)
    ])),
    settingsFieldDefinitions: Object.fromEntries(Object.entries(metadata.settingsFieldsByProtocol).map(([protocol, rows]) => [
      protocol,
      fieldDefinitions(rows)
    ])),
    settingsFieldOrderByProtocol,
    streamFields: fieldFlags(metadata.streamFields),
    streamFieldDefinitions: fieldDefinitions(metadata.streamFields),
    streamFieldOrder: metadata.streamFields.map((field) => field.json),
    muxFields: fieldFlags(metadata.muxFields),
    muxFieldDefinitions: fieldDefinitions(metadata.muxFields),
    proxySettingsFields: fieldFlags(metadata.proxySettingsFields),
    proxySettingsFieldDefinitions: fieldDefinitions(metadata.proxySettingsFields)
  };
}

export function getOutboundFieldVisibility(draft: Outbound, capabilities: OutboundFormCapabilities = getOutboundFormCapabilities()): OutboundFieldVisibility {
  if (draft.protocol === "unmanaged") {
    return {
      settings: false,
      streamSettings: false,
      mux: false,
      proxySettings: false,
      raw: true
    };
  }

  return {
    settings: Object.keys(capabilities.settingsFields[draft.protocol] ?? {}).length > 0 || "settings" in draft,
    streamSettings: capabilities.envelopeFields.streamSettings === true,
    mux: capabilities.envelopeFields.mux === true,
    proxySettings: capabilities.envelopeFields.proxySettings === true,
    raw: true
  };
}

export function validateInboundDraft(draft: Inbound, options: ValidateOptions = {}): Issue[] {
  return validateProfile({
    schemaVersion: "xck.v1",
    inbounds: [draft]
  }, options).issues.map((issue) => ({
    ...issue,
    path: issue.path.replace(/^\/inbounds\/1/, "")
  }));
}

export function validateRoutingRuleDraft(draft: RoutingRule, options: ValidateOptions = {}): Issue[] {
  return validateProfile({
    schemaVersion: "xck.v1",
    inbounds: [],
    routing: {
      rules: [draft]
    }
  }, options).issues.map((issue) => ({
    ...issue,
    path: issue.path.replace(/^\/routing\/rules\/0/, "")
  }));
}

export function validateOutboundDraft(draft: Outbound, options: ValidateOptions = {}): Issue[] {
  return validateProfile({
    schemaVersion: "xck.v1",
    inbounds: [],
    outbounds: [draft]
  }, options).issues.map((issue) => ({
    ...issue,
    path: issue.path.replace(/^\/outbounds\/1/, "")
  }));
}
