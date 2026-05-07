import { getCapabilities } from "../adapters/xray/registry.js";
import { validateProfile } from "./validate.js";
import type { Inbound, Issue, Security, Transport, ValidateOptions } from "./types.js";

const placeholderUuid = "00000000-0000-4000-8000-000000000000";
const placeholderKey32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

type CreateDefaultInboundBaseOptions<Protocol extends Exclude<Inbound["protocol"], "unmanaged">> = {
  readonly protocol: Protocol;
  readonly tag?: string;
  readonly port?: number;
  readonly listen?: string;
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
  readonly transports: Record<string, boolean>;
  readonly securities: Record<string, boolean>;
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

export function createDefaultInbound<const Options extends CreateDefaultInboundOptions>(
  options: ExactCreateDefaultInboundOptions<Options>
): InboundForProtocol<Options["protocol"]> {
  const typedOptions = options as CreateDefaultInboundOptions;
  assertCreateDefaultInboundOptions(typedOptions);

  const tag = typedOptions.tag ?? `${typedOptions.protocol}-inbound`;
  const port = typedOptions.port ?? 443;
  const listen = typedOptions.listen ?? "";

  if (typedOptions.protocol === "vmess") {
    return {
      kind: "inbound",
      protocol: "vmess",
      tag,
      listen,
      port,
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
      listen,
      port,
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
      listen,
      port,
      clients: typedOptions.clientDefaults === "empty"
        ? []
        : [{ protocol: "trojan", password: "change-me-trojan-password", email: "user" }],
      security: defaultSecurity(typedOptions.security === "reality" ? "reality" : typedOptions.security ?? "tls"),
      transport: defaultTransport(typedOptions.transport)
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "shadowsocks") {
    const usesStreamSettings = typedOptions.security !== undefined || typedOptions.transport !== undefined;
    const inbound: Extract<Inbound, { protocol: "shadowsocks" }> = {
      kind: "inbound",
      protocol: "shadowsocks",
      tag,
      listen,
      port,
      method: "2022-blake3-aes-256-gcm",
      password: "change-me-server-password",
      network: "tcp,udp",
      clients: typedOptions.clientDefaults === "empty"
        ? []
        : [{ protocol: "shadowsocks", password: "change-me-client-password", email: "user" }]
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
      listen,
      port,
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
      listen: "127.0.0.1",
      port: typedOptions.port ?? 8080,
      accounts: [{ user: "user", pass: "change-me-http-password" }]
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "mixed" || typedOptions.protocol === "socks") {
    return {
      kind: "inbound",
      protocol: typedOptions.protocol,
      tag,
      listen: "127.0.0.1",
      port: typedOptions.port ?? 1080,
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
      listen,
      port,
      address: "127.0.0.1",
      targetPort: typedOptions.port ?? 80,
      network: "tcp"
    } as InboundForProtocol<Options["protocol"]>;
  }

  if (typedOptions.protocol === "tun") {
    return {
      kind: "inbound",
      protocol: "tun",
      tag,
      listen,
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
    listen,
    port: typedOptions.port ?? 51820,
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
  return {
    protocols: Object.fromEntries(capabilities.protocols.map((item) => [item, true])),
    transports: Object.fromEntries(capabilities.transports.map((item) => [item, true])),
    securities: Object.fromEntries(capabilities.securities.map((item) => [item, true])),
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

export function validateInboundDraft(draft: Inbound, options: ValidateOptions = {}): Issue[] {
  return validateProfile({
    schemaVersion: "xck.v1",
    inbounds: [draft]
  }, options).issues.map((issue) => ({
    ...issue,
    path: issue.path.replace(/^\/inbounds\/0/, "")
  }));
}
