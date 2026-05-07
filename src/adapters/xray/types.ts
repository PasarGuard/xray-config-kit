import type { Issue, Profile } from "../../core/types.js";

export type XrayFeature =
  | "vmess"
  | "vless"
  | "trojan"
  | "shadowsocks"
  | "http"
  | "mixed"
  | "wireguard"
  | "hysteria"
  | "tun"
  | "dokodemo-door"
  | "reality"
  | "tls"
  | "tcp"
  | "grpc"
  | "xhttp"
  | "httpupgrade"
  | "websocket"
  | "mkcp"
  | "quic"
  | "http-transport"
  | "routing"
  | "dns"
  | "finalmask"
  | "metrics"
  | "api"
  | "stats";

export type FeatureSupport = {
  readonly supported: boolean;
  readonly introduced?: string;
  readonly removed?: string;
  readonly replacement?: string;
  readonly deprecated?: boolean;
};

export type CompatibilityMatrix = Record<string, FeatureSupport>;

export type XrayCapabilities = {
  readonly adapterId: string;
  readonly xrayVersionRange: string;
  readonly latestTestedVersion: string;
  readonly protocols: readonly string[];
  readonly transports: readonly string[];
  readonly securities: readonly string[];
  readonly fingerprints: readonly string[];
  readonly alpn: readonly string[];
  readonly removedFeatures: readonly {
    readonly feature: string;
    readonly replacement?: string;
  }[];
  readonly deprecatedFeatures: readonly {
    readonly feature: string;
    readonly replacement?: string;
    readonly removalDate?: string;
  }[];
  readonly compatibilityMatrix: CompatibilityMatrix;
};

export type XrayAdapter = {
  readonly id: string;
  readonly versionRange: string;
  readonly latestTestedVersion: string;
  readonly capabilities: XrayCapabilities;
  readonly issues?: readonly Issue[];
  readonly validateCompatibility: (profile: Profile) => Issue[];
};
