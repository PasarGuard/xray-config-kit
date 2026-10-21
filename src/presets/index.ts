import type { Dns, Outbound, Profile, Routing } from "../core/types.js";

export type PresetName =
  | "direct-block-outbounds"
  | "api-stats-routing"
  | "dns-simple"
  | "dns-doh"
  | "routing-private-direct"
  | "routing-ads-block"
  | "routing-bittorrent-block"
  | "regional-ir-direct"
  | "vless-reality-tcp"
  | "vless-reality-grpc"
  | "trojan-tls"
  | "shadowsocks-aead"
  | "shadowsocks-2022";

export type PresetDefinition = {
  readonly name: PresetName;
  readonly description: string;
  readonly profile: Partial<Profile>;
};

const directBlockOutbounds: Outbound[] = [
  { protocol: "freedom", tag: "direct", settings: { domainStrategy: "AsIs" } },
  { protocol: "blackhole", tag: "block", settings: { response: { type: "none" } } }
];

const apiStatsRouting: Routing = {
  domainStrategy: "AsIs",
  rules: [
    {
      type: "field",
      inboundTag: ["api"],
      outboundTag: "api"
    }
  ]
};

export const presetCatalog: Record<PresetName, PresetDefinition> = {
  "direct-block-outbounds": {
    name: "direct-block-outbounds",
    description: "Adds standard direct and block outbounds.",
    profile: { outbounds: directBlockOutbounds }
  },
  "api-stats-routing": {
    name: "api-stats-routing",
    description: "Pins the internal API/stats routing rule before user rules.",
    profile: { routing: apiStatsRouting }
  },
  "dns-simple": {
    name: "dns-simple",
    description: "Adds simple UDP DNS servers.",
    profile: {
      dns: {
        servers: ["1.1.1.1", "8.8.8.8"],
        queryStrategy: "UseIP"
      }
    }
  },
  "dns-doh": {
    name: "dns-doh",
    description: "Adds common DNS-over-HTTPS endpoints.",
    profile: {
      dns: {
        servers: ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
        queryStrategy: "UseIP"
      }
    }
  },
  "routing-private-direct": {
    name: "routing-private-direct",
    description: "Routes private IP ranges directly.",
    profile: {
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
          {
            type: "field",
            ip: ["geoip:private"],
            outboundTag: "direct"
          }
        ]
      }
    }
  },
  "routing-ads-block": {
    name: "routing-ads-block",
    description: "Blocks common ad domains through geosite category rules.",
    profile: {
      routing: {
        rules: [
          {
            type: "field",
            domain: ["geosite:category-ads-all"],
            outboundTag: "block"
          }
        ]
      }
    }
  },
  "routing-bittorrent-block": {
    name: "routing-bittorrent-block",
    description: "Blocks BitTorrent protocol sniffing matches.",
    profile: {
      routing: {
        rules: [
          {
            type: "field",
            protocol: ["bittorrent"],
            outboundTag: "block"
          }
        ]
      }
    }
  },
  "regional-ir-direct": {
    name: "regional-ir-direct",
    description: "Routes Iran geosite/geoip entries directly.",
    profile: {
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
          // geosite:ir exists only in third-party geosite files; the geosite.dat in Xray release zips has category-ir.
          { type: "field", domain: ["geosite:category-ir"], outboundTag: "direct" },
          { type: "field", ip: ["geoip:ir"], outboundTag: "direct" }
        ]
      }
    }
  },
  "vless-reality-tcp": {
    name: "vless-reality-tcp",
    description: "Template marker for VLESS REALITY over TCP. Supply concrete inbound fields in createProfile input.",
    profile: {}
  },
  "vless-reality-grpc": {
    name: "vless-reality-grpc",
    description: "Template marker for VLESS REALITY over gRPC. Supply concrete inbound fields in createProfile input.",
    profile: {}
  },
  "trojan-tls": {
    name: "trojan-tls",
    description: "Template marker for Trojan over TLS. Supply concrete inbound fields in createProfile input.",
    profile: {}
  },
  "shadowsocks-aead": {
    name: "shadowsocks-aead",
    description: "Template marker for Shadowsocks AEAD. Supply concrete inbound fields in createProfile input.",
    profile: {}
  },
  "shadowsocks-2022": {
    name: "shadowsocks-2022",
    description: "Template marker for Shadowsocks 2022. Supply concrete inbound fields in createProfile input.",
    profile: {}
  }
};

function mergeOutbounds(existing: readonly Outbound[] | undefined, preset: readonly Outbound[] | undefined): Outbound[] | undefined {
  if (!existing && !preset) return undefined;
  const merged = [...(preset ?? []), ...(existing ?? [])];
  const seen = new Set<string>();
  return merged.filter((outbound) => {
    const tag = outbound.tag;
    if (!tag) return true;
    if (seen.has(tag)) return false;
    seen.add(tag);
    return true;
  });
}

function mergeRouting(existing: Routing | undefined, preset: Routing | undefined): Routing | undefined {
  if (!existing && !preset) return undefined;
  return {
    domainStrategy: existing?.domainStrategy ?? preset?.domainStrategy,
    rules: [...(preset?.rules ?? []), ...(existing?.rules ?? [])]
  };
}

function mergeDns(existing: Dns | undefined, preset: Dns | undefined): Dns | undefined {
  return existing ?? preset;
}

export function applyPresets(profile: Partial<Profile>, names: readonly string[] = []): Partial<Profile> {
  let next: Partial<Profile> = { ...profile };
  for (const name of names) {
    const preset = presetCatalog[name as PresetName];
    if (!preset) continue;
    next = {
      ...preset.profile,
      ...next,
      outbounds: mergeOutbounds(next.outbounds, preset.profile.outbounds),
      routing: mergeRouting(next.routing, preset.profile.routing),
      dns: mergeDns(next.dns, preset.profile.dns)
    };
  }
  return next;
}
