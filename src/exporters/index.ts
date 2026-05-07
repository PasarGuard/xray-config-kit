import { buildXrayConfig, compileStreamSettings } from "../core/compiler.js";
import { base64EncodeUtf8 } from "../core/base64.js";
import { makeIssue } from "../core/issues.js";
import type {
  Client,
  ClientLinkOptions,
  Inbound,
  Issue,
  JsonObject,
  JsonValue,
  Profile,
  RealitySecurity,
  Security,
  SubscriptionOptions,
  SubscriptionResult,
  Transport,
  WireGuardConfigOptions
} from "../core/types.js";

export {
  generateUriFromXrayJson,
  generateUriFromXrayOutbound,
  generateXrayConfigFromUri,
  generateXrayOutboundFromUri,
  uriToXrayConfig,
  uriToXrayOutbound,
  xrayJsonToUri,
  xrayOutboundToUri
} from "./uris.js";
export type {
  ClientUriProtocol,
  UriToXrayJsonOptions,
  XrayJsonToUriOptions
} from "./uris.js";

function encode(value: string): string {
  return encodeURIComponent(value);
}

function displayHost(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, host: string | undefined): string {
  if (host) return host;
  if (inbound.listen && inbound.listen !== "0.0.0.0" && inbound.listen !== "::" && inbound.listen !== "[::]") return inbound.listen;
  return "example.com";
}

function singlePortForExport(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, override: number | undefined, label: string): number {
  if (override !== undefined) return override;
  if (!("port" in inbound)) throw new Error(`${label} requires a network port.`);
  if (typeof inbound.port === "number") return inbound.port;
  if (/^\d+$/.test(inbound.port.trim())) return Number(inbound.port.trim());
  throw new Error(`${label} requires a single numeric port. Pass an explicit port when the inbound uses multiple ports.`);
}

function findInbound(profile: Profile, tag: string): Exclude<Inbound, { protocol: "unmanaged" }> | undefined {
  const inbound = profile.inbounds.find((candidate) => candidate.tag === tag);
  return inbound?.protocol === "unmanaged" ? undefined : inbound;
}

function findClient(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, clientId: string): Client | undefined {
  if (inbound.protocol === "vmess") {
    return inbound.clients.find((client) => client.id === clientId || client.email === clientId);
  }
  if (inbound.protocol === "vless") {
    return inbound.clients.find((client) => client.id === clientId || client.email === clientId);
  }
  if (inbound.protocol === "trojan") {
    return inbound.clients.find((client) => client.password === clientId || client.email === clientId);
  }
  if (inbound.protocol === "hysteria") {
    return inbound.clients.find((client) => client.auth === clientId || client.email === clientId);
  }
  if (inbound.protocol !== "shadowsocks") return undefined;
  return inbound.clients.find((client) => client.password === clientId || client.email === clientId);
}

function firstHeaderValue(headers: Record<string, string[]> | Record<string, string> | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
  if (!entry) return undefined;
  const value = entry[1];
  return Array.isArray(value) ? value[0] : value;
}

function appendTransportParams(params: URLSearchParams, transport: Transport): void {
  params.set("type", transport.type);
  if (transport.type === "tcp") {
    params.set("headerType", transport.header?.type ?? "none");
  }
  if (transport.type === "grpc") {
    params.set("serviceName", transport.serviceName);
    if (transport.authority) params.set("authority", transport.authority);
    if (transport.multiMode) params.set("mode", "multi");
  }
  if (transport.type === "xhttp") {
    if (transport.path) params.set("path", transport.path);
    if (transport.host) params.set("host", transport.host);
    if (transport.mode) params.set("mode", transport.mode);
  }
  if (transport.type === "ws") {
    if (transport.path) params.set("path", transport.path);
    if (transport.host) params.set("host", transport.host);
  }
  if (transport.type === "httpupgrade") {
    if (transport.path) params.set("path", transport.path);
    if (transport.host) params.set("host", transport.host);
  }
}

function vmessTransportParams(transport: Transport): JsonObject {
  if (transport.type === "tcp") {
    const headerType = transport.header?.type ?? "none";
    const request = transport.header?.request;
    return {
      type: headerType,
      path: headerType === "http" ? request?.path?.join(",") : undefined,
      host: headerType === "http" ? firstHeaderValue(request?.headers, "host") : undefined
    };
  }
  if (transport.type === "ws") {
    return {
      path: transport.path,
      host: transport.host ?? firstHeaderValue(transport.headers, "host")
    };
  }
  if (transport.type === "grpc") {
    return {
      path: transport.serviceName,
      authority: transport.authority,
      type: transport.multiMode ? "multi" : undefined
    };
  }
  if (transport.type === "xhttp") {
    return {
      path: transport.path,
      host: transport.host,
      type: transport.mode
    };
  }
  if (transport.type === "httpupgrade") {
    return {
      path: transport.path,
      host: transport.host ?? firstHeaderValue(transport.headers, "host")
    };
  }
  return {};
}

function appendSecurityParams(params: URLSearchParams, security: Security): void {
  params.set("security", security.type);
  if (security.type === "tls") {
    if (security.serverName) params.set("sni", security.serverName);
    if (security.fingerprint) params.set("fp", security.fingerprint);
    if (security.alpn?.length) params.set("alpn", security.alpn.join(","));
    return;
  }

  if (security.type === "reality") {
    if (!security.publicKey) {
      throw new Error("REALITY client link generation requires security.publicKey.");
    }
    params.set("pbk", security.publicKey);
    params.set("sni", security.serverNames[0] ?? "");
    params.set("sid", security.shortIds[0] ?? "");
    if (security.spiderX) params.set("spx", security.spiderX);
    if (security.fingerprint) params.set("fp", security.fingerprint);
    if (security.mldsa65Verify) params.set("pqv", security.mldsa65Verify);
  }
}

function linkRemark(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, client: Client, options: ClientLinkOptions): string {
  return options.remark ?? client.email ?? `${inbound.tag}-${client.protocol}`;
}

function shadowsocksClientPassword(inbound: Extract<Inbound, { protocol: "shadowsocks" }>, client: Extract<Client, { protocol: "shadowsocks" }>): string {
  const method = client.method ?? inbound.method;
  if (!method) throw new Error("Shadowsocks client export requires a method on the client or inbound.");
  if (method.startsWith("2022-") && inbound.password) return `${inbound.password}:${client.password}`;
  return client.password;
}

export function generateClientLink(profile: Profile, options: ClientLinkOptions): string {
  const inbound = findInbound(profile, options.inboundTag);
  if (!inbound) throw new Error(`Inbound "${options.inboundTag}" was not found or is unmanaged.`);
  const client = findClient(inbound, options.clientId);
  if (!client) throw new Error(`Client "${options.clientId}" was not found in inbound "${options.inboundTag}".`);
  if (client.enabled === false) throw new Error(`Client "${options.clientId}" is disabled.`);

  const host = displayHost(inbound, options.host);
  const port = singlePortForExport(inbound, options.port, `Client link for inbound "${options.inboundTag}"`);
  const remark = encode(linkRemark(inbound, client, options));

  if (inbound.protocol === "vmess" && client.protocol === "vmess") {
    const vmessJson = {
      v: "2",
      ps: decodeURIComponent(remark),
      add: host,
      port,
      id: client.id,
      scy: client.security ?? "auto",
      net: inbound.transport.type,
      tls: inbound.security.type === "tls" ? "tls" : "none",
      ...vmessTransportParams(inbound.transport),
      sni: inbound.security.type === "tls" ? inbound.security.serverName : undefined,
      fp: inbound.security.type === "tls" ? inbound.security.fingerprint : undefined,
      alpn: inbound.security.type === "tls" ? inbound.security.alpn?.join(",") : undefined
    };
    return `vmess://${base64EncodeUtf8(JSON.stringify(vmessJson, null, 2))}`;
  }

  if (inbound.protocol === "vless" && client.protocol === "vless") {
    const params = new URLSearchParams();
    params.set("encryption", "none");
    if (client.flow) params.set("flow", client.flow);
    appendTransportParams(params, inbound.transport);
    appendSecurityParams(params, inbound.security);
    return `vless://${client.id}@${host}:${port}?${params.toString()}#${remark}`;
  }

  if (inbound.protocol === "trojan" && client.protocol === "trojan") {
    const params = new URLSearchParams();
    appendTransportParams(params, inbound.transport);
    appendSecurityParams(params, inbound.security);
    return `trojan://${encode(client.password)}@${host}:${port}?${params.toString()}#${remark}`;
  }

  if (inbound.protocol === "shadowsocks" && client.protocol === "shadowsocks") {
    const method = client.method ?? inbound.method;
    if (!method) throw new Error("Shadowsocks link generation requires a method on the client or inbound.");
    const userInfo = base64EncodeUtf8(`${method}:${shadowsocksClientPassword(inbound, client)}`);
    const params = new URLSearchParams();
    if (inbound.transport) appendTransportParams(params, inbound.transport);
    if (inbound.security) appendSecurityParams(params, inbound.security);
    const queryString = params.toString();
    const query = queryString ? `?${queryString}` : "";
    return `ss://${userInfo}@${host}:${port}${query}#${remark}`;
  }

  throw new Error(`Client protocol "${client.protocol}" does not match inbound "${inbound.protocol}".`);
}

export function generateVmessLink(profile: Profile, options: ClientLinkOptions): string {
  const inbound = findInbound(profile, options.inboundTag);
  if (inbound?.protocol !== "vmess") throw new Error(`Inbound "${options.inboundTag}" is not a VMess inbound.`);
  return generateClientLink(profile, options);
}

export function generateVlessLink(profile: Profile, options: ClientLinkOptions): string {
  const inbound = findInbound(profile, options.inboundTag);
  if (inbound?.protocol !== "vless") throw new Error(`Inbound "${options.inboundTag}" is not a VLESS inbound.`);
  return generateClientLink(profile, options);
}

export function generateTrojanLink(profile: Profile, options: ClientLinkOptions): string {
  const inbound = findInbound(profile, options.inboundTag);
  if (inbound?.protocol !== "trojan") throw new Error(`Inbound "${options.inboundTag}" is not a Trojan inbound.`);
  return generateClientLink(profile, options);
}

export function generateShadowsocksLink(profile: Profile, options: ClientLinkOptions): string {
  const inbound = findInbound(profile, options.inboundTag);
  if (inbound?.protocol !== "shadowsocks") throw new Error(`Inbound "${options.inboundTag}" is not a Shadowsocks inbound.`);
  return generateClientLink(profile, options);
}

export function generateWireGuardConfig(profile: Profile, options: WireGuardConfigOptions): string {
  const inbound = findInbound(profile, options.inboundTag);
  if (inbound?.protocol !== "wireguard") throw new Error(`Inbound "${options.inboundTag}" is not a WireGuard inbound.`);
  const peer = inbound.peers.find((candidate) => candidate.publicKey === options.peerPublicKey);
  if (!peer) throw new Error(`WireGuard peer "${options.peerPublicKey}" was not found in inbound "${options.inboundTag}".`);
  const serverPublicKey = options.serverPublicKey ?? inbound.publicKey;
  if (!serverPublicKey) throw new Error("WireGuard config generation requires inbound.publicKey or options.serverPublicKey.");

  const endpointPort = singlePortForExport(inbound, options.endpointPort, `WireGuard config for inbound "${options.inboundTag}"`);
  const endpoint = `${options.endpointHost}:${endpointPort}`;
  const address = Array.isArray(options.clientAddress) ? options.clientAddress.join(", ") : options.clientAddress;
  const lines = [
    options.remark ? `# ${options.remark}` : undefined,
    "[Interface]",
    `PrivateKey = ${options.clientPrivateKey}`,
    `Address = ${address}`,
    options.dns?.length ? `DNS = ${options.dns.join(", ")}` : undefined,
    `MTU = ${options.mtu ?? inbound.mtu ?? 1420}`,
    "",
    "[Peer]",
    `PublicKey = ${serverPublicKey}`,
    peer.preSharedKey ? `PresharedKey = ${peer.preSharedKey}` : undefined,
    `AllowedIPs = ${peer.allowedIPs.join(", ")}`,
    `Endpoint = ${endpoint}`,
    peer.keepAlive !== undefined ? `PersistentKeepalive = ${peer.keepAlive}` : undefined
  ].filter((line): line is string => line !== undefined);

  return `${lines.join("\n")}\n`;
}

function compileRealityClient(security: RealitySecurity): JsonObject {
  if (!security.publicKey) throw new Error("REALITY xray-json subscription requires security.publicKey.");
  return {
    fingerprint: security.fingerprint ?? "chrome",
    serverName: security.serverNames[0] ?? "",
    publicKey: security.publicKey,
    shortId: security.shortIds[0] ?? "",
    spiderX: security.spiderX ?? "/",
    mldsa65Verify: security.mldsa65Verify
  };
}

function compileClientStream(transport: Transport, security: Security): JsonObject {
  if (security.type !== "reality") return compileStreamSettings(transport, security);
  const base = compileStreamSettings(transport, { type: "none" });
  return {
    ...base,
    security: "reality",
    realitySettings: compileRealityClient(security)
  };
}

function outboundTag(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, client: Client): string {
  const credential = client.protocol === "vless" || client.protocol === "vmess"
    ? client.id
    : client.protocol === "hysteria"
      ? client.auth
      : client.password;
  return `client-${inbound.tag}-${client.email ?? credential.slice(0, 8)}`;
}

function compileClientOutbound(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, client: Client, host: string | undefined): JsonObject {
  const address = displayHost(inbound, host);
  const port = singlePortForExport(inbound, undefined, `Outbound subscription for inbound "${inbound.tag}"`);
  if (inbound.protocol === "vmess" && client.protocol === "vmess") {
    return {
      tag: outboundTag(inbound, client),
      protocol: "vmess",
      settings: {
        vnext: [
          {
            address,
            port,
            users: [
              {
                id: client.id,
                security: client.security ?? "auto",
                email: client.email,
                level: client.level
              }
            ]
          }
        ]
      },
      streamSettings: compileClientStream(inbound.transport, inbound.security)
    };
  }

  if (inbound.protocol === "vless" && client.protocol === "vless") {
    return {
      tag: outboundTag(inbound, client),
      protocol: "vless",
      settings: {
        vnext: [
          {
            address,
            port,
            users: [
              {
                id: client.id,
                encryption: "none",
                flow: client.flow,
                level: client.level
              }
            ]
          }
        ]
      },
      streamSettings: compileClientStream(inbound.transport, inbound.security)
    };
  }

  if (inbound.protocol === "trojan" && client.protocol === "trojan") {
    return {
      tag: outboundTag(inbound, client),
      protocol: "trojan",
      settings: {
        servers: [
          {
            address,
            port,
            password: client.password,
            email: client.email,
            level: client.level
          }
        ]
      },
      streamSettings: compileClientStream(inbound.transport, inbound.security)
    };
  }

  if (inbound.protocol === "shadowsocks" && client.protocol === "shadowsocks") {
    const method = client.method ?? inbound.method;
    if (!method) throw new Error("Shadowsocks outbound subscription generation requires a method on the client or inbound.");
    const outbound = {
      tag: outboundTag(inbound, client),
      protocol: "shadowsocks",
      settings: {
        servers: [
          {
            address,
            port,
            method,
            password: shadowsocksClientPassword(inbound, client),
            email: client.email,
            level: client.level
          }
        ]
      }
    };
    if (inbound.transport && inbound.security) {
      return {
        ...outbound,
        streamSettings: compileClientStream(inbound.transport, inbound.security)
      };
    }
    return outbound;
  }

  throw new Error("Inbound and client protocol mismatch.");
}

function selectedClients(profile: Profile, options: SubscriptionOptions): readonly [Exclude<Inbound, { protocol: "unmanaged" }>, Client][] {
  const selected = new Set(options.clients ?? []);
  const result: [Exclude<Inbound, { protocol: "unmanaged" }>, Client][] = [];
  for (const inbound of profile.inbounds) {
    if (inbound.protocol === "unmanaged") continue;
    if (!("clients" in inbound)) continue;
    const clients = inbound.clients;
    for (const client of clients) {
      const ids = [
        client.email,
        client.protocol === "vless" || client.protocol === "vmess"
          ? client.id
          : client.protocol === "hysteria"
            ? client.auth
            : client.password
      ].filter((value): value is string => typeof value === "string");
      if (client.enabled === false && !options.includeDisabled) continue;
      if (selected.size > 0 && !ids.some((id) => selected.has(id))) continue;
      result.push([inbound, client]);
    }
  }
  return result;
}

export function generateSubscription(profile: Profile, options: SubscriptionOptions): SubscriptionResult {
  const issues: Issue[] = [];
  const entries = selectedClients(profile, options);

  if (options.format === "xray-json") {
    const outbounds: JsonObject[] = [];
    for (const [inbound, client] of entries) {
      try {
        outbounds.push(compileClientOutbound(inbound, client, options.host));
      } catch (error) {
        issues.push(makeIssue({
          code: "XCK_SUBSCRIPTION_CLIENT_OUTBOUND_FAILED",
          severity: "warning",
          category: "suggestion",
          path: `/inbounds/${profile.inbounds.indexOf(inbound)}`,
          message: "Could not generate xray-json outbound for a client.",
          suggestion: error instanceof Error ? error.message : undefined
        }));
      }
    }
    const config = buildXrayConfig({
      schemaVersion: "xck.v1",
      inbounds: [],
      outbounds: [
        { protocol: "freedom", tag: "direct", settings: { domainStrategy: "AsIs" } },
        { protocol: "blackhole", tag: "block", settings: { response: { type: "none" } } },
        ...outbounds.map((raw, index) => ({ protocol: "unmanaged" as const, tag: `client-${index}`, editable: false as const, raw }))
      ]
    }, { mode: "permissive" }).config;

    return {
      format: options.format,
      content: JSON.stringify(config, null, 2),
      entries: outbounds.length,
      issues
    };
  }

  const links: string[] = [];
  for (const [inbound, client] of entries) {
    try {
      links.push(generateClientLink(profile, {
        inboundTag: inbound.tag,
        clientId: client.email ?? (client.protocol === "vless" || client.protocol === "vmess"
          ? client.id
          : client.protocol === "hysteria"
            ? client.auth
            : client.password),
        host: options.host
      }));
    } catch (error) {
      issues.push(makeIssue({
        code: "XCK_SUBSCRIPTION_LINK_FAILED",
        severity: "warning",
        category: "suggestion",
        path: `/inbounds/${profile.inbounds.indexOf(inbound)}`,
        message: "Could not generate a subscription link for a client.",
        suggestion: error instanceof Error ? error.message : undefined
      }));
    }
  }

  const content = links.join("\n");
  return {
    format: options.format,
    content: options.format === "links-base64" ? base64EncodeUtf8(content) : content,
    entries: links.length,
    issues
  };
}
