import { base64DecodeUtf8, base64EncodeUtf8 } from "../core/base64.js";
import { isJsonObject, sortJson } from "../core/json.js";
import type { JsonObject, JsonValue, XrayConfig } from "../core/types.js";

export type ClientUriProtocol = "vmess" | "vless" | "trojan" | "shadowsocks" | "hysteria" | "wireguard";

export type UriToXrayJsonOptions = {
  readonly tag?: string;
  readonly remarkAsTag?: boolean;
};

export type XrayJsonToUriOptions = {
  readonly remark?: string;
  readonly host?: string;
  readonly port?: number;
  readonly outboundIndex?: number;
  readonly userIndex?: number;
  readonly serverIndex?: number;
  readonly peerIndex?: number;
};

type LooseJsonValue = JsonValue | undefined | null;

function compactObject(input: Record<string, LooseJsonValue>): JsonObject {
  const output: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined || value === null || value === "") continue;
    if (isJsonObject(value)) {
      const nested = compactObject(value as Record<string, LooseJsonValue>);
      if (Object.keys(nested).length > 0) output[key] = nested;
      continue;
    }
    output[key] = value;
  }
  return output;
}

function asString(value: JsonValue | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asNumber(value: JsonValue | undefined): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asBoolean(value: JsonValue | undefined): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asObjectArray(value: JsonValue | undefined): JsonObject[] {
  return Array.isArray(value) ? value.filter(isJsonObject) : [];
}

function asStringArray(value: JsonValue | undefined): string[] | undefined {
  return Array.isArray(value) && value.every((item) => typeof item === "string") ? [...value] : undefined;
}

function splitCsv(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  const parts = value.split(",").map((item) => item.trim()).filter(Boolean);
  return parts.length > 0 ? parts : undefined;
}

function parseInteger(value: string | undefined, label: string): number {
  if (!value || !/^\d+$/.test(value)) throw new Error(`${label} requires a numeric port.`);
  return Number(value);
}

function parseOptionalInteger(value: string | undefined): number | undefined {
  return value && /^\d+$/.test(value) ? Number(value) : undefined;
}

function parseBooleanParam(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  if (value === "1" || value.toLowerCase() === "true") return true;
  if (value === "0" || value.toLowerCase() === "false") return false;
  return undefined;
}

function decodeUriComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function encodeFragment(value: string | undefined): string {
  return value ? `#${encodeURIComponent(value)}` : "";
}

function cleanHostname(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

function authorityHost(address: string): string {
  if (address.startsWith("[") && address.endsWith("]")) return address;
  return address.includes(":") ? `[${address}]` : address;
}

function parseAuthority(authority: string, label: string): { address: string; port: number } {
  const url = new URL(`${label}://${authority}`);
  return {
    address: cleanHostname(url.hostname),
    port: parseInteger(url.port, label)
  };
}

function splitUri(uri: string): { scheme: string; rest: string; main: string; query: string; remark: string | undefined } {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(uri);
  if (!match?.[1]) throw new Error("Client URI must include a scheme.");
  const scheme = match[1].toLowerCase();
  const rest = uri.slice(match[0].length);
  const hashIndex = rest.indexOf("#");
  const withoutHash = hashIndex === -1 ? rest : rest.slice(0, hashIndex);
  const remark = hashIndex === -1 ? undefined : decodeUriComponent(rest.slice(hashIndex + 1));
  const queryIndex = withoutHash.indexOf("?");
  return {
    scheme,
    rest,
    main: queryIndex === -1 ? withoutHash : withoutHash.slice(0, queryIndex),
    query: queryIndex === -1 ? "" : withoutHash.slice(queryIndex + 1),
    remark
  };
}

function rawUserInfoFromMain(main: string): string | undefined {
  const atIndex = main.lastIndexOf("@");
  if (atIndex === -1) return undefined;
  return decodeUriComponent(main.slice(0, atIndex));
}

function tagFromRemark(protocol: ClientUriProtocol, remark: string | undefined, options: UriToXrayJsonOptions): string {
  if (options.tag) return options.tag;
  if (options.remarkAsTag !== false && remark) return remark;
  return protocol === "wireguard" ? "wireguard" : "proxy";
}

function paramsFromQuery(query: string): URLSearchParams {
  return new URLSearchParams(query);
}

function param(params: URLSearchParams, key: string): string | undefined {
  const value = params.get(key);
  return value === null ? undefined : value;
}

function setParam(params: URLSearchParams, key: string, value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  params.set(key, String(value));
}

function parseJsonObject(value: string | undefined): JsonObject | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value);
    return isJsonObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function jsonString(value: JsonValue | undefined): string | undefined {
  if (value === undefined) return undefined;
  return JSON.stringify(value);
}

function firstHeaderValue(headers: JsonValue | undefined, name: string): string | undefined {
  if (!isJsonObject(headers)) return undefined;
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
  if (!entry) return undefined;
  const value = entry[1];
  if (Array.isArray(value)) return value.find((item): item is string => typeof item === "string");
  return typeof value === "string" ? value : undefined;
}

function firstString(value: JsonValue | undefined): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.find((item): item is string => typeof item === "string");
  return undefined;
}

function streamSettingsKey(network: string): string {
  if (network === "mkcp") return "kcpSettings";
  if (network === "gun") return "grpcSettings";
  return `${network}Settings`;
}

function streamSettingsForNetwork(streamSettings: JsonObject | undefined, network: string): JsonObject | undefined {
  if (!streamSettings) return undefined;
  const candidates = [
    streamSettingsKey(network),
    network === "tcp" ? "rawSettings" : undefined,
    network === "raw" ? "tcpSettings" : undefined,
    network === "splithttp" ? "xhttpSettings" : undefined,
    network === "xhttp" ? "splithttpSettings" : undefined,
    network === "grpc" ? "gunSettings" : undefined
  ].filter((key): key is string => key !== undefined);

  for (const key of candidates) {
    const value = streamSettings[key];
    if (isJsonObject(value)) return value;
  }
  return undefined;
}

function appendSecurityToStream(streamSettings: Record<string, JsonValue>, security: string | undefined, params: URLSearchParams): void {
  const normalized = (security || "none").toLowerCase();
  streamSettings.security = normalized;
  if (normalized === "tls") {
    streamSettings.tlsSettings = compactObject({
      serverName: param(params, "sni"),
      fingerprint: param(params, "fp"),
      alpn: splitCsv(param(params, "alpn")),
      allowInsecure: parseBooleanParam(param(params, "allowInsecure")),
      pinnedPeerCertSha256: param(params, "pcs"),
      verifyPeerCertByName: param(params, "vcn"),
      echConfigList: param(params, "ech"),
      echForceQuery: param(params, "echForceQuery")
    });
  }
  if (normalized === "reality") {
    streamSettings.realitySettings = compactObject({
      serverName: param(params, "sni"),
      fingerprint: param(params, "fp"),
      publicKey: param(params, "pbk"),
      shortId: param(params, "sid"),
      spiderX: param(params, "spx"),
      mldsa65Verify: param(params, "pqv")
    });
  }
}

function appendSecurityParams(params: URLSearchParams, streamSettings: JsonObject | undefined): void {
  const security = asString(streamSettings?.security) ?? "none";
  params.set("security", security);
  if (security === "tls") {
    const tls = isJsonObject(streamSettings?.tlsSettings) ? streamSettings.tlsSettings : {};
    setParam(params, "sni", tls.serverName);
    setParam(params, "fp", tls.fingerprint);
    const alpn = asStringArray(tls.alpn)?.join(",") ?? asString(tls.alpn);
    setParam(params, "alpn", alpn);
    if (asBoolean(tls.allowInsecure)) params.set("allowInsecure", "1");
    setParam(params, "pcs", tls.pinnedPeerCertSha256);
    setParam(params, "vcn", tls.verifyPeerCertByName);
    setParam(params, "ech", tls.echConfigList);
    setParam(params, "echForceQuery", tls.echForceQuery);
  }
  if (security === "reality") {
    const reality = isJsonObject(streamSettings?.realitySettings) ? streamSettings.realitySettings : {};
    setParam(params, "sni", reality.serverName);
    setParam(params, "fp", reality.fingerprint);
    setParam(params, "pbk", reality.publicKey);
    setParam(params, "sid", reality.shortId);
    setParam(params, "spx", reality.spiderX);
    setParam(params, "pqv", reality.mldsa65Verify);
  }
}

function appendSecurityToVmessPayload(payload: Record<string, LooseJsonValue>, streamSettings: JsonObject | undefined): void {
  const security = asString(streamSettings?.security) ?? "none";
  payload.tls = security;
  if (security === "tls") {
    const tls = isJsonObject(streamSettings?.tlsSettings) ? streamSettings.tlsSettings : {};
    payload.sni = tls.serverName;
    payload.fp = tls.fingerprint;
    payload.alpn = asStringArray(tls.alpn)?.join(",") ?? asString(tls.alpn);
    payload.pcs = tls.pinnedPeerCertSha256;
    payload.vcn = tls.verifyPeerCertByName;
    payload.ech = tls.echConfigList;
    payload.echForceQuery = tls.echForceQuery;
    if (asBoolean(tls.allowInsecure)) payload.allowInsecure = 1;
  }
  if (security === "reality") {
    const reality = isJsonObject(streamSettings?.realitySettings) ? streamSettings.realitySettings : {};
    payload.sni = reality.serverName;
    payload.fp = reality.fingerprint;
    payload.pbk = reality.publicKey;
    payload.sid = reality.shortId;
    payload.spx = reality.spiderX;
    payload.pqv = reality.mldsa65Verify;
  }
}

function securityParamsFromVmessPayload(payload: JsonObject): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of ["sni", "fp", "alpn", "pcs", "vcn", "ech", "echForceQuery", "pbk", "sid", "spx", "pqv", "allowInsecure"]) {
    const value = payload[key];
    if (value !== undefined) setParam(params, key, value);
  }
  return params;
}

function transportSettingsFromLink(
  network: string,
  params: URLSearchParams,
  source: JsonObject = {},
  protocol: ClientUriProtocol
): JsonObject | undefined {
  const path = asString(source.path) ?? param(params, "path");
  const host = asString(source.host) ?? param(params, "host");
  const vmessType = asString(source.type);
  const headerType = protocol === "vmess" ? vmessType : param(params, "headerType");

  if (network === "ws") {
    return compactObject({
      path,
      host,
      heartbeatPeriod: parseOptionalInteger(param(params, "heartbeatPeriod"))
    });
  }

  if (network === "httpupgrade") {
    return compactObject({ path, host });
  }

  if (network === "grpc" || network === "gun") {
    return compactObject({
      serviceName: param(params, "serviceName") ?? path,
      authority: param(params, "authority") ?? host,
      multiMode: param(params, "mode") === "multi" || vmessType === "multi" ? true : undefined
    });
  }

  if (network === "xhttp" || network === "splithttp") {
    return compactObject({
      path,
      host,
      mode: param(params, "mode") ?? (protocol === "vmess" ? vmessType : undefined),
      extra: parseJsonObject(param(params, "extra"))
    });
  }

  if (network === "kcp" || network === "mkcp") {
    return compactObject({
      mtu: parseOptionalInteger(param(params, "mtu")),
      tti: parseOptionalInteger(param(params, "tti")),
      header: headerType ? { type: headerType } : undefined
    });
  }

  if (network === "quic") {
    return compactObject({
      key: param(params, "key"),
      security: param(params, "quicSecurity"),
      header: headerType ? { type: headerType } : undefined
    });
  }

  if (network === "tcp" || network === "raw" || network === "http" || network === "h2") {
    const request = compactObject({
      path: path ? [path] : undefined,
      headers: host ? { Host: [host] } : undefined
    });
    return compactObject({
      header: compactObject({
        type: headerType ?? "none",
        request: Object.keys(request).length > 0 ? request : undefined
      })
    });
  }

  return undefined;
}

function streamSettingsFromLink(
  protocol: ClientUriProtocol,
  params: URLSearchParams,
  source: JsonObject = {}
): JsonObject {
  const network = (protocol === "vmess" ? asString(source.net) : param(params, "type"))?.toLowerCase() ?? "tcp";
  const streamSettings: Record<string, JsonValue> = { network };
  const security = protocol === "vmess" ? asString(source.tls) : param(params, "security");
  const securityParams = protocol === "vmess" ? securityParamsFromVmessPayload(source) : params;
  appendSecurityToStream(streamSettings, security, securityParams);

  const transport = transportSettingsFromLink(network, params, source, protocol);
  if (transport && Object.keys(transport).length > 0) streamSettings[streamSettingsKey(network)] = transport;

  const finalmask = parseJsonObject(param(params, "fm")) ?? parseJsonObject(asString(source.fm));
  if (finalmask) streamSettings.finalmask = finalmask;
  return compactObject(streamSettings);
}

function appendTransportParamsFromStream(
  params: URLSearchParams,
  streamSettings: JsonObject | undefined,
  protocol: Exclude<ClientUriProtocol, "vmess">
): void {
  const network = asString(streamSettings?.network) ?? "tcp";
  params.set("type", network);
  const settings = streamSettingsForNetwork(streamSettings, network);

  if (network === "ws" || network === "httpupgrade") {
    setParam(params, "path", settings?.path);
    setParam(params, "host", settings?.host ?? firstHeaderValue(settings?.headers, "host"));
    setParam(params, "heartbeatPeriod", settings?.heartbeatPeriod);
  } else if (network === "grpc" || network === "gun") {
    setParam(params, "serviceName", settings?.serviceName);
    setParam(params, "authority", settings?.authority);
    if (settings?.multiMode === true) params.set("mode", "multi");
  } else if (network === "xhttp" || network === "splithttp") {
    setParam(params, "path", settings?.path);
    setParam(params, "host", settings?.host);
    setParam(params, "mode", settings?.mode);
    const extra = xhttpExtraFromSettings(settings);
    if (extra && Object.keys(extra).length > 0) params.set("extra", JSON.stringify(extra));
  } else if (network === "kcp" || network === "mkcp") {
    setParam(params, "mtu", settings?.mtu);
    setParam(params, "tti", settings?.tti);
    if (isJsonObject(settings?.header)) setParam(params, "headerType", settings.header.type);
  } else if (network === "quic") {
    setParam(params, "key", settings?.key);
    setParam(params, "quicSecurity", settings?.security);
    if (isJsonObject(settings?.header)) setParam(params, "headerType", settings.header.type);
  } else {
    const header = isJsonObject(settings?.header) ? settings.header : undefined;
    const request = isJsonObject(header?.request) ? header.request : undefined;
    setParam(params, "headerType", header?.type ?? "none");
    setParam(params, "path", firstString(request?.path));
    setParam(params, "host", firstHeaderValue(request?.headers, "host"));
  }

  appendSecurityParams(params, streamSettings);
  const finalmask = isJsonObject(streamSettings?.finalmask) ? streamSettings.finalmask : undefined;
  if (finalmask) params.set(protocol === "hysteria" ? "fm" : "fm", JSON.stringify(finalmask));
}

function appendTransportToVmessPayload(payload: Record<string, LooseJsonValue>, streamSettings: JsonObject | undefined): void {
  const network = asString(streamSettings?.network) ?? "tcp";
  payload.net = network;
  const settings = streamSettingsForNetwork(streamSettings, network);

  if (network === "ws" || network === "httpupgrade") {
    payload.path = settings?.path;
    payload.host = settings?.host ?? firstHeaderValue(settings?.headers, "host");
  } else if (network === "grpc" || network === "gun") {
    payload.path = settings?.serviceName;
    payload.host = settings?.authority;
    payload.type = settings?.multiMode === true ? "multi" : "gun";
  } else if (network === "xhttp" || network === "splithttp") {
    payload.path = settings?.path;
    payload.host = settings?.host;
    payload.type = settings?.mode;
    const extra = xhttpExtraFromSettings(settings);
    if (extra && Object.keys(extra).length > 0) payload.extra = JSON.stringify(extra);
  } else {
    const header = isJsonObject(settings?.header) ? settings.header : undefined;
    const request = isJsonObject(header?.request) ? header.request : undefined;
    payload.type = asString(header?.type) ?? "none";
    payload.path = firstString(request?.path);
    payload.host = firstHeaderValue(request?.headers, "host");
    if (network === "kcp" || network === "mkcp") {
      payload.mtu = settings?.mtu;
      payload.tti = settings?.tti;
    }
    if (network === "quic") {
      payload.key = settings?.key;
      payload.quicSecurity = settings?.security;
    }
  }

  appendSecurityToVmessPayload(payload, streamSettings);
  if (isJsonObject(streamSettings?.finalmask)) payload.fm = JSON.stringify(streamSettings.finalmask);
}

function xhttpExtraFromSettings(settings: JsonObject | undefined): JsonObject | undefined {
  if (!settings) return undefined;
  if (isJsonObject(settings.extra)) return settings.extra;
  const known = new Set(["host", "path", "mode"]);
  const extra: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(settings)) {
    if (!known.has(key) && value !== undefined) extra[key] = value;
  }
  return Object.keys(extra).length > 0 ? extra : undefined;
}

function outboundBase(protocol: ClientUriProtocol, tag: string, settings: JsonObject, streamSettings?: JsonObject): JsonObject {
  return compactObject({
    protocol,
    tag,
    settings,
    streamSettings
  });
}

function parseVmess(uri: string, options: UriToXrayJsonOptions): JsonObject {
  const { main, remark } = splitUri(uri);
  const payload = JSON.parse(base64DecodeUtf8(decodeUriComponent(main))) as unknown;
  if (!isJsonObject(payload)) throw new Error("VMess URI payload must decode to a JSON object.");
  const address = asString(payload.add);
  const id = asString(payload.id);
  if (!address || !id) throw new Error("VMess URI requires add and id fields.");
  const port = typeof payload.port === "number" ? payload.port : parseInteger(asString(payload.port), "VMess URI");
  const streamSettings = streamSettingsFromLink("vmess", new URLSearchParams(), payload);
  return outboundBase("vmess", tagFromRemark("vmess", asString(payload.ps) ?? remark, options), {
    vnext: [
      {
        address,
        port,
        users: [
          compactObject({
            id,
            alterId: typeof payload.aid === "number" ? payload.aid : parseOptionalInteger(asString(payload.aid)) ?? 0,
            security: asString(payload.scy) ?? asString(payload.security) ?? "auto"
          })
        ]
      }
    ]
  }, streamSettings);
}

function parseVless(uri: string, options: UriToXrayJsonOptions): JsonObject {
  const split = splitUri(uri);
  const url = new URL(uri);
  const id = rawUserInfoFromMain(split.main);
  if (!id) throw new Error("VLESS URI requires a user id.");
  const params = paramsFromQuery(split.query);
  const streamSettings = streamSettingsFromLink("vless", params);
  return outboundBase("vless", tagFromRemark("vless", split.remark, options), {
    vnext: [
      {
        address: cleanHostname(url.hostname),
        port: parseInteger(url.port, "VLESS URI"),
        users: [
          compactObject({
            id,
            encryption: param(params, "encryption") ?? "none",
            flow: param(params, "flow")
          })
        ]
      }
    ]
  }, streamSettings);
}

function parseTrojan(uri: string, options: UriToXrayJsonOptions): JsonObject {
  const split = splitUri(uri);
  const url = new URL(uri);
  const password = rawUserInfoFromMain(split.main);
  if (!password) throw new Error("Trojan URI requires a password.");
  const params = paramsFromQuery(split.query);
  const streamSettings = streamSettingsFromLink("trojan", params);
  return outboundBase("trojan", tagFromRemark("trojan", split.remark, options), {
    servers: [
      compactObject({
        address: cleanHostname(url.hostname),
        port: parseInteger(url.port, "Trojan URI"),
        password,
        flow: param(params, "flow")
      })
    ]
  }, streamSettings);
}

function decodeShadowsocksUserInfo(userInfo: string): { method: string; password: string } {
  const decoded = userInfo.includes(":") ? decodeUriComponent(userInfo) : base64DecodeUtf8(decodeUriComponent(userInfo));
  const separator = decoded.indexOf(":");
  if (separator === -1) throw new Error("Shadowsocks URI user info must be method:password.");
  return {
    method: decoded.slice(0, separator),
    password: decoded.slice(separator + 1)
  };
}

function parseShadowsocks(uri: string, options: UriToXrayJsonOptions): JsonObject {
  const split = splitUri(uri);
  const params = paramsFromQuery(split.query);
  const atIndex = split.main.lastIndexOf("@");
  let userInfo: { method: string; password: string };
  let endpoint: { address: string; port: number };

  if (atIndex === -1) {
    const decoded = base64DecodeUtf8(decodeUriComponent(split.main));
    const endpointIndex = decoded.lastIndexOf("@");
    if (endpointIndex === -1) throw new Error("Shadowsocks URI requires an endpoint.");
    userInfo = decodeShadowsocksUserInfo(decoded.slice(0, endpointIndex));
    endpoint = parseAuthority(decoded.slice(endpointIndex + 1), "ss");
  } else {
    userInfo = decodeShadowsocksUserInfo(split.main.slice(0, atIndex));
    endpoint = parseAuthority(split.main.slice(atIndex + 1), "ss");
  }

  const streamSettings = split.query ? streamSettingsFromLink("shadowsocks", params) : undefined;
  return outboundBase("shadowsocks", tagFromRemark("shadowsocks", split.remark, options), {
    servers: [
      {
        address: endpoint.address,
        port: endpoint.port,
        method: userInfo.method,
        password: userInfo.password
      }
    ]
  }, streamSettings);
}

function finalmaskFromHysteriaParams(params: URLSearchParams): JsonObject | undefined {
  const existing = parseJsonObject(param(params, "fm"));
  if (existing) return existing;
  const obfs = param(params, "obfs");
  const obfsPassword = param(params, "obfs-password");
  const mports = param(params, "mports");
  const udp = obfs === "salamander" && obfsPassword
    ? [{ type: "salamander", settings: { password: obfsPassword } }]
    : undefined;
  const quicParams = mports ? { udpHop: { ports: mports } } : undefined;
  if (!udp && !quicParams) return undefined;
  return compactObject({ udp, quicParams });
}

function parseHysteria(uri: string, options: UriToXrayJsonOptions): JsonObject {
  const split = splitUri(uri);
  const url = new URL(uri);
  const auth = rawUserInfoFromMain(split.main);
  if (!auth) throw new Error("Hysteria2 URI requires auth user info.");
  const params = paramsFromQuery(split.query);
  const finalmask = finalmaskFromHysteriaParams(params);
  const streamSettings: Record<string, JsonValue> = {
    network: "hysteria",
    hysteriaSettings: compactObject({
      version: 2,
      auth
    })
  };
  appendSecurityToStream(streamSettings, param(params, "security"), params);
  if (finalmask) streamSettings.finalmask = finalmask;
  return outboundBase("hysteria", tagFromRemark("hysteria", split.remark, options), {
    version: 2,
    address: cleanHostname(url.hostname),
    port: parseInteger(url.port, "Hysteria2 URI")
  }, compactObject(streamSettings));
}

function parseWireguardReserved(value: string | undefined): number[] | string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  const body = trimmed.startsWith("[") && trimmed.endsWith("]") ? trimmed.slice(1, -1) : trimmed;
  const numbers = body.split(",").map((part) => part.trim()).filter(Boolean).map((part) => Number(part));
  return numbers.every((item) => Number.isInteger(item)) ? numbers : value;
}

function parseWireguard(uri: string, options: UriToXrayJsonOptions): JsonObject {
  const split = splitUri(uri);
  const url = new URL(uri);
  const privateKey = rawUserInfoFromMain(split.main);
  if (!privateKey) throw new Error("WireGuard URI requires a private key.");
  const params = paramsFromQuery(split.query);
  const publicKey = param(params, "publickey");
  if (!publicKey) throw new Error("WireGuard URI requires publickey.");
  const address = cleanHostname(url.hostname);
  const port = parseInteger(url.port, "WireGuard URI");
  return outboundBase("wireguard", tagFromRemark("wireguard", split.remark, options), compactObject({
    secretKey: privateKey,
    address: splitCsv(param(params, "address")),
    mtu: parseOptionalInteger(param(params, "mtu")),
    reserved: parseWireguardReserved(param(params, "reserved")),
    domainStrategy: "ForceIP",
    peers: [
      compactObject({
        endpoint: `${authorityHost(address)}:${port}`,
        publicKey,
        allowedIPs: splitCsv(param(params, "allowedips")) ?? ["0.0.0.0/0", "::/0"],
        keepAlive: parseOptionalInteger(param(params, "keepalive")),
        preSharedKey: param(params, "presharedkey")
      })
    ]
  }));
}

export function generateXrayOutboundFromUri(uri: string, options: UriToXrayJsonOptions = {}): JsonObject {
  const { scheme } = splitUri(uri);
  if (scheme === "vmess") return parseVmess(uri, options);
  if (scheme === "vless") return parseVless(uri, options);
  if (scheme === "trojan") return parseTrojan(uri, options);
  if (scheme === "ss") return parseShadowsocks(uri, options);
  if (scheme === "hysteria2" || scheme === "hy2") return parseHysteria(uri, options);
  if (scheme === "wireguard") return parseWireguard(uri, options);
  throw new Error(`Unsupported client URI scheme "${scheme}".`);
}

export function generateXrayConfigFromUri(uri: string, options: UriToXrayJsonOptions = {}): XrayConfig {
  return {
    outbounds: [generateXrayOutboundFromUri(uri, options)]
  };
}

function firstVnext(outbound: JsonObject, options: XrayJsonToUriOptions): { address: string; port: number; user: JsonObject } {
  const settings = isJsonObject(outbound.settings) ? outbound.settings : {};
  const vnext = asObjectArray(settings.vnext)[options.serverIndex ?? 0];
  if (!vnext) throw new Error(`${outbound.protocol ?? "Outbound"} JSON requires settings.vnext.`);
  const user = asObjectArray(vnext.users)[options.userIndex ?? 0];
  const address = asString(vnext.address);
  const port = asNumber(vnext.port);
  if (!address || port === undefined || !user) throw new Error(`${outbound.protocol ?? "Outbound"} JSON requires address, port, and a user.`);
  return { address, port, user };
}

function firstServer(outbound: JsonObject, options: XrayJsonToUriOptions): JsonObject {
  const settings = isJsonObject(outbound.settings) ? outbound.settings : {};
  const server = asObjectArray(settings.servers)[options.serverIndex ?? 0];
  if (!server) throw new Error(`${outbound.protocol ?? "Outbound"} JSON requires settings.servers.`);
  return server;
}

function endpointFromServer(server: JsonObject, options: XrayJsonToUriOptions, label: string): { address: string; port: number } {
  const address = options.host ?? asString(server.address);
  const port = options.port ?? asNumber(server.port);
  if (!address || port === undefined) throw new Error(`${label} JSON requires address and port.`);
  return { address, port };
}

function remarkForOutbound(outbound: JsonObject, options: XrayJsonToUriOptions): string | undefined {
  return options.remark ?? asString(outbound.tag);
}

function generateVmessUri(outbound: JsonObject, options: XrayJsonToUriOptions): string {
  const { address, port, user } = firstVnext(outbound, options);
  const streamSettings = isJsonObject(outbound.streamSettings) ? outbound.streamSettings : undefined;
  const payload: Record<string, LooseJsonValue> = {
    v: "2",
    ps: remarkForOutbound(outbound, options),
    add: options.host ?? address,
    port: options.port ?? port,
    id: user.id,
    aid: String(user.alterId ?? 0),
    scy: user.security ?? "auto"
  };
  appendTransportToVmessPayload(payload, streamSettings);
  return `vmess://${base64EncodeUtf8(JSON.stringify(sortJson(compactObject(payload))))}`;
}

function generateVlessUri(outbound: JsonObject, options: XrayJsonToUriOptions): string {
  const { address, port, user } = firstVnext(outbound, options);
  const id = asString(user.id);
  if (!id) throw new Error("VLESS outbound JSON requires a user id.");
  const params = new URLSearchParams();
  params.set("encryption", asString(user.encryption) ?? "none");
  setParam(params, "flow", user.flow);
  appendTransportParamsFromStream(params, isJsonObject(outbound.streamSettings) ? outbound.streamSettings : undefined, "vless");
  return `vless://${encodeURIComponent(id)}@${authorityHost(options.host ?? address)}:${options.port ?? port}?${params.toString()}${encodeFragment(remarkForOutbound(outbound, options))}`;
}

function generateTrojanUri(outbound: JsonObject, options: XrayJsonToUriOptions): string {
  const server = firstServer(outbound, options);
  const password = asString(server.password);
  if (!password) throw new Error("Trojan outbound JSON requires a server password.");
  const endpoint = endpointFromServer(server, options, "Trojan outbound");
  const params = new URLSearchParams();
  setParam(params, "flow", server.flow);
  appendTransportParamsFromStream(params, isJsonObject(outbound.streamSettings) ? outbound.streamSettings : undefined, "trojan");
  return `trojan://${encodeURIComponent(password)}@${authorityHost(endpoint.address)}:${endpoint.port}?${params.toString()}${encodeFragment(remarkForOutbound(outbound, options))}`;
}

function generateShadowsocksUri(outbound: JsonObject, options: XrayJsonToUriOptions): string {
  const server = firstServer(outbound, options);
  const method = asString(server.method);
  const password = asString(server.password);
  if (!method || !password) throw new Error("Shadowsocks outbound JSON requires method and password.");
  const endpoint = endpointFromServer(server, options, "Shadowsocks outbound");
  const streamSettings = isJsonObject(outbound.streamSettings) ? outbound.streamSettings : undefined;
  const params = new URLSearchParams();
  if (streamSettings) appendTransportParamsFromStream(params, streamSettings, "shadowsocks");
  const query = params.toString();
  return `ss://${base64EncodeUtf8(`${method}:${password}`)}@${authorityHost(endpoint.address)}:${endpoint.port}${query ? `?${query}` : ""}${encodeFragment(remarkForOutbound(outbound, options))}`;
}

function hysteriaFinalmaskParams(params: URLSearchParams, streamSettings: JsonObject | undefined): void {
  const finalmask = isJsonObject(streamSettings?.finalmask) ? streamSettings.finalmask : undefined;
  const udpEntries = Array.isArray(finalmask?.udp) ? finalmask.udp.filter(isJsonObject) : [];
  const salamander = udpEntries.find((entry) => entry.type === "salamander" && isJsonObject(entry.settings));
  if (salamander && isJsonObject(salamander.settings)) {
    params.set("obfs", "salamander");
    setParam(params, "obfs-password", salamander.settings.password);
  }
  const quicParams = isJsonObject(finalmask?.quicParams) ? finalmask.quicParams : undefined;
  const udpHop = isJsonObject(quicParams?.udpHop) ? quicParams.udpHop : undefined;
  setParam(params, "mports", Array.isArray(udpHop?.ports) ? udpHop.ports.join(",") : udpHop?.ports);
}

function generateHysteriaUri(outbound: JsonObject, options: XrayJsonToUriOptions): string {
  const settings = isJsonObject(outbound.settings) ? outbound.settings : {};
  const streamSettings = isJsonObject(outbound.streamSettings) ? outbound.streamSettings : undefined;
  const hysteriaSettings = streamSettingsForNetwork(streamSettings, "hysteria") ?? {};
  const auth = asString(hysteriaSettings.auth) ?? asString(settings.auth);
  const address = options.host ?? asString(settings.address);
  const port = options.port ?? asNumber(settings.port);
  if (!auth || !address || port === undefined) throw new Error("Hysteria outbound JSON requires auth, address, and port.");
  const params = new URLSearchParams();
  hysteriaFinalmaskParams(params, streamSettings);
  appendSecurityParams(params, streamSettings);
  if (isJsonObject(streamSettings?.finalmask)) params.set("fm", JSON.stringify(streamSettings.finalmask));
  return `hysteria2://${encodeURIComponent(auth)}@${authorityHost(address)}:${port}?${params.toString()}${encodeFragment(remarkForOutbound(outbound, options))}`;
}

function parseWireguardEndpoint(endpoint: string | undefined, options: XrayJsonToUriOptions): { address: string; port: number } {
  if (options.host && options.port !== undefined) return { address: options.host, port: options.port };
  if (!endpoint) throw new Error("WireGuard outbound JSON requires peer.endpoint or explicit host and port options.");
  return parseAuthority(endpoint, "wireguard");
}

function generateWireguardUri(outbound: JsonObject, options: XrayJsonToUriOptions): string {
  const settings = isJsonObject(outbound.settings) ? outbound.settings : {};
  const peer = asObjectArray(settings.peers)[options.peerIndex ?? 0];
  const privateKey = asString(settings.secretKey);
  const publicKey = asString(peer?.publicKey);
  if (!privateKey || !peer || !publicKey) throw new Error("WireGuard outbound JSON requires secretKey and a peer publicKey.");
  const endpoint = parseWireguardEndpoint(asString(peer.endpoint), options);
  const params = new URLSearchParams();
  params.set("publickey", publicKey);
  const address = asStringArray(settings.address)?.join(",") ?? asString(settings.address);
  setParam(params, "address", address);
  setParam(params, "mtu", settings.mtu);
  const allowedIPs = asStringArray(peer.allowedIPs)?.join(",") ?? asString(peer.allowedIPs);
  setParam(params, "allowedips", allowedIPs);
  setParam(params, "keepalive", peer.keepAlive);
  setParam(params, "reserved", Array.isArray(settings.reserved) ? settings.reserved.join(",") : settings.reserved);
  setParam(params, "presharedkey", peer.preSharedKey);
  return `wireguard://${encodeURIComponent(privateKey)}@${authorityHost(endpoint.address)}:${endpoint.port}/?${params.toString()}${encodeFragment(remarkForOutbound(outbound, options))}`;
}

export function generateUriFromXrayOutbound(outbound: JsonObject, options: XrayJsonToUriOptions = {}): string {
  const protocol = asString(outbound.protocol);
  if (protocol === "vmess") return generateVmessUri(outbound, options);
  if (protocol === "vless") return generateVlessUri(outbound, options);
  if (protocol === "trojan") return generateTrojanUri(outbound, options);
  if (protocol === "shadowsocks") return generateShadowsocksUri(outbound, options);
  if (protocol === "hysteria") return generateHysteriaUri(outbound, options);
  if (protocol === "wireguard") return generateWireguardUri(outbound, options);
  throw new Error(`Unsupported outbound protocol "${protocol ?? "unknown"}".`);
}

export function generateUriFromXrayJson(input: JsonObject, options: XrayJsonToUriOptions = {}): string {
  const selected = Array.isArray(input.outbounds)
    ? input.outbounds[options.outboundIndex ?? 0]
    : input;
  if (!isJsonObject(selected)) throw new Error("Xray JSON input does not contain a selectable outbound.");
  return generateUriFromXrayOutbound(selected, options);
}

export const uriToXrayOutbound = generateXrayOutboundFromUri;
export const uriToXrayConfig = generateXrayConfigFromUri;
export const xrayOutboundToUri = generateUriFromXrayOutbound;
export const xrayJsonToUri = generateUriFromXrayJson;
