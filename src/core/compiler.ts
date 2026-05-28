import { getXrayAdapter } from "../adapters/xray/registry.js";
import { analyzeProfile } from "../analyze/index.js";
import { applyRawPatch, cloneJson, isJsonObject, mergeTopLevel } from "./json.js";
import { hasErrors, makeIssue } from "./issues.js";
import { normalizeProfile, profileSourceFingerprint } from "./profile.js";
import type {
  BuildOptions,
  BuildResult,
  Dns,
  Fallback,
  GrpcTransport,
  HttpUpgradeTransport,
  Inbound,
  Issue,
  JsonObject,
  JsonValue,
  KcpTransport,
  Outbound,
  Profile,
  QuicParams,
  RealitySecurity,
  Security,
  Sniffing,
  StreamAdvanced,
  TcpTransport,
  TlsSecurity,
  Transport,
  WebSocketTransport,
  XHttpTransport,
  XrayConfig
} from "./types.js";

function compactObject(input: Record<string, JsonValue | undefined>): JsonObject {
  const output: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) output[key] = value;
  }
  return output;
}

function compactArray<T extends JsonValue>(input: readonly (T | undefined)[]): T[] {
  return input.filter((item): item is T => item !== undefined);
}

function getJsonObjectTag(value: JsonValue): string | undefined {
  return isJsonObject(value) && typeof value.tag === "string" ? value.tag : undefined;
}

function uniqueTaggedItems(items: JsonValue[]): Map<string, JsonValue> {
  const tagged = new Map<string, JsonValue>();
  const duplicates = new Set<string>();
  for (const item of items) {
    const tag = getJsonObjectTag(item);
    if (!tag) continue;
    if (tagged.has(tag)) {
      tagged.delete(tag);
      duplicates.add(tag);
      continue;
    }
    if (!duplicates.has(tag)) tagged.set(tag, item);
  }
  return tagged;
}

function isEmptyJsonObject(value: JsonValue): boolean {
  return isJsonObject(value) && Object.keys(value).length === 0;
}

function shouldSkipMissingSourceField(parentKey: string | undefined, key: string, value: JsonValue): boolean {
  if (isEmptyJsonObject(value)) return true;
  return parentKey === "streamSettings" && key === "network" && value === "tcp";
}

const knownSourceFieldsByParent = new Map<string, ReadonlySet<string>>([
  ["__root", new Set(["log", "dns", "routing", "inbounds", "outbounds"])],
  ["inbounds", new Set(["tag", "listen", "port", "protocol", "settings", "streamSettings", "sniffing"])],
  ["outbounds", new Set(["tag", "protocol", "sendThrough", "settings", "streamSettings", "proxySettings", "mux", "targetStrategy"])],
  ["settings", new Set([
    "clients",
    "default",
    "flow",
    "decryption",
    "encryption",
    "fallbacks",
    "accounts",
    "allowTransparent",
    "userLevel",
    "auth",
    "udp",
    "ip",
    "secretKey",
    "publicKey",
    "pubKey",
    "address",
    "peers",
    "mtu",
    "workers",
    "reserved",
    "domainStrategy",
    "noKernelTun",
    "port",
    "network",
    "followRedirect",
    "portMap",
    "name",
    "gateway",
    "dns",
    "autoSystemRoutingTable",
    "autoOutboundsInterface",
    "method",
    "password",
    "level",
    "email",
    "servers",
    "vnext",
    "response",
    "redirect"
  ])],
  ["vnext", new Set(["address", "port", "users"])],
  ["servers", new Set(["address", "port", "domains", "expectedIPs", "skipFallback", "queryStrategy", "tag", "password", "method", "level", "email", "flow", "uot", "uotVersion", "ivCheck", "users"])],
  ["users", new Set(["id", "alterId", "security", "encryption", "flow", "password", "method", "level", "email", "experiments"])],
  ["streamSettings", new Set([
    "network",
    "security",
    "tlsSettings",
    "realitySettings",
    "tcpSettings",
    "rawSettings",
    "grpcSettings",
    "xhttpSettings",
    "splithttpSettings",
    "wsSettings",
    "httpupgradeSettings",
    "kcpSettings",
    "hysteriaSettings",
    "sockopt",
    "finalmask"
  ])],
  ["tlsSettings", new Set([
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
    "echSockopt",
    "certificates"
  ])],
  ["realitySettings", new Set([
    "serverNames",
    "privateKey",
    "publicKey",
    "shortIds",
    "target",
    "dest",
    "spiderX",
    "fingerprint",
    "mldsa65Seed",
    "mldsa65Verify",
    "maxTimeDiff",
    "show"
  ])],
  ["tcpSettings", new Set(["acceptProxyProtocol", "header"])],
  ["rawSettings", new Set(["acceptProxyProtocol", "header"])],
  ["grpcSettings", new Set(["serviceName", "authority", "multiMode", "idle_timeout", "health_check_timeout", "permit_without_stream", "initial_windows_size", "user_agent"])],
  ["xhttpSettings", new Set(["host", "path", "mode", "headers", "scMaxBufferedPosts", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scStreamUpServerSecs", "noSSEHeader", "xPaddingBytes", "xPaddingObfsMode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod", "sessionPlacement", "sessionKey", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize", "noGRPCHeader", "xmux"])],
  ["splithttpSettings", new Set(["host", "path", "mode", "headers", "scMaxBufferedPosts", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scStreamUpServerSecs", "noSSEHeader", "xPaddingBytes", "xPaddingObfsMode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod", "sessionPlacement", "sessionKey", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize", "noGRPCHeader", "xmux"])],
  ["wsSettings", new Set(["path", "host", "headers", "acceptProxyProtocol", "heartbeatPeriod"])],
  ["httpupgradeSettings", new Set(["path", "host", "headers", "acceptProxyProtocol"])],
  ["kcpSettings", new Set(["mtu", "tti", "uplinkCapacity", "downlinkCapacity", "cwndMultiplier", "maxSendingWindow"])],
  ["hysteriaSettings", new Set(["version", "auth", "udpIdleTimeout", "masquerade"])],
  ["sniffing", new Set(["enabled", "destOverride", "domainsExcluded", "ipsExcluded", "metadataOnly", "routeOnly"])],
  ["proxySettings", new Set(["tag", "transportLayer"])],
  ["mux", new Set(["enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"])],
  ["routing", new Set(["domainStrategy", "rules", "balancers"])],
  ["rules", new Set(["type", "ruleTag", "inboundTag", "outboundTag", "balancerTag", "domain", "domains", "ip", "port", "sourceIP", "source", "sourcePort", "user", "vlessRoute", "protocol", "network", "attrs", "localIP", "localPort", "process", "webhook"])],
  ["webhook", new Set(["url", "deduplication", "headers"])],
  ["balancers", new Set(["tag", "selector", "strategy", "fallbackTag"])],
  ["strategy", new Set(["type", "settings"])],
  ["dns", new Set(["servers", "hosts", "queryStrategy", "disableCache", "disableFallback"])],
  ["observatory", new Set(["subjectSelector", "probeURL", "probeUrl", "probeInterval", "enableConcurrency"])],
  ["burstObservatory", new Set(["subjectSelector", "pingConfig"])],
  ["pingConfig", new Set(["destination", "connectivity", "interval", "timeout", "sampling", "httpMethod"])]
]);

function shouldDropMissingCompiledField(parentKey: string | undefined, key: string): boolean {
  return knownSourceFieldsByParent.get(parentKey ?? "__root")?.has(key) === true;
}

function mergeJsonPreservingSource(source: JsonValue, compiled: JsonValue, parentKey?: string): JsonValue {
  if (Array.isArray(source) && Array.isArray(compiled)) {
    const sourceByTag = uniqueTaggedItems(source);
    return compiled.map((item, index) => {
      const tag = getJsonObjectTag(item);
      const sourceItem = tag ? sourceByTag.get(tag) ?? source[index] : source[index];
      return sourceItem === undefined ? cloneJson(item) : mergeJsonPreservingSource(sourceItem, item, parentKey);
    });
  }
  if (isJsonObject(source) && isJsonObject(compiled)) {
    if (
      typeof source.tag === "string" &&
      typeof compiled.tag === "string" &&
      source.tag !== compiled.tag
    ) {
      return cloneJson(compiled);
    }
    if (
      typeof source.protocol === "string" &&
      typeof compiled.protocol === "string" &&
      source.protocol !== compiled.protocol
    ) {
      return cloneJson(compiled);
    }
    const output: Record<string, JsonValue | undefined> = { ...cloneJson(source) };
    for (const key of Object.keys(source)) {
      if (compiled[key] === undefined && shouldDropMissingCompiledField(parentKey, key)) delete output[key];
    }
    for (const [key, value] of Object.entries(compiled)) {
      if (value === undefined) continue;
      const sourceValue = source[key];
      if (sourceValue === undefined) {
        if (shouldSkipMissingSourceField(parentKey, key, value)) continue;
        output[key] = cloneJson(value);
        continue;
      }
      output[key] = mergeJsonPreservingSource(sourceValue, value, key);
    }
    return output as JsonObject;
  }
  return cloneJson(compiled);
}

function compileFallback(fallback: Fallback): JsonObject {
  return compactObject({
    name: fallback.name,
    alpn: fallback.alpn,
    path: fallback.path,
    dest: fallback.dest,
    type: fallback.type,
    xver: fallback.xver
  });
}

function compileSniffing(sniffing: Sniffing | undefined): JsonObject | undefined {
  if (!sniffing) return undefined;
  return compactObject({
    enabled: sniffing.enabled,
    destOverride: sniffing.destOverride,
    domainsExcluded: sniffing.domainsExcluded,
    ipsExcluded: sniffing.ipsExcluded,
    metadataOnly: sniffing.metadataOnly,
    routeOnly: sniffing.routeOnly
  });
}

function shadowsocksUsesServerPassword(method: string | undefined): boolean {
  return method === "2022-blake3-aes-128-gcm" || method === "2022-blake3-aes-256-gcm";
}

function compileTls(security: TlsSecurity): JsonObject {
  return compactObject({
    serverName: security.serverName,
    alpn: security.alpn,
    fingerprint: security.fingerprint,
    allowInsecure: security.allowInsecure,
    enableSessionResumption: security.enableSessionResumption,
    disableSystemRoot: security.disableSystemRoot,
    minVersion: security.minVersion,
    maxVersion: security.maxVersion,
    cipherSuites: security.cipherSuites,
    rejectUnknownSni: security.rejectUnknownSni,
    curvePreferences: security.curvePreferences,
    masterKeyLog: security.masterKeyLog,
    pinnedPeerCertSha256: security.pinnedPeerCertSha256,
    verifyPeerCertByName: security.verifyPeerCertByName?.join(","),
    echServerKeys: security.echServerKeys,
    echConfigList: security.echConfigList,
    echForceQuery: security.echForceQuery,
    echSockopt: security.echSockopt,
    certificates: security.certificates?.map((certificate) => compactObject({
      ...certificate.raw,
      certificateFile: certificate.certificateFile,
      keyFile: certificate.keyFile,
      certificate: certificate.certificate,
      key: certificate.key,
      usage: certificate.usage,
      ocspStapling: certificate.ocspStapling,
      oneTimeLoading: certificate.oneTimeLoading,
      buildChain: certificate.buildChain,
      serveOnNode: certificate.serveOnNode
    }))
  });
}

function compileRealityServer(security: RealitySecurity): JsonObject {
  return compactObject({
    show: security.show,
    target: security.target,
    serverNames: security.serverNames,
    privateKey: security.privateKey,
    shortIds: security.shortIds,
    maxTimeDiff: security.maxTimeDiff,
    mldsa65Seed: security.mldsa65Seed,
    spiderX: security.spiderX
  });
}

function compileTcp(transport: TcpTransport): JsonObject {
  return compactObject({
    acceptProxyProtocol: transport.acceptProxyProtocol,
    header: transport.header
      ? compactObject({
          type: transport.header.type,
          request: transport.header.request ? compactObject(transport.header.request as unknown as Record<string, JsonValue | undefined>) : undefined,
          response: transport.header.response ? compactObject(transport.header.response as unknown as Record<string, JsonValue | undefined>) : undefined
        })
      : undefined
  });
}

function compileGrpc(transport: GrpcTransport): JsonObject {
  return compactObject({
    authority: transport.authority,
    serviceName: transport.serviceName,
    multiMode: transport.multiMode,
    idle_timeout: transport.idleTimeout,
    health_check_timeout: transport.healthCheckTimeout,
    permit_without_stream: transport.permitWithoutStream,
    initial_windows_size: transport.initialWindowsSize,
    user_agent: transport.userAgent
  });
}

function compileXhttp(transport: XHttpTransport): JsonObject {
  return compactObject({
    ...transport.extra?.unknown,
    host: transport.host,
    path: transport.path,
    mode: transport.mode,
    headers: transport.extra?.headers,
    scMaxBufferedPosts: transport.extra?.scMaxBufferedPosts,
    scMaxEachPostBytes: transport.extra?.scMaxEachPostBytes,
    scMinPostsIntervalMs: transport.extra?.scMinPostsIntervalMs,
    scStreamUpServerSecs: transport.extra?.scStreamUpServerSecs,
    noSSEHeader: transport.extra?.noSSEHeader,
    xPaddingBytes: transport.extra?.xPaddingBytes,
    xPaddingObfsMode: transport.extra?.xPaddingObfsMode,
    xPaddingKey: transport.extra?.xPaddingKey,
    xPaddingHeader: transport.extra?.xPaddingHeader,
    xPaddingPlacement: transport.extra?.xPaddingPlacement,
    xPaddingMethod: transport.extra?.xPaddingMethod,
    uplinkHTTPMethod: transport.extra?.uplinkHTTPMethod,
    sessionPlacement: transport.extra?.sessionPlacement,
    sessionKey: transport.extra?.sessionKey,
    seqPlacement: transport.extra?.seqPlacement,
    seqKey: transport.extra?.seqKey,
    uplinkDataPlacement: transport.extra?.uplinkDataPlacement,
    uplinkDataKey: transport.extra?.uplinkDataKey,
    uplinkChunkSize: transport.extra?.uplinkChunkSize,
    noGRPCHeader: transport.extra?.noGRPCHeader,
    xmux: transport.extra?.xmux
  });
}

function compileWebSocket(transport: WebSocketTransport): JsonObject {
  return compactObject({
    path: transport.path,
    host: transport.host,
    headers: transport.headers,
    acceptProxyProtocol: transport.acceptProxyProtocol,
    heartbeatPeriod: transport.heartbeatPeriod
  });
}

function compileHttpUpgrade(transport: HttpUpgradeTransport): JsonObject {
  return compactObject({
    path: transport.path,
    host: transport.host,
    headers: transport.headers,
    acceptProxyProtocol: transport.acceptProxyProtocol
  });
}

function compileKcp(transport: KcpTransport): JsonObject {
  return compactObject({
    mtu: transport.mtu,
    tti: transport.tti,
    uplinkCapacity: transport.uplinkCapacity,
    downlinkCapacity: transport.downlinkCapacity,
    cwndMultiplier: transport.cwndMultiplier,
    maxSendingWindow: transport.maxSendingWindow
  });
}

function compileQuicParams(params: QuicParams): JsonObject {
  return compactObject({
    congestion: params.congestion,
    debug: params.debug,
    bbrProfile: params.bbrProfile,
    brutalUp: params.brutalUp,
    brutalDown: params.brutalDown,
    udpHop: params.udpHop ? compactObject({
      ports: Array.isArray(params.udpHop.ports) ? params.udpHop.ports.join(",") : params.udpHop.ports,
      interval: params.udpHop.interval
    }) : undefined,
    initStreamReceiveWindow: params.initStreamReceiveWindow,
    maxStreamReceiveWindow: params.maxStreamReceiveWindow,
    initConnectionReceiveWindow: params.initConnectionReceiveWindow,
    maxConnectionReceiveWindow: params.maxConnectionReceiveWindow,
    maxIdleTimeout: params.maxIdleTimeout,
    keepAlivePeriod: params.keepAlivePeriod,
    disablePathMTUDiscovery: params.disablePathMTUDiscovery,
    maxIncomingStreams: params.maxIncomingStreams
  });
}

function compileHysteria(transport: Extract<Transport, { type: "hysteria" }>): JsonObject {
  return compactObject({
    version: transport.version,
    auth: transport.auth,
    udpIdleTimeout: transport.udpIdleTimeout,
    masquerade: transport.masquerade ? compactObject({
      type: transport.masquerade.type,
      dir: transport.masquerade.dir,
      url: transport.masquerade.url,
      rewriteHost: transport.masquerade.rewriteHost,
      insecure: transport.masquerade.insecure,
      content: transport.masquerade.content,
      headers: transport.masquerade.headers,
      statusCode: transport.masquerade.statusCode
    }) : undefined
  });
}

export function compileStreamSettings(
  transport: Transport,
  security: Security,
  advanced?: StreamAdvanced
): JsonObject {
  const streamSettings: Record<string, JsonValue> = {
    network: transport.type,
    security: security.type
  };

  if (security.type === "tls") streamSettings.tlsSettings = compileTls(security);
  if (security.type === "reality") streamSettings.realitySettings = compileRealityServer(security);

  if (transport.type === "tcp") streamSettings.tcpSettings = compileTcp(transport);
  if (transport.type === "grpc") streamSettings.grpcSettings = compileGrpc(transport);
  if (transport.type === "xhttp") streamSettings.xhttpSettings = compileXhttp(transport);
  if (transport.type === "ws") streamSettings.wsSettings = compileWebSocket(transport);
  if (transport.type === "httpupgrade") streamSettings.httpupgradeSettings = compileHttpUpgrade(transport);
  if (transport.type === "kcp") streamSettings.kcpSettings = compileKcp(transport);
  if (transport.type === "hysteria") streamSettings.hysteriaSettings = compileHysteria(transport);
  if (advanced?.sockopt) streamSettings.sockopt = advanced.sockopt;
  if (advanced?.finalmask || advanced?.quicParams) {
    streamSettings.finalmask = compactObject({
      ...(advanced.finalmask ?? {}),
      quicParams: advanced.quicParams ? compileQuicParams(advanced.quicParams) : advanced.finalmask?.quicParams
    });
  }

  let compiled = compactObject(streamSettings);
  for (const patch of advanced?.patches ?? []) {
    compiled = applyRawPatch(compiled, patch);
  }

  return compiled;
}

function compileInboundBase(inbound: Exclude<Inbound, { protocol: "unmanaged" }>, settings: JsonObject, security?: Security, transport?: Transport): JsonObject {
  const streamAdvanced = "streamAdvanced" in inbound ? inbound.streamAdvanced : undefined;
  const compiled = compactObject({
    tag: inbound.tag,
    listen: inbound.listen,
    port: "port" in inbound ? inbound.port : undefined,
    protocol: inbound.protocol,
    settings,
    streamSettings: security && transport ? compileStreamSettings(transport, security, streamAdvanced) : undefined,
    sniffing: compileSniffing(inbound.sniffing)
  });

  let withRaw = compiled;
  for (const patch of inbound.raw ?? []) {
    withRaw = applyRawPatch(withRaw, patch);
  }
  return withRaw;
}

function compileInbound(inbound: Inbound): JsonObject {
  if (inbound.protocol === "unmanaged") return cloneJson(inbound.raw);

  if (inbound.protocol === "vmess") {
    const settings = compactObject({
      clients: inbound.clients
        .filter((client) => client.enabled !== false)
        .map((client) => compactObject({
          id: client.id,
          security: client.security ?? "auto",
          email: client.email,
          level: client.level
        })),
      default: inbound.defaultLevel === undefined ? undefined : { level: inbound.defaultLevel }
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "vless") {
    const inboundFlow =
      typeof inbound.flow === "string" && inbound.flow.trim() !== "" ? inbound.flow.trim() : undefined;
    const settings = compactObject({
      clients: inbound.clients
        .filter((client) => client.enabled !== false)
        .map((client) => compactObject({
          id: client.id,
          email: client.email,
          flow: client.flow,
          level: client.level
        })),
      flow: inboundFlow,
      decryption: inbound.decryption ?? "none",
      encryption: inbound.encryption,
      fallbacks: inbound.fallbacks?.map(compileFallback)
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "trojan") {
    const settings = compactObject({
      clients: inbound.clients
        .filter((client) => client.enabled !== false)
        .map((client) => compactObject({
          password: client.password,
          email: client.email,
          level: client.level
        })),
      fallbacks: inbound.fallbacks?.map(compileFallback)
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "http") {
    const settings = compactObject({
      accounts: inbound.accounts?.map((account) => compactObject({
        user: account.user,
        pass: account.pass
      })),
      allowTransparent: inbound.allowTransparent,
      userLevel: inbound.userLevel
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "mixed" || inbound.protocol === "socks") {
    const settings = compactObject({
      auth: inbound.auth ?? (inbound.accounts && inbound.accounts.length > 0 ? "password" : "noauth"),
      accounts: inbound.accounts?.map((account) => compactObject({
        user: account.user,
        pass: account.pass
      })),
      udp: inbound.udp,
      ip: inbound.ip,
      userLevel: inbound.userLevel
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "wireguard") {
    const settings = compactObject({
      secretKey: inbound.secretKey,
      address: inbound.address,
      peers: inbound.peers.map((peer) => compactObject({
        publicKey: peer.publicKey,
        preSharedKey: peer.preSharedKey,
        endpoint: peer.endpoint,
        keepAlive: peer.keepAlive,
        allowedIPs: peer.allowedIPs
      })),
      mtu: inbound.mtu,
      workers: inbound.workers,
      reserved: inbound.reserved,
      domainStrategy: inbound.domainStrategy,
      noKernelTun: inbound.noKernelTun
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "hysteria") {
    const settings = compactObject({
      version: inbound.version,
      clients: inbound.clients
        .filter((client) => client.enabled !== false)
        .map((client) => compactObject({
          auth: client.auth,
          email: client.email,
          level: client.level
        }))
    });
    return compileInboundBase(inbound, settings, inbound.security, inbound.transport);
  }

  if (inbound.protocol === "dokodemo-door" || inbound.protocol === "tunnel") {
    const portMap =
      inbound.portMap !== undefined && Object.keys(inbound.portMap).length > 0 ? inbound.portMap : undefined;
    // Xray JSON tags (selected parity): address, port, network — not rewrite*/allowedNetwork.
    const settings = compactObject({
      address: inbound.address,
      port: inbound.targetPort,
      network: inbound.network,
      followRedirect: inbound.followRedirect,
      userLevel: inbound.userLevel,
      portMap
    });
    return compileInboundBase(inbound, settings);
  }

  if (inbound.protocol === "tun") {
    const settings = compactObject({
      name: inbound.name,
      mtu: inbound.mtu,
      gateway: inbound.gateway,
      dns: inbound.dns,
      userLevel: inbound.userLevel,
      autoSystemRoutingTable: inbound.autoSystemRoutingTable,
      autoOutboundsInterface: inbound.autoOutboundsInterface
    });
    return compileInboundBase(inbound, settings);
  }

  const shadowsocksInbound = inbound as Extract<Inbound, { protocol: "shadowsocks" }>;
  const settings = compactObject({
    method: shadowsocksInbound.method,
    password: shadowsocksUsesServerPassword(shadowsocksInbound.method) ? shadowsocksInbound.password : undefined,
    network: shadowsocksInbound.network ?? "tcp,udp",
    clients: shadowsocksInbound.clients
      .filter((client) => client.enabled !== false)
      .map((client) => compactObject({
        method: client.method,
        password: client.password,
        email: client.email,
        level: client.level
      }))
  });
  return compileInboundBase(shadowsocksInbound, settings, shadowsocksInbound.security, shadowsocksInbound.transport);
}

function compileOutbound(outbound: Outbound): JsonObject {
  if (outbound.protocol === "unmanaged") return cloneJson(outbound.raw);
  let compiled = compactObject({
    tag: outbound.tag,
    protocol: outbound.protocol,
    sendThrough: outbound.sendThrough,
    settings: outbound.settings && Object.keys(outbound.settings).length > 0 ? cloneJson(outbound.settings as unknown as JsonObject) : undefined,
    streamSettings: outbound.streamSettings ? cloneJson(outbound.streamSettings) : undefined,
    proxySettings: outbound.proxySettings ? cloneJson(outbound.proxySettings) : undefined,
    mux: outbound.mux ? cloneJson(outbound.mux) : undefined,
    targetStrategy: outbound.targetStrategy
  });
  if ("raw" in outbound) {
    for (const patch of outbound.raw ?? []) {
      compiled = applyRawPatch(compiled, patch);
    }
  }
  return compiled;
}

function compileRouting(profile: Profile): JsonObject | undefined {
  if (!profile.routing) return undefined;
  return compactObject({
    domainStrategy: profile.routing.domainStrategy,
    rules: profile.routing.rules.map((rule) => compactObject({
      type: rule.type ?? "field",
      ruleTag: rule.ruleTag,
      inboundTag: rule.inboundTag,
      outboundTag: rule.outboundTag,
      balancerTag: rule.balancerTag,
      domain: rule.domain,
      domains: rule.domains,
      ip: rule.ip,
      port: rule.port,
      sourceIP: rule.sourceIP,
      source: rule.source,
      sourcePort: rule.sourcePort,
      user: rule.user,
      vlessRoute: rule.vlessRoute,
      protocol: rule.protocol,
      network: rule.network,
      attrs: rule.attrs,
      localIP: rule.localIP,
      localPort: rule.localPort,
      process: rule.process,
      webhook: rule.webhook ? compactObject({
        url: rule.webhook.url,
        deduplication: rule.webhook.deduplication,
        headers: rule.webhook.headers
      }) : undefined
    })),
    balancers: profile.routing.balancers?.map((balancer) => compactObject({
      tag: balancer.tag,
      selector: balancer.selector,
      strategy: balancer.strategy ? compactObject({
        type: balancer.strategy.type,
        settings: balancer.strategy.settings
      }) : undefined,
      fallbackTag: balancer.fallbackTag
    }))
  });
}

function compileDns(dns: Dns | undefined): JsonObject | undefined {
  if (!dns) return undefined;
  return compactObject({
    servers: dns.servers.map((server) => (typeof server === "string" ? server : compactObject({
      address: server.address,
      port: server.port,
      domains: server.domains,
      expectedIPs: server.expectedIPs,
      skipFallback: server.skipFallback,
      queryStrategy: server.queryStrategy,
      tag: server.tag
    }))),
    hosts: dns.hosts,
    queryStrategy: dns.queryStrategy,
    disableCache: dns.disableCache,
    disableFallback: dns.disableFallback
  });
}

function applyUnknownPreservation(config: XrayConfig, profile: Profile): { config: XrayConfig; issues: Issue[] } {
  let next: JsonObject = config;
  const issues: Issue[] = [];
  for (const [path, value] of Object.entries(profile.unknown?.pointers ?? {})) {
    try {
      next = applyRawPatch(next, { op: "add", path: path as `/${string}`, value });
    } catch (error) {
      issues.push(makeIssue({
        code: "XCK_IMPORT_UNKNOWN_PRESERVE_FAILED",
        severity: "warning",
        category: "import",
        path,
        message: `Could not preserve imported unknown field at ${path}.`,
        suggestion: error instanceof Error ? error.message : undefined
      }));
    }
  }
  return { config: next as XrayConfig, issues };
}

function compileProfile(profile: Profile): XrayConfig {
  const config = compactObject({
    log: profile.log,
    dns: compileDns(profile.dns),
    routing: compileRouting(profile),
    inbounds: profile.inbounds.map(compileInbound),
    outbounds: profile.outbounds?.map(compileOutbound)
  });
  return config as XrayConfig;
}

export function buildXrayConfig(profileInput: Profile, options: BuildOptions = {}): BuildResult {
  const adapter = getXrayAdapter(options.xrayVersion);
  const normalized = normalizeProfile(profileInput);
  const analysis = analyzeProfile(normalized, options);
  const strict = options.mode !== "permissive";

  const adapterHasErrors = (adapter.issues ?? []).some((issue) => issue.severity === "error");
  if ((strict && hasErrors(analysis.issues)) || adapterHasErrors) {
    return {
      config: {},
      normalized,
      issues: analysis.issues,
      adapterId: adapter.id
    };
  }

  const compiledProfile = compileProfile(normalized);
  const sourcePreserved = normalized.raw?.source
    ? mergeJsonPreservingSource(normalized.raw.source, compiledProfile) as JsonObject
    : compiledProfile;
  let config = mergeTopLevel(sourcePreserved, normalized.raw?.topLevel) as XrayConfig;
  const issues = [...analysis.issues];

  if (
    normalized.raw?.source &&
    normalized.raw.sourceProfileFingerprint &&
    normalized.raw.sourceProfileFingerprint === profileSourceFingerprint(normalized) &&
    !normalized.raw.patches?.length
  ) {
    config = cloneJson(normalized.raw.source) as XrayConfig;
  }

  if (options.preserveUnknown) {
    const preserved = applyUnknownPreservation(config, normalized);
    config = preserved.config;
    issues.push(...preserved.issues);
  }

  for (const patch of normalized.raw?.patches ?? []) {
    if (patch.unsafe && !options.allowUnsafeRaw) continue;
    try {
      config = applyRawPatch(config, patch);
    } catch (error) {
      issues.push(makeIssue({
        code: "XCK_RAW_PATCH_FAILED",
        severity: strict ? "error" : "warning",
        category: "raw",
        path: patch.path,
        message: `Failed to apply raw patch at ${patch.path}.`,
        suggestion: error instanceof Error ? error.message : undefined,
        adapterId: adapter.id
      }));
    }
  }

  if (!isJsonObject(config)) {
    return {
      config: {},
      normalized,
      issues: [
        ...issues,
        makeIssue({
          code: "XCK_BUILD_NON_OBJECT_CONFIG",
          severity: "error",
          category: "semantic",
          path: "/",
          message: "Compiled Xray config must be a JSON object.",
          adapterId: adapter.id
        })
      ],
      adapterId: adapter.id
    };
  }

  return {
    config,
    normalized,
    issues,
    adapterId: adapter.id
  };
}


