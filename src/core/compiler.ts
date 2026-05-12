import { getXrayAdapter } from "../adapters/xray/registry.js";
import { analyzeProfile } from "../analyze/index.js";
import { applyRawPatch, cloneJson, isJsonObject, mergeTopLevel } from "./json.js";
import { hasErrors, makeIssue } from "./issues.js";
import { normalizeProfile } from "./profile.js";
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
      certificateFile: certificate.certificateFile,
      keyFile: certificate.keyFile,
      certificate: certificate.certificate,
      key: certificate.key,
      usage: certificate.usage,
      ocspStapling: certificate.ocspStapling,
      oneTimeLoading: certificate.oneTimeLoading,
      buildChain: certificate.buildChain
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
    const settings = compactObject({
      clients: inbound.clients
        .filter((client) => client.enabled !== false)
        .map((client) => compactObject({
          id: client.id,
          email: client.email,
          flow: client.flow,
          level: client.level
        })),
      decryption: inbound.decryption ?? "none",
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
    return compileInboundBase(inbound, settings);
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
    return compileInboundBase(inbound, settings);
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
    return compileInboundBase(inbound, settings);
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
    password: shadowsocksInbound.password,
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

  if ((!analysis.ok && hasErrors(analysis.issues)) || (strict && hasErrors(analysis.issues))) {
    return {
      config: {},
      normalized,
      issues: analysis.issues,
      adapterId: adapter.id
    };
  }

  let config = mergeTopLevel(compileProfile(normalized), normalized.raw?.topLevel) as XrayConfig;
  const issues = [...analysis.issues];

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
