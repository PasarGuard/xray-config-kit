import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { inboundPortSchema, jsonObjectSchema, jsonValueSchema, portSchema, tagSchema } from "./shared.js";

export const rawPatchSchema = z.object({
  op: z.enum(["add", "replace", "remove"]),
  path: z.string().regex(/^\/.+/),
  value: jsonValueSchema.optional(),
  unsafe: z.boolean().optional()
}).strict();

export const unknownPreservationSchema = z.object({
  source: z.enum(["import", "rawOverride"]),
  pointers: z.record(jsonValueSchema)
}).strict();

export const fingerprintSchema = z.enum([
  "chrome",
  "firefox",
  "safari",
  "ios",
  "android",
  "edge",
  "360",
  "qq",
  "random",
  "randomized",
  "randomizednoalpn",
  "unsafe"
]);

export const alpnSchema = z.enum(["h2", "h3", "http/1.1"]);

export const shadowsocksMethodSchema = z.enum([
  "aes-128-gcm",
  "aes-256-gcm",
  "chacha20-poly1305",
  "chacha20-ietf-poly1305",
  "xchacha20-poly1305",
  "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm"
]);

export const vmessSecuritySchema = z.enum(["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"]);

export const vmessClientSchema = z.object({
  protocol: z.literal("vmess"),
  id: z.string().min(1),
  security: vmessSecuritySchema.optional(),
  email: z.string().optional(),
  level: z.number().int().min(0).optional(),
  enabled: z.boolean().optional(),
  meta: z.record(jsonValueSchema).optional()
}).strict();

export const vlessClientSchema = z.object({
  protocol: z.literal("vless"),
  id: z.string().min(1),
  email: z.string().optional(),
  flow: z.literal("xtls-rprx-vision").optional(),
  level: z.number().int().min(0).optional(),
  enabled: z.boolean().optional(),
  meta: z.record(jsonValueSchema).optional()
}).strict();

export const trojanClientSchema = z.object({
  protocol: z.literal("trojan"),
  password: z.string().min(1),
  email: z.string().optional(),
  level: z.number().int().min(0).optional(),
  enabled: z.boolean().optional(),
  meta: z.record(jsonValueSchema).optional()
}).strict();

export const shadowsocksClientSchema = z.object({
  protocol: z.literal("shadowsocks"),
  password: z.string().min(1),
  method: shadowsocksMethodSchema.optional(),
  email: z.string().optional(),
  level: z.number().int().min(0).optional(),
  enabled: z.boolean().optional(),
  meta: z.record(jsonValueSchema).optional()
}).strict();

export const hysteriaClientSchema = z.object({
  protocol: z.literal("hysteria"),
  auth: z.string().min(1),
  email: z.string().optional(),
  level: z.number().int().min(0).optional(),
  enabled: z.boolean().optional(),
  meta: z.record(jsonValueSchema).optional()
}).strict();

export const clientSchema = z.discriminatedUnion("protocol", [
  vmessClientSchema,
  vlessClientSchema,
  trojanClientSchema,
  shadowsocksClientSchema,
  hysteriaClientSchema
]);

export const noneSecuritySchema = z.object({
  type: z.literal("none")
}).strict();

export const tlsCertificateSchema = z.object({
  certificateFile: z.string().optional(),
  keyFile: z.string().optional(),
  certificate: z.array(z.string()).optional(),
  key: z.array(z.string()).optional(),
  usage: z.enum(["encipherment", "verify", "issue"]).optional(),
  ocspStapling: z.number().int().min(0).optional(),
  oneTimeLoading: z.boolean().optional(),
  buildChain: z.boolean().optional()
}).strict();

export const tlsSecuritySchema = z.object({
  type: z.literal("tls"),
  serverName: z.string().optional(),
  alpn: z.array(alpnSchema).optional(),
  fingerprint: fingerprintSchema.optional(),
  allowInsecure: z.boolean().optional(),
  enableSessionResumption: z.boolean().optional(),
  disableSystemRoot: z.boolean().optional(),
  minVersion: z.string().optional(),
  maxVersion: z.string().optional(),
  cipherSuites: z.string().optional(),
  rejectUnknownSni: z.boolean().optional(),
  curvePreferences: z.array(z.string()).optional(),
  masterKeyLog: z.string().optional(),
  pinnedPeerCertSha256: z.string().optional(),
  verifyPeerCertByName: z.array(z.string()).optional(),
  echServerKeys: z.string().optional(),
  echConfigList: z.string().optional(),
  echForceQuery: z.enum(["none", "half", "full"]).optional(),
  echSockopt: jsonObjectSchema.optional(),
  certificates: z.array(tlsCertificateSchema).optional()
}).strict();

export const realitySecuritySchema = z.object({
  type: z.literal("reality"),
  serverNames: z.array(z.string().min(1)).min(1),
  privateKey: z.string().min(1),
  publicKey: z.string().optional(),
  shortIds: z.array(z.string()),
  target: z.union([z.string(), z.number().int().min(1).max(65535)]),
  spiderX: z.string().optional(),
  fingerprint: fingerprintSchema.exclude(["unsafe"]).optional(),
  mldsa65Seed: z.string().optional(),
  mldsa65Verify: z.string().optional(),
  maxTimeDiff: z.number().int().min(0).optional(),
  show: z.boolean().optional()
}).strict();

export const securitySchema = z.discriminatedUnion("type", [
  noneSecuritySchema,
  tlsSecuritySchema,
  realitySecuritySchema
]);

const httpHeaderSchema = z.object({
  version: z.enum(["1.0", "1.1", "2.0", "3.0"]).optional(),
  method: z.enum(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]).optional(),
  path: z.array(z.string()).optional(),
  headers: z.record(z.array(z.string())).optional()
}).strict();

export const tcpTransportSchema = z.object({
  type: z.literal("tcp"),
  acceptProxyProtocol: z.boolean().optional(),
  header: z.object({
    type: z.enum(["none", "http"]),
    request: httpHeaderSchema.optional(),
    response: httpHeaderSchema.omit({ method: true, path: true }).extend({
      status: z.string().optional(),
      reason: z.string().optional()
    }).optional()
  }).strict().optional()
}).strict();

export const grpcTransportSchema = z.object({
  type: z.literal("grpc"),
  serviceName: z.string(),
  authority: z.string().optional(),
  multiMode: z.boolean().optional(),
  idleTimeout: z.number().int().min(0).optional(),
  healthCheckTimeout: z.number().int().min(0).optional(),
  permitWithoutStream: z.boolean().optional(),
  initialWindowsSize: z.number().int().min(0).optional(),
  userAgent: z.string().optional()
}).strict();

const intRangeSchema = z.union([
  z.number().int(),
  z.string().regex(/^-?\d+(?:--?\d+)?$/)
]);

export const xhttpExtraSchema = z.object({
  headers: z.record(z.string()).optional(),
  scMaxBufferedPosts: intRangeSchema.optional(),
  scMaxEachPostBytes: intRangeSchema.optional(),
  scMinPostsIntervalMs: intRangeSchema.optional(),
  scStreamUpServerSecs: intRangeSchema.optional(),
  noSSEHeader: z.boolean().optional(),
  xPaddingBytes: intRangeSchema.optional(),
  xPaddingObfsMode: z.boolean().optional(),
  xPaddingKey: z.string().optional(),
  xPaddingHeader: z.string().optional(),
  xPaddingPlacement: z.enum(["cookie", "header", "query", "queryInHeader"]).optional(),
  xPaddingMethod: z.enum(["repeat-x", "tokenish"]).optional(),
  uplinkHTTPMethod: z.string().optional(),
  sessionPlacement: z.enum(["path", "cookie", "header", "query"]).optional(),
  sessionKey: z.string().optional(),
  seqPlacement: z.enum(["path", "cookie", "header", "query"]).optional(),
  seqKey: z.string().optional(),
  uplinkDataPlacement: z.enum(["body", "cookie", "header"]).optional(),
  uplinkDataKey: z.string().optional(),
  uplinkChunkSize: intRangeSchema.optional(),
  noGRPCHeader: z.boolean().optional(),
  xmux: z.record(jsonValueSchema).optional(),
  unknown: z.record(jsonValueSchema).optional()
}).strict();

export const xhttpTransportSchema = z.object({
  type: z.literal("xhttp"),
  path: z.string().optional(),
  host: z.string().optional(),
  mode: z.enum(["auto", "packet-up", "stream-up", "stream-one"]).optional(),
  extra: xhttpExtraSchema.optional()
}).strict();

export const websocketTransportSchema = z.object({
  type: z.literal("ws"),
  path: z.string().optional(),
  host: z.string().optional(),
  headers: z.record(z.string()).optional(),
  acceptProxyProtocol: z.boolean().optional(),
  heartbeatPeriod: z.number().int().min(0).optional()
}).strict();

export const httpUpgradeTransportSchema = z.object({
  type: z.literal("httpupgrade"),
  path: z.string().optional(),
  host: z.string().optional(),
  headers: z.record(z.string()).optional(),
  acceptProxyProtocol: z.boolean().optional()
}).strict();

export const kcpTransportSchema = z.object({
  type: z.literal("kcp"),
  mtu: z.number().int().min(0).optional(),
  tti: z.number().int().min(0).optional(),
  uplinkCapacity: z.number().int().min(0).optional(),
  downlinkCapacity: z.number().int().min(0).optional(),
  cwndMultiplier: z.number().int().min(0).optional(),
  maxSendingWindow: z.number().int().min(0).optional()
}).strict();

export const udpHopSchema = z.object({
  ports: z.union([z.string(), z.array(z.string())]).optional(),
  interval: intRangeSchema.optional()
}).strict();

export const quicParamsSchema = z.object({
  congestion: z.enum(["brutal", "reno", "bbr", "force-brutal"]).optional(),
  debug: z.boolean().optional(),
  bbrProfile: z.enum(["conservative", "standard", "aggressive"]).optional(),
  brutalUp: z.string().optional(),
  brutalDown: z.string().optional(),
  udpHop: udpHopSchema.optional(),
  initStreamReceiveWindow: z.number().int().min(0).optional(),
  maxStreamReceiveWindow: z.number().int().min(0).optional(),
  initConnectionReceiveWindow: z.number().int().min(0).optional(),
  maxConnectionReceiveWindow: z.number().int().min(0).optional(),
  maxIdleTimeout: z.number().int().min(0).optional(),
  keepAlivePeriod: z.number().int().min(0).optional(),
  disablePathMTUDiscovery: z.boolean().optional(),
  maxIncomingStreams: z.number().int().min(0).optional()
}).strict();

export const hysteriaMasqueradeSchema = z.object({
  type: z.string().optional(),
  dir: z.string().optional(),
  url: z.string().optional(),
  rewriteHost: z.boolean().optional(),
  insecure: z.boolean().optional(),
  content: z.string().optional(),
  headers: z.record(z.string()).optional(),
  statusCode: z.number().int().min(0).optional()
}).strict();

export const hysteriaTransportSchema = z.object({
  type: z.literal("hysteria"),
  version: z.literal(2),
  auth: z.string().optional(),
  udpIdleTimeout: z.number().int().min(0).optional(),
  masquerade: hysteriaMasqueradeSchema.optional()
}).strict();

export const transportSchema = z.discriminatedUnion("type", [
  tcpTransportSchema,
  grpcTransportSchema,
  xhttpTransportSchema,
  websocketTransportSchema,
  httpUpgradeTransportSchema,
  kcpTransportSchema,
  hysteriaTransportSchema
]);

export const sniffingSchema = z.object({
  enabled: z.boolean(),
  destOverride: z.array(z.enum(["http", "tls", "quic", "fakedns"])).optional(),
  domainsExcluded: z.array(z.string()).optional(),
  ipsExcluded: z.array(z.string()).optional(),
  metadataOnly: z.boolean().optional(),
  routeOnly: z.boolean().optional()
}).strict();

export const fallbackSchema = z.object({
  name: z.string().optional(),
  alpn: z.string().optional(),
  path: z.string().optional(),
  dest: z.union([z.string(), z.number().int().min(1).max(65535)]),
  type: z.enum(["tcp", "unix", "serve"]).optional(),
  xver: z.union([z.literal(0), z.literal(1), z.literal(2)]).optional()
}).strict();

const baseInboundShape = {
  kind: z.literal("inbound"),
  tag: tagSchema,
  listen: z.string().optional(),
  port: inboundPortSchema,
  sniffing: sniffingSchema.optional(),
  streamAdvanced: z.object({
    sockopt: jsonObjectSchema.optional(),
    finalmask: jsonObjectSchema.optional(),
    quicParams: quicParamsSchema.optional(),
    patches: z.array(rawPatchSchema).optional()
  }).strict().optional(),
  raw: z.array(rawPatchSchema).optional()
};

export const vmessInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("vmess"),
  clients: z.array(vmessClientSchema),
  security: z.discriminatedUnion("type", [tlsSecuritySchema, noneSecuritySchema]),
  transport: transportSchema,
  defaultLevel: z.number().int().min(0).optional()
}).strict();

export const vlessInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("vless"),
  clients: z.array(vlessClientSchema),
  security: securitySchema,
  transport: transportSchema,
  decryption: z.string().optional(),
  encryption: z.string().optional(),
  fallbacks: z.array(fallbackSchema).optional()
}).strict();

export const trojanInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("trojan"),
  clients: z.array(trojanClientSchema),
  security: securitySchema,
  transport: transportSchema,
  fallbacks: z.array(fallbackSchema).optional()
}).strict();

export const shadowsocksInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("shadowsocks"),
  method: shadowsocksMethodSchema.optional(),
  password: z.string().optional(),
  network: z.union([z.string().min(1), z.array(z.string())]).optional(),
  clients: z.array(shadowsocksClientSchema),
  security: z.discriminatedUnion("type", [tlsSecuritySchema, noneSecuritySchema]).optional(),
  transport: transportSchema.optional()
}).strict();

export const httpAccountSchema = z.object({
  user: z.string().min(1),
  pass: z.string().min(1)
}).strict();

export const httpInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("http"),
  accounts: z.array(httpAccountSchema).optional(),
  allowTransparent: z.boolean().optional(),
  userLevel: z.number().int().min(0).optional()
}).strict();

export const mixedAccountSchema = z.object({
  user: z.string().min(1),
  pass: z.string().min(1)
}).strict();

export const mixedInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("mixed"),
  auth: z.enum(["noauth", "password"]).optional(),
  accounts: z.array(mixedAccountSchema).optional(),
  udp: z.boolean().optional(),
  ip: z.string().optional(),
  userLevel: z.number().int().min(0).optional()
}).strict();

export const socksInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("socks"),
  auth: z.enum(["noauth", "password"]).optional(),
  accounts: z.array(mixedAccountSchema).optional(),
  udp: z.boolean().optional(),
  ip: z.string().optional(),
  userLevel: z.number().int().min(0).optional()
}).strict();

export const wireGuardPeerSchema = z.object({
  publicKey: z.string().min(1),
  preSharedKey: z.string().optional(),
  allowedIPs: z.array(z.string()).min(1),
  keepAlive: z.number().int().min(0).optional(),
  endpoint: z.string().optional(),
  meta: z.record(jsonValueSchema).optional()
}).strict();

export const wireGuardInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("wireguard"),
  secretKey: z.string().min(1),
  publicKey: z.string().optional(),
  peers: z.array(wireGuardPeerSchema),
  address: z.array(z.string()).optional(),
  mtu: z.number().int().min(0).optional(),
  workers: z.number().int().min(0).optional(),
  reserved: z.union([z.array(z.number().int().min(0).max(255)).length(3), z.string()]).optional(),
  domainStrategy: z.enum(["forceip", "forceipv4", "forceipv6", "forceipv4v6", "forceipv6v4"]).optional(),
  noKernelTun: z.boolean().optional()
}).strict();

export const hysteriaInboundSchema = z.object({
  ...baseInboundShape,
  protocol: z.literal("hysteria"),
  version: z.literal(2),
  clients: z.array(hysteriaClientSchema),
  security: z.discriminatedUnion("type", [tlsSecuritySchema, noneSecuritySchema]),
  transport: hysteriaTransportSchema
}).strict();

const dokodemoInboundShape = {
  ...baseInboundShape,
  address: z.string().optional(),
  targetPort: portSchema.optional(),
  /** Per-listen-port rewrite targets (`DokodemoConfig.portMap`). */
  portMap: z.record(z.string(), z.string()).optional(),
  network: z.enum(["tcp", "udp", "tcp,udp"]).optional(),
  followRedirect: z.boolean().optional(),
  userLevel: z.number().int().min(0).optional()
};

export const dokodemoDoorInboundSchema = z.object({
  ...dokodemoInboundShape,
  protocol: z.literal("dokodemo-door")
}).strict();

export const tunnelInboundSchema = z.object({
  ...dokodemoInboundShape,
  protocol: z.literal("tunnel")
}).strict();

export const tunInboundSchema = z.object({
  kind: z.literal("inbound"),
  protocol: z.literal("tun"),
  tag: tagSchema,
  listen: z.string().optional(),
  sniffing: sniffingSchema.optional(),
  name: z.string().optional(),
  mtu: z.number().int().min(0).optional(),
  gateway: z.array(z.string()).optional(),
  dns: z.array(z.string()).optional(),
  userLevel: z.number().int().min(0).optional(),
  autoSystemRoutingTable: z.array(z.string()).optional(),
  autoOutboundsInterface: z.string().optional(),
  raw: z.array(rawPatchSchema).optional()
}).strict();

export const unmanagedInboundSchema = z.object({
  kind: z.literal("inbound"),
  protocol: z.literal("unmanaged"),
  tag: z.string().optional(),
  editable: z.literal(false),
  raw: jsonObjectSchema
}).strict();

export const inboundSchema = z.discriminatedUnion("protocol", [
  vmessInboundSchema,
  vlessInboundSchema,
  trojanInboundSchema,
  shadowsocksInboundSchema,
  httpInboundSchema,
  mixedInboundSchema,
  socksInboundSchema,
  wireGuardInboundSchema,
  hysteriaInboundSchema,
  dokodemoDoorInboundSchema,
  tunnelInboundSchema,
  tunInboundSchema,
  unmanagedInboundSchema
]);

export const routingRuleSchema = z.object({
  type: z.literal("field").optional(),
  ruleTag: z.string().optional(),
  inboundTag: z.array(z.string()).optional(),
  outboundTag: z.string().optional(),
  balancerTag: z.string().optional(),
  domain: z.array(z.string()).optional(),
  domains: z.array(z.string()).optional(),
  ip: z.array(z.string()).optional(),
  port: inboundPortSchema.optional(),
  sourceIP: z.array(z.string()).optional(),
  source: z.array(z.string()).optional(),
  sourcePort: inboundPortSchema.optional(),
  user: z.array(z.string()).optional(),
  vlessRoute: inboundPortSchema.optional(),
  protocol: z.array(z.string()).optional(),
  network: z.union([z.string().min(1), z.array(z.string())]).optional(),
  attrs: z.record(z.string()).optional(),
  localIP: z.array(z.string()).optional(),
  localPort: inboundPortSchema.optional(),
  process: z.array(z.string()).optional(),
  webhook: z.object({
    url: z.string().min(1),
    deduplication: z.number().int().min(0).max(4294967295).optional(),
    headers: z.record(z.string()).optional()
  }).strict().optional()
}).strict();

export const routingBalancerSchema = z.object({
  tag: tagSchema,
  selector: z.array(z.string()),
  strategy: z.object({
    type: z.string().optional(),
    settings: jsonObjectSchema.optional()
  }).strict().optional(),
  fallbackTag: z.string().optional()
}).strict();

export const routingSchema = z.object({
  domainStrategy: z.enum(["AsIs", "IPIfNonMatch", "IPOnDemand"]).optional(),
  rules: z.array(routingRuleSchema),
  balancers: z.array(routingBalancerSchema).optional()
}).strict();

export const nameServerSchema = z.object({
  address: z.string(),
  port: portSchema.optional(),
  domains: z.array(z.string()).optional(),
  expectedIPs: z.array(z.string()).optional(),
  skipFallback: z.boolean().optional(),
  queryStrategy: z.enum(["UseIP", "UseIPv4", "UseIPv6"]).optional(),
  tag: z.string().optional()
}).strict();

export const dnsSchema = z.object({
  servers: z.array(z.union([z.string(), nameServerSchema])),
  hosts: z.record(z.union([z.string(), z.array(z.string())])).optional(),
  queryStrategy: z.enum(["UseIP", "UseIPv4", "UseIPv6"]).optional(),
  disableCache: z.boolean().optional(),
  disableFallback: z.boolean().optional()
}).strict();

export const freedomOutboundSchema = z.object({
  protocol: z.literal("freedom"),
  tag: z.string(),
  sendThrough: z.string().optional(),
  settings: jsonObjectSchema.optional(),
  streamSettings: jsonObjectSchema.optional(),
  proxySettings: jsonObjectSchema.optional(),
  mux: jsonObjectSchema.optional(),
  targetStrategy: z.string().optional()
}).strict();

export const blackholeOutboundSchema = z.object({
  protocol: z.literal("blackhole"),
  tag: z.string(),
  sendThrough: z.string().optional(),
  settings: jsonObjectSchema.optional(),
  streamSettings: jsonObjectSchema.optional(),
  proxySettings: jsonObjectSchema.optional(),
  mux: jsonObjectSchema.optional(),
  targetStrategy: z.string().optional()
}).strict();

export const dnsOutboundSchema = z.object({
  protocol: z.literal("dns"),
  tag: z.string(),
  sendThrough: z.string().optional(),
  settings: jsonObjectSchema.optional(),
  streamSettings: jsonObjectSchema.optional(),
  proxySettings: jsonObjectSchema.optional(),
  mux: jsonObjectSchema.optional(),
  targetStrategy: z.string().optional()
}).strict();

export const proxyOutboundSchema = z.object({
  protocol: z.enum(["http", "socks", "shadowsocks", "vless", "vmess", "trojan", "hysteria", "wireguard", "loopback"]),
  tag: z.string(),
  sendThrough: z.string().optional(),
  settings: jsonObjectSchema.optional(),
  streamSettings: jsonObjectSchema.optional(),
  proxySettings: jsonObjectSchema.optional(),
  mux: jsonObjectSchema.optional(),
  targetStrategy: z.string().optional(),
  raw: z.array(rawPatchSchema).optional()
}).strict();

export const unmanagedOutboundSchema = z.object({
  protocol: z.literal("unmanaged"),
  tag: z.string().optional(),
  editable: z.literal(false),
  raw: jsonObjectSchema
}).strict();

export const outboundSchema = z.discriminatedUnion("protocol", [
  freedomOutboundSchema,
  blackholeOutboundSchema,
  dnsOutboundSchema,
  proxyOutboundSchema,
  unmanagedOutboundSchema
]);

export const profileSchema = z.object({
  schemaVersion: z.literal("xck.v1"),
  name: z.string().optional(),
  inbounds: z.array(inboundSchema),
  outbounds: z.array(outboundSchema).optional(),
  routing: routingSchema.optional(),
  dns: dnsSchema.optional(),
  log: z.record(jsonValueSchema).optional(),
  raw: z.object({
    topLevel: z.record(jsonValueSchema).optional(),
    patches: z.array(rawPatchSchema).optional()
  }).strict().optional(),
  unknown: unknownPreservationSchema.optional()
}).strict();

export type ProfileSchema = typeof profileSchema;

export function getProfileJsonSchema() {
  return zodToJsonSchema(profileSchema, {
    name: "XrayConfigKitProfile",
    target: "jsonSchema7"
  });
}
