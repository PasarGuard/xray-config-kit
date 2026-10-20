import { portSchema } from "../schemas/shared.js";
import { firstHostPrefix, masquePoolProblem, parseIpAddress, parseIpPrefix } from "./ip.js";
import type { IpFamily } from "./ip.js";
import { makeIssue } from "./issues.js";
import { escapePointerSegment, isJsonObject } from "./json.js";
import { expandMasquePathTemplate, MASQUE_LIMITS, XDRIVE_LIMITS, XDRIVE_SERVICES } from "./masque-xdrive.js";
import type { Inbound, InboundPort, Issue, JsonObject, MasqueInbound, Outbound, ProxyOutbound } from "./types.js";

/** httpguts.ValidHeaderFieldName: an RFC 7230 token. */
const headerNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** httpguts.ValidHeaderFieldValue rejects control characters other than horizontal tab. */
const headerValueControlPattern = /[\u0000-\u0008\u000A-\u001F\u007F]/;
const pemKeyPattern = /^-----BEGIN [A-Z0-9 ]+-----[\s\S]+-----END [A-Z0-9 ]+-----$/;
const base64KeyPattern = /^[A-Za-z0-9+/]+={0,2}$/;
const quotedXdriveServices = XDRIVE_SERVICES.map((service) => `"${service}"`);
/** The XDrive services as message text: `"local", "Google Drive", or "template"`. */
const xdriveServiceChoices = `${quotedXdriveServices.slice(0, -1).join(", ")}, or ${quotedXdriveServices.at(-1)}`;

function isNonBlankString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

/**
 * Upper bound (Xray's `To`) of an Int32Range: an integer, or a string "n" or "a-b" where either side may be
 * negative and "" means 0. Undefined when Xray cannot parse the value.
 */
function int32RangeUpperBound(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isInteger(value) ? value : undefined;
  if (typeof value !== "string") return undefined;
  if (value === "") return 0;
  const match = /^([+-]?\d+)(?:-([+-]?\d+))?$/.exec(value);
  if (!match) return undefined;
  const left = Number(match[1]);
  return match[2] === undefined ? left : Math.max(left, Number(match[2]));
}

/** Mirrors decodeWarpKey: a PEM block or standard base64 DER, after trimming. */
function isWarpKeyEncoding(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const key = value.trim();
  if (pemKeyPattern.test(key)) return true;
  // Go's base64.StdEncoding skips \r and \n, so a wrapped key still decodes.
  const compact = key.replace(/[\r\n]/g, "");
  return base64KeyPattern.test(compact) && compact.length % 4 === 0;
}

/** Address family of a WARP address entry (a prefix or a zone-less address), or undefined when it is neither. */
function warpAddressFamily(entry: unknown): IpFamily | undefined {
  if (typeof entry !== "string") return undefined;
  const prefix = parseIpPrefix(entry);
  if (prefix) return prefix.address.family;
  const address = parseIpAddress(entry);
  return address && !address.zone ? address.family : undefined;
}

function masqueHeaderProblem(name: string, value: unknown, hasBasicAuth: boolean): string | undefined {
  if (!headerNamePattern.test(name) || typeof value !== "string" || headerValueControlPattern.test(value)) {
    return `MASQUE header "${name}" has an invalid name or value.`;
  }
  const lower = name.toLowerCase();
  if (lower === "host") return "MASQUE headers cannot contain Host; use host instead.";
  if (lower === "capsule-protocol") return "MASQUE headers cannot contain Capsule-Protocol; Xray sets it.";
  if (lower === "authorization" && hasBasicAuth) return "MASQUE headers cannot contain Authorization while user or pass is set.";
  return undefined;
}

function masqueWarpIssues(warp: JsonObject, path: string): Issue[] {
  const issues: Issue[] = [];

  for (const key of ["privateKey", "publicKey"] as const) {
    if (!isWarpKeyEncoding(warp[key])) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_WARP_KEY",
        severity: "error",
        category: "semantic",
        path: `${path}/${key}`,
        message: `WARP ${key} must be a PEM block or standard base64 DER.`
      }));
    }
  }

  const address = warp.address;
  if (!Array.isArray(address) || address.length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_WARP_ADDRESS",
      severity: "error",
      category: "semantic",
      path: `${path}/address`,
      message: "WARP address needs the tunnel addresses from the WARP registration."
    }));
    return issues;
  }

  const families = new Set<IpFamily>();
  address.forEach((entry, entryIndex) => {
    const family = warpAddressFamily(entry);
    const message = family === undefined
      ? `WARP address ${JSON.stringify(entry)} is not an IP address or prefix.`
      : families.has(family) ? "WARP address takes at most one IPv4 and one IPv6 address." : undefined;
    if (family !== undefined) families.add(family);
    if (message) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_WARP_ADDRESS",
        severity: "error",
        category: "semantic",
        path: `${path}/address/${entryIndex}`,
        message
      }));
    }
  });

  return issues;
}

/** Checks one masque transport settings object (an inbound `transport` or an outbound `masqueSettings` block) found at `path`. */
export function masqueSettingsIssues(settings: JsonObject, path: string, side: "server" | "client"): Issue[] {
  const issues: Issue[] = [];
  const hasBasicAuth = isNonEmptyString(settings.user) || isNonEmptyString(settings.pass);

  if (isNonEmptyString(settings.host) && /[\s/?#@]/.test(settings.host)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_HOST",
      severity: "error",
      category: "semantic",
      path: `${path}/host`,
      message: "MASQUE host must be a host name or host:port, without scheme, path or credentials."
    }));
  }

  if (isNonEmptyString(settings.path)) {
    const expanded = expandMasquePathTemplate(settings.path);
    if (!expanded.startsWith("/") || /[{}]/.test(expanded)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_PATH",
        severity: "error",
        category: "semantic",
        path: `${path}/path`,
        message: "MASQUE path must start with \"/\" and may only use the variables {target} and {ipproto}."
      }));
    }
  }

  if (typeof settings.user === "string" && settings.user.includes(":")) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_USER",
      severity: "error",
      category: "semantic",
      path: `${path}/user`,
      message: "MASQUE user cannot contain \":\" (it is sent as HTTP Basic auth)."
    }));
  }

  if (isJsonObject(settings.headers)) {
    for (const [name, value] of Object.entries(settings.headers)) {
      const message = masqueHeaderProblem(name, value, hasBasicAuth);
      if (message) {
        issues.push(makeIssue({
          code: "XCK_SEMANTIC_MASQUE_HEADER",
          severity: "error",
          category: "semantic",
          path: `${path}/headers/${escapePointerSegment(name)}`,
          message
        }));
      }
    }
  }

  if (isJsonObject(settings.warp)) {
    if (hasBasicAuth) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_WARP_AUTH_CONFLICT",
        severity: "error",
        category: "semantic",
        path: `${path}/warp`,
        message: "MASQUE user and pass cannot be used with warp."
      }));
    }
    issues.push(...masqueWarpIssues(settings.warp, `${path}/warp`));
  }

  if (isJsonObject(settings.xmux)) {
    const maxConnections = int32RangeUpperBound(settings.xmux.maxConnections) ?? 0;
    const maxConcurrency = int32RangeUpperBound(settings.xmux.maxConcurrency) ?? 0;
    if (maxConnections > 0 && maxConcurrency > 0) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_XMUX_CONFLICT",
        severity: "error",
        category: "semantic",
        path: `${path}/xmux`,
        message: "MASQUE xmux cannot set both maxConnections and maxConcurrency.",
        suggestion: "Keep one of maxConnections or maxConcurrency, or set the other to 0."
      }));
    }
  }

  if (side === "server") {
    for (const key of ["user", "pass", "warp", "xmux"] as const) {
      const value = settings[key];
      // An empty xmux is Xray's zero XmuxConfig (client defaults apply), so only a non-empty one is flagged.
      const isEmptyXmux = key === "xmux" && isJsonObject(value) && Object.keys(value).length === 0;
      if (value !== undefined && value !== null && value !== "" && !isEmptyXmux) {
        issues.push(makeIssue({
          code: "XCK_SEMANTIC_MASQUE_CLIENT_ONLY_FIELD",
          severity: "warning",
          category: "semantic",
          path: `${path}/${key}`,
          message: `MASQUE ${key} is only used by clients; the server ignores it.`
        }));
      }
    }
  }

  return issues;
}

function masqueAddressIssues(inbound: MasqueInbound, base: string): Issue[] {
  if (inbound.address.length === 0) {
    return [makeIssue({
      code: "XCK_SEMANTIC_MASQUE_ADDRESS_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${base}/address`,
      message: "MASQUE needs the server's address with a prefix, for example 10.14.0.1/16 or fd14::1/64.",
      suggestion: "Add one IPv4 and/or one IPv6 prefix; clients get addresses from these subnets."
    })];
  }

  const issues: Issue[] = [];
  const families = new Set<IpFamily>();
  inbound.address.forEach((entry, entryIndex) => {
    const path = `${base}/address/${entryIndex}`;
    const prefix = parseIpPrefix(entry);
    const problem = prefix ? masquePoolProblem(prefix) : "invalid";
    if (!prefix || problem === "invalid") {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_ADDRESS_INVALID",
        severity: "error",
        category: "semantic",
        path,
        message: `${entry} is not a valid MASQUE address prefix.`,
        suggestion: "Use the server's address with a prefix length, for example 10.14.0.1/16 or fd14::1/64 (no IPv4-mapped IPv6)."
      }));
      return;
    }

    const family = prefix.address.family;
    if (families.has(family)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_ADDRESS_FAMILY_DUPLICATE",
        severity: "error",
        category: "semantic",
        path,
        message: "MASQUE address takes at most one IPv4 and one IPv6 prefix."
      }));
      return;
    }
    families.add(family);

    if (problem === "not-host") {
      const firstHost = firstHostPrefix(prefix);
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_ADDRESS_NOT_HOST",
        severity: "error",
        category: "semantic",
        path,
        message: `${entry} is a network or broadcast address, not the server's host address.`,
        suggestion: firstHost
          ? `Use the server's own address inside the subnet, for example ${firstHost}.`
          : "Use the server's own address with room for clients, for example 10.14.0.1/16 or fd14::1/64."
      }));
    } else if (problem === "no-pool") {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_ADDRESS_POOL_EMPTY",
        severity: "error",
        category: "semantic",
        path,
        message: `${entry} leaves no addresses to assign to clients.`,
        suggestion: "Use a shorter prefix, for example /24 for IPv4 or /64 for IPv6."
      }));
    }
  });

  return issues;
}

/**
 * Checks a MASQUE `remoteDNS` value found at `path`. On inbounds the key is a PasarGuard convention
 * (client DNS for MASQUE users) that Xray ignores; on outbounds it is Xray's own []string, which
 * loads absent or null without error. Both sides get the same IP-list rules.
 */
function remoteDnsIssues(entries: unknown, path: string): Issue[] {
  if (entries === undefined || entries === null) return [];
  if (!Array.isArray(entries)) {
    return [makeIssue({
      code: "XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID",
      severity: "error",
      category: "semantic",
      path,
      message: "MASQUE remoteDNS must be a list of IP addresses."
    })];
  }
  const issues: Issue[] = [];
  entries.forEach((entry, entryIndex) => {
    if (typeof entry !== "string" || !parseIpAddress(entry)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID",
        severity: "error",
        category: "semantic",
        path: `${path}/${entryIndex}`,
        message: `MASQUE remoteDNS entry ${JSON.stringify(entry)} must be an IP address.`
      }));
    }
  });
  return issues;
}

export function masqueInboundIssues(inbound: MasqueInbound, inboundIndex: number): Issue[] {
  const base = `/inbounds/${inboundIndex + 1}`;
  const issues: Issue[] = [];

  if (inbound.security.type !== "tls") {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_TLS_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${base}/security`,
      message: "MASQUE requires TLS."
    }));
  }

  issues.push(...masqueAddressIssues(inbound, base));

  if (inbound.mtu !== undefined && inbound.mtu !== 0 && (inbound.mtu < MASQUE_LIMITS.minMtu || inbound.mtu > MASQUE_LIMITS.maxMtu)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_MTU",
      severity: "error",
      category: "semantic",
      path: `${base}/mtu`,
      message: `MASQUE mtu must be 0 (the default, ${MASQUE_LIMITS.minMtu}) or between ${MASQUE_LIMITS.minMtu} and ${MASQUE_LIMITS.maxMtu}.`
    }));
  }

  issues.push(...remoteDnsIssues(inbound.remoteDNS, `${base}/remoteDNS`));

  inbound.clients.forEach((client, clientIndex) => {
    if (client.enabled === false) return;
    if (!isNonBlankString(client.email) || client.email.includes(":")) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_CLIENT_EMAIL",
        severity: "error",
        category: "semantic",
        path: `${base}/clients/${clientIndex}/email`,
        message: "MASQUE clients need an email without \":\"; Xray uses it as the user name."
      }));
    }
  });

  issues.push(...masqueSettingsIssues(inbound.transport, `${base}/transport`, "server"));
  return issues;
}

/** The stream's transport name, lowercased. Xray reads `method` first and falls back to `network`. */
export function transportName(stream: JsonObject | undefined): string | undefined {
  const name = stream?.method ?? stream?.network;
  return typeof name === "string" ? name.toLowerCase() : undefined;
}

/** The stream key that names the transport: `method` when present, else `network`. */
function transportKey(stream: JsonObject | undefined): "method" | "network" {
  return stream?.method === undefined || stream.method === null ? "network" : "method";
}

export function masqueOutboundIssues(outbound: ProxyOutbound, outboundIndex: number): Issue[] {
  const base = `/outbounds/${outboundIndex + 1}`;
  const stream = outbound.streamSettings as JsonObject | undefined;
  const settings = outbound.settings ?? {};
  const issues: Issue[] = [];

  if (transportName(stream) !== "masque") {
    const key = transportKey(stream);
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_TRANSPORT_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${base}/streamSettings/${key}`,
      message: "MASQUE outbounds need the masque transport.",
      suggestion: `Set streamSettings.${key} to "masque".`
    }));
  }

  if (String(stream?.security ?? "").toLowerCase() !== "tls") {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_TLS_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${base}/streamSettings/security`,
      message: "MASQUE requires TLS."
    }));
  }

  if (outbound.mux?.enabled === true) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_MUX_UNSUPPORTED",
      severity: "error",
      category: "semantic",
      path: `${base}/mux/enabled`,
      message: "MASQUE outbounds do not support mux."
    }));
  }

  if (!isNonBlankString(settings.address)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_SERVER_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${base}/settings/address`,
      message: "MASQUE outbounds need the server address."
    }));
  }

  if (!portSchema.safeParse(settings.port).success) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_SERVER_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${base}/settings/port`,
      message: "MASQUE outbounds need a server port between 1 and 65535."
    }));
  }

  issues.push(...remoteDnsIssues(settings.remoteDNS, `${base}/settings/remoteDNS`));

  return issues;
}

/**
 * Checks one XDrive settings object (an inbound `transport` or an outbound `xdriveSettings` block) found at `path`.
 * `selected` is false for a stale block on a stream that runs another transport: Xray's XDriveConfig.Build checks
 * only the service, secrets and template, and remoteFolder is checked only when the transport runs.
 */
export function xdriveSettingsIssues(settings: JsonObject, path: string, selected: boolean): Issue[] {
  const issues: Issue[] = [];
  const service = typeof settings.service === "string" ? settings.service : "";

  if (!(XDRIVE_SERVICES as readonly string[]).includes(service)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_SERVICE",
      severity: "error",
      category: "semantic",
      path: `${path}/service`,
      message: `XDrive service must be ${xdriveServiceChoices}.`
    }));
  }

  if (selected && (service === "local" || service === "Google Drive") && !isNonBlankString(settings.remoteFolder)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${path}/remoteFolder`,
      message: `XDrive "${service}" needs remoteFolder (a directory for local, a folder ID for Google Drive).`
    }));
  }

  const secrets = settings.secrets;
  if (service === "Google Drive" && !(Array.isArray(secrets) && secrets.length === 3 && secrets.every(isNonBlankString))) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS",
      severity: "error",
      category: "semantic",
      path: `${path}/secrets`,
      message: "Google Drive needs 3 secrets in order: ClientID, ClientSecret, RefreshToken."
    }));
  }

  if (service === "template" && !isJsonObject(settings.template)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_TEMPLATE_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${path}/template`,
      message: "The template service needs a template object."
    }));
  }

  if (typeof settings.segmentBytes === "number" && settings.segmentBytes > XDRIVE_LIMITS.segmentBytes) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_SEGMENT_BYTES_CAPPED",
      severity: "warning",
      category: "semantic",
      path: `${path}/segmentBytes`,
      message: `Xray caps segmentBytes at ${XDRIVE_LIMITS.segmentBytes} (${XDRIVE_LIMITS.segmentBytes / (1024 * 1024)} MiB).`
    }));
  }

  if (typeof settings.concurrency === "number" && settings.concurrency > XDRIVE_LIMITS.concurrency) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_CONCURRENCY_CAPPED",
      severity: "warning",
      category: "semantic",
      path: `${path}/concurrency`,
      message: `Xray caps concurrency at ${XDRIVE_LIMITS.concurrency}.`
    }));
  }

  return issues;
}

function xdriveProtocolIssue(path: string): Issue {
  return makeIssue({
    code: "XCK_SEMANTIC_XDRIVE_PROTOCOL",
    severity: "error",
    category: "semantic",
    path,
    message: "The xdrive transport can only be used by VLESS.",
    suggestion: "Use VLESS with VLESS Encryption for XDrive, or pick another transport."
  });
}

function xdriveFlowIssue(path: string): Issue {
  return makeIssue({
    code: "XCK_SEMANTIC_XDRIVE_VLESS_FLOW",
    severity: "error",
    category: "semantic",
    path,
    message: "The xdrive transport does not support VLESS \"flow\".",
    suggestion: "Remove the flow."
  });
}

/**
 * Number of ports in an Xray port list, or undefined when it cannot be counted before Xray runs (an env: port)
 * or does not parse (XCK_SEMANTIC_INVALID_PORT reports that).
 */
function portListSize(port: InboundPort): number | undefined {
  if (typeof port === "number") return 1;
  let size = 0;
  for (const segment of port.split(",")) {
    const trimmed = segment.trim();
    if (trimmed === "") continue;
    const range = /^(\d+)(?:-(\d+))?$/.exec(trimmed);
    if (!range) return undefined;
    const from = Number(range[1]);
    const to = range[2] === undefined ? from : Number(range[2]);
    if (to < from) return undefined;
    size += to - from + 1;
  }
  return size;
}

/** Xray listens on a Unix socket (and drops the port list) when listen is an absolute path or starts with "@". */
function listensOnUnixSocket(listen: string | undefined): boolean {
  return listen !== undefined && (listen.startsWith("/") || listen.startsWith("@"));
}

/** Mirrors the inbound half of Xray's validateXDrive (infra/conf/xray.go): VLESS only, with decryption, no flow, one port. */
function xdriveInboundIssues(inbound: Inbound, base: string): Issue[] {
  if (inbound.protocol !== "vless") return [xdriveProtocolIssue(`${base}/transport/type`)];
  const issues: Issue[] = [];

  // The compiler writes "none" when decryption is left out; an empty value fails Xray's VLESS build.
  if (!isNonEmptyString(inbound.decryption) || inbound.decryption === "none") {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION",
      severity: "error",
      category: "semantic",
      path: `${base}/decryption`,
      message: "The xdrive transport needs VLESS \"decryption\"; run \"xray vlessenc\" to get one.",
      suggestion: "Set decryption to the server half of a VLESS Encryption pair and give clients the matching encryption."
    }));
  }

  // Only enabled clients are compiled; a client without its own flow takes the inbound flow.
  const enabledClients = inbound.clients.filter((client) => client.enabled !== false);
  inbound.clients.forEach((client, clientIndex) => {
    if (client.enabled !== false && isNonEmptyString(client.flow)) issues.push(xdriveFlowIssue(`${base}/clients/${clientIndex}/flow`));
  });
  if (isNonBlankString(inbound.flow) && enabledClients.some((client) => !isNonEmptyString(client.flow))) {
    issues.push(xdriveFlowIssue(`${base}/flow`));
  }

  const portCount = inbound.port === undefined || listensOnUnixSocket(inbound.listen) ? undefined : portListSize(inbound.port);
  if (portCount !== undefined && portCount !== 1) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_SINGLE_PORT",
      severity: "error",
      category: "semantic",
      path: `${base}/port`,
      message: "The xdrive transport can only listen on one port.",
      suggestion: "Use a single port: every port would open its own listener on the same folder."
    }));
  }

  return issues;
}

/**
 * The VLESS account Xray builds from outbound settings, with its issue path: the flat fields when settings.address
 * is set (vnext is then ignored), else the single vnext[0].users[0]. Undefined when Xray rejects the shape first.
 */
function vlessOutboundAccount(settings: JsonObject, base: string): { readonly account: JsonObject; readonly path: string; readonly flat: boolean } | undefined {
  if (settings.address !== undefined && settings.address !== null) return { account: settings, path: `${base}/settings`, flat: true };
  const server = Array.isArray(settings.vnext) && settings.vnext.length === 1 ? settings.vnext[0] : undefined;
  const users = isJsonObject(server) ? server.users : undefined;
  const user = Array.isArray(users) && users.length === 1 ? users[0] : undefined;
  return isJsonObject(user) ? { account: user, path: `${base}/settings/vnext/0/users/0`, flat: false } : undefined;
}

function xdriveMuxIssues(mux: unknown, path: string): Issue[] {
  const muxIssue = (field?: string) => makeIssue({
    code: "XCK_SEMANTIC_XDRIVE_MUX_REQUIRED",
    severity: "error",
    category: "semantic",
    path: field ? `${path}/${field}` : path,
    message: "The xdrive transport needs \"mux\" enabled, with no negative \"concurrency\" or \"xudpConcurrency\" and no \"xudpProxyUDP443\": \"skip\".",
    suggestion: "Set mux to { \"enabled\": true }; XDrive carries every connection over Mux.Cool."
  });
  if (!isJsonObject(mux)) return [muxIssue()];
  const issues: Issue[] = [];
  if (mux.enabled !== true) issues.push(muxIssue("enabled"));
  for (const field of ["concurrency", "xudpConcurrency"] as const) {
    const value = mux[field];
    if (typeof value === "number" && value < 0) issues.push(muxIssue(field));
  }
  if (mux.xudpProxyUDP443 === "skip") issues.push(muxIssue("xudpProxyUDP443"));
  return issues;
}

/** Mirrors the outbound half of Xray's validateXDrive: VLESS only, with encryption, no flow or testpre, and mux unless reverse. */
function xdriveOutboundIssues(outbound: Exclude<Outbound, { protocol: "unmanaged" }>, base: string, stream: JsonObject | undefined): Issue[] {
  if (outbound.protocol !== "vless") return [xdriveProtocolIssue(`${base}/streamSettings/${transportKey(stream)}`)];
  const settings = (outbound.settings ?? {}) as JsonObject;
  const found = vlessOutboundAccount(settings, base);
  const issues: Issue[] = [];

  if (found && isNonEmptyString(found.account.flow)) issues.push(xdriveFlowIssue(`${found.path}/flow`));

  // An empty or missing encryption fails Xray's VLESS build before this check, so it needs a value here too.
  if (found && (!isNonEmptyString(found.account.encryption) || found.account.encryption === "none")) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_VLESS_ENCRYPTION",
      severity: "error",
      category: "semantic",
      path: `${found.path}/encryption`,
      message: "The xdrive transport needs VLESS \"encryption\"; run \"xray vlessenc\" to get one.",
      suggestion: "Set encryption to the client half of the server's VLESS Encryption pair."
    }));
  }

  // VLESS reverse (read only from the flat shape) opens its own mux.
  const hasReverse = found?.flat === true && settings.reverse !== undefined && settings.reverse !== null;
  if (!hasReverse) issues.push(...xdriveMuxIssues(outbound.mux, `${base}/mux`));

  const testpre = found?.account.testpre;
  if (found && testpre !== undefined && testpre !== null && testpre !== 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_VLESS_TESTPRE",
      severity: "error",
      category: "semantic",
      path: `${found.path}/testpre`,
      message: "The xdrive transport does not support VLESS \"testpre\".",
      suggestion: "Remove testpre or set it to 0."
    }));
  }

  return issues;
}

export function inboundTransportIssues(inbound: Inbound, inboundIndex: number): Issue[] {
  const transport = inbound.protocol !== "unmanaged" && "transport" in inbound ? inbound.transport : undefined;
  const base = `/inbounds/${inboundIndex + 1}`;
  if (inbound.protocol !== "masque" && transport?.type === "masque") {
    return [makeIssue({
      code: "XCK_SEMANTIC_MASQUE_TRANSPORT_PROTOCOL",
      severity: "error",
      category: "semantic",
      path: `${base}/transport/type`,
      message: "The masque transport can only be used by the masque protocol."
    })];
  }
  if (transport?.type !== "xdrive") return [];
  return [...xdriveSettingsIssues(transport, `${base}/transport`, true), ...xdriveInboundIssues(inbound, base)];
}

export function outboundTransportIssues(outbound: Outbound, outboundIndex: number): Issue[] {
  if (outbound.protocol === "unmanaged") return [];
  const base = `/outbounds/${outboundIndex + 1}`;
  const stream = outbound.streamSettings as JsonObject | undefined;
  const issues: Issue[] = [];

  if (outbound.protocol === "masque") {
    issues.push(...masqueOutboundIssues(outbound, outboundIndex));
  } else if (transportName(stream) === "masque") {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MASQUE_TRANSPORT_PROTOCOL",
      severity: "error",
      category: "semantic",
      path: `${base}/streamSettings/${transportKey(stream)}`,
      message: "The masque transport can only be used by the masque protocol."
    }));
  }

  // Xray builds every *Settings block that is present, even when the stream selects another transport.
  const masqueSettings = stream?.masqueSettings;
  if (isJsonObject(masqueSettings)) {
    issues.push(...masqueSettingsIssues(masqueSettings, `${base}/streamSettings/masqueSettings`, "client"));
  }

  const xdriveSettings = stream?.xdriveSettings;
  const xdrivePath = `${base}/streamSettings/xdriveSettings`;
  const xdriveSelected = transportName(stream) === "xdrive";
  if (isJsonObject(xdriveSettings)) issues.push(...xdriveSettingsIssues(xdriveSettings, xdrivePath, xdriveSelected));
  else if (xdriveSelected) issues.push(...xdriveSettingsIssues({}, xdrivePath, true));
  if (xdriveSelected) issues.push(...xdriveOutboundIssues(outbound, base, stream));

  return issues;
}
