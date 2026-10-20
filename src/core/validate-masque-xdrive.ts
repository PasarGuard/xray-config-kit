import { portSchema } from "../schemas/shared.js";
import { firstHostPrefix, masquePoolProblem, parseIpAddress, parseIpPrefix } from "./ip.js";
import type { IpFamily } from "./ip.js";
import { makeIssue } from "./issues.js";
import { escapePointerSegment, isJsonObject } from "./json.js";
import { expandMasquePathTemplate, MASQUE_LIMITS, XDRIVE_LIMITS, XDRIVE_SERVICES } from "./masque-xdrive.js";
import type { Inbound, Issue, JsonObject, MasqueInbound, Outbound, ProxyOutbound } from "./types.js";

/** httpguts.ValidHeaderFieldName: an RFC 7230 token. */
const headerNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** httpguts.ValidHeaderFieldValue rejects control characters other than horizontal tab. */
const headerValueControlPattern = /[\u0000-\u0008\u000A-\u001F\u007F]/;
const pemKeyPattern = /^-----BEGIN [A-Z0-9 ]+-----[\s\S]+-----END [A-Z0-9 ]+-----$/;
const base64KeyPattern = /^[A-Za-z0-9+/]+={0,2}$/;

function isNonBlankString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
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

  if (side === "server") {
    for (const key of ["user", "pass", "warp"] as const) {
      const value = settings[key];
      if (value !== undefined && value !== null && value !== "") {
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

  (inbound.remoteDNS ?? []).forEach((entry, entryIndex) => {
    if (!parseIpAddress(entry)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID",
        severity: "error",
        category: "semantic",
        path: `${base}/remoteDNS/${entryIndex}`,
        message: `MASQUE remoteDNS entry "${entry}" must be an IP address.`
      }));
    }
  });

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

  const remoteDNS = settings.remoteDNS;
  if (Array.isArray(remoteDNS)) {
    remoteDNS.forEach((entry, entryIndex) => {
      if (typeof entry !== "string" || !parseIpAddress(entry)) {
        issues.push(makeIssue({
          code: "XCK_SEMANTIC_MASQUE_REMOTE_DNS_INVALID",
          severity: "error",
          category: "semantic",
          path: `${base}/settings/remoteDNS/${entryIndex}`,
          message: `MASQUE remoteDNS entry ${JSON.stringify(entry)} must be an IP address.`
        }));
      }
    });
  }

  return issues;
}

/** Checks one XDrive settings object (an inbound `transport` or an outbound `xdriveSettings` block) found at `path`. */
export function xdriveSettingsIssues(settings: JsonObject, path: string): Issue[] {
  const issues: Issue[] = [];
  const service = typeof settings.service === "string" ? settings.service : "";

  if (!(XDRIVE_SERVICES as readonly string[]).includes(service)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_SERVICE",
      severity: "error",
      category: "semantic",
      path: `${path}/service`,
      message: `XDrive service must be "local", "Google Drive", or "template".`
    }));
  }

  if ((service === "local" || service === "Google Drive") && !isNonBlankString(settings.remoteFolder)) {
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
      message: "Xray caps segmentBytes at 16777216 (16 MiB)."
    }));
  }

  if (typeof settings.concurrency === "number" && settings.concurrency > XDRIVE_LIMITS.concurrency) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_CONCURRENCY_CAPPED",
      severity: "warning",
      category: "semantic",
      path: `${path}/concurrency`,
      message: "Xray caps concurrency at 64."
    }));
  }

  return issues;
}

export function inboundTransportIssues(inbound: Inbound, inboundIndex: number): Issue[] {
  const transport = inbound.protocol !== "unmanaged" && "transport" in inbound ? inbound.transport : undefined;
  if (inbound.protocol !== "masque" && transport?.type === "masque") {
    return [makeIssue({
      code: "XCK_SEMANTIC_MASQUE_TRANSPORT_PROTOCOL",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/transport/type`,
      message: "The masque transport can only be used by the masque protocol."
    })];
  }
  if (transport?.type !== "xdrive") return [];
  return xdriveSettingsIssues(transport, `/inbounds/${inboundIndex + 1}/transport`);
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
  if (isJsonObject(xdriveSettings)) issues.push(...xdriveSettingsIssues(xdriveSettings, xdrivePath));
  else if (transportName(stream) === "xdrive") issues.push(...xdriveSettingsIssues({}, xdrivePath));

  return issues;
}
