import { getXrayAdapter } from "../adapters/xray/registry.js";
import { profileSchema } from "../schemas/profile.js";
import { base64UrlByteLength } from "./base64.js";
import { hasErrors, makeIssue, pathForZod } from "./issues.js";
import { normalizeProfile } from "./profile.js";
import type { Client, Inbound, InboundPort, Issue, Profile, RawPatch, RoutingRule, ValidateOptions, ValidationResult, XrayPortList } from "./types.js";

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const shortIdRegex = /^[0-9a-fA-F]*$/;
const envPortRegex = /^env:[A-Za-z_][A-Za-z0-9_]*$/;

function clientKey(client: Client): string {
  if (client.protocol === "vmess") return `vmess:${client.id.toLowerCase()}`;
  if (client.protocol === "vless") return `vless:${client.id.toLowerCase()}`;
  if (client.protocol === "trojan") return `trojan:${client.password}`;
  if (client.protocol === "shadowsocks") return `shadowsocks:${client.password}`;
  return `hysteria:${client.auth}`;
}

function shadowsocksUsesServerPassword(method: string | undefined): boolean {
  return method === "2022-blake3-aes-128-gcm" || method === "2022-blake3-aes-256-gcm";
}

function validateRawPatches(patches: readonly RawPatch[] | undefined, path: string, options: ValidateOptions): Issue[] {
  if (!patches) return [];
  return patches.flatMap((patch, index) => {
    if (!patch.unsafe || options.allowUnsafeRaw) return [];
    return [
      makeIssue({
        code: "XCK_RAW_UNSAFE_PATCH",
        severity: "error",
        category: "raw",
        path: `${path}/${index}`,
        message: "Unsafe raw patches are blocked unless allowUnsafeRaw is enabled.",
        suggestion: "Move this setting into the typed profile model or explicitly allow unsafe raw patches on the backend."
      })
    ];
  });
}

function validateInboundTags(profile: Profile): Issue[] {
  const seen = new Map<string, number>();
  const issues: Issue[] = [];

  profile.inbounds.forEach((inbound, index) => {
    if (!inbound.tag) return;
    const previous = seen.get(inbound.tag);
    if (previous !== undefined) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_DUPLICATE_INBOUND_TAG",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${index + 1}/tag`,
        message: `Inbound tag "${inbound.tag}" is duplicated.`,
        suggestion: `Rename this tag or merge it with /inbounds/${previous + 1}.`
      }));
    }
    seen.set(inbound.tag, index);
  });

  return issues;
}

function validateOutboundTags(profile: Profile): Issue[] {
  const seen = new Map<string, number>();
  const issues: Issue[] = [];

  profile.outbounds?.forEach((outbound, index) => {
    if (!outbound.tag) return;
    const previous = seen.get(outbound.tag);
    if (previous !== undefined) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_DUPLICATE_OUTBOUND_TAG",
        severity: "error",
        category: "semantic",
        path: `/outbounds/${index + 1}/tag`,
        message: `Outbound tag "${outbound.tag}" is duplicated.`,
        suggestion: `Rename this tag or merge it with /outbounds/${previous + 1}.`
      }));
    }
    seen.set(outbound.tag, index);
  });

  return issues;
}

function validateClients(inbound: Inbound, inboundIndex: number): Issue[] {
  if (inbound.protocol === "unmanaged") return [];
  const issues: Issue[] = [];
  const seen = new Map<string, number>();
  const emails = new Map<string, number>();
  if (!("clients" in inbound)) return [];
  const clients = inbound.clients;

  if ((inbound.protocol === "vmess" || inbound.protocol === "vless" || inbound.protocol === "trojan" || inbound.protocol === "hysteria") && clients.filter((client) => client.enabled !== false).length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MISSING_CLIENTS",
      severity: "warning",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/clients`,
      message: `${inbound.protocol.toUpperCase()} inbound has no enabled clients.`
    }));
  }

  if (inbound.protocol === "shadowsocks" && !inbound.password && clients.length > 0 && clients.filter((client) => client.enabled !== false).length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MISSING_SHADOWSOCKS_CREDENTIALS",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}`,
      message: "Shadowsocks inbound requires either a server password or at least one enabled client."
    }));
  }

  if (inbound.protocol === "shadowsocks" && !inbound.method && inbound.clients.some((client) => client.enabled !== false && !client.method)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_SHADOWSOCKS_MISSING_METHOD",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/method`,
      message: "Shadowsocks inbound requires a server method or per-client methods when clients are configured."
    }));
  }

  if (inbound.protocol === "shadowsocks" && shadowsocksUsesServerPassword(inbound.method) && clients.length > 0 && !inbound.password) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_SHADOWSOCKS_2022_MISSING_SERVER_PASSWORD",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/password`,
      message: "Multi-user Shadowsocks 2022 requires a server password so client passwords can be composed correctly."
    }));
  }

  clients.forEach((client, clientIndex) => {
    const key = clientKey(client);
    const previous = seen.get(key);
    if (previous !== undefined) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_DUPLICATE_CLIENT",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/clients/${clientIndex}`,
        message: "Client credential is duplicated within the same inbound.",
        suggestion: `Remove this client or rotate its credential. First occurrence is /inbounds/${inboundIndex + 1}/clients/${previous}.`
      }));
    }
    seen.set(key, clientIndex);

    if (client.email) {
      const previousEmail = emails.get(client.email);
      if (previousEmail !== undefined) {
        issues.push(makeIssue({
          code: "XCK_SEMANTIC_DUPLICATE_CLIENT_EMAIL",
          severity: "warning",
          category: "semantic",
          path: `/inbounds/${inboundIndex + 1}/clients/${clientIndex}/email`,
          message: `Client email "${client.email}" is duplicated within the same inbound.`,
          suggestion: `Use unique emails if the control plane maps traffic or subscriptions by email. First occurrence is /inbounds/${inboundIndex + 1}/clients/${previousEmail}.`
        }));
      }
      emails.set(client.email, clientIndex);
    }

    if ((client.protocol === "vmess" || client.protocol === "vless") && !uuidRegex.test(client.id)) {
      issues.push(makeIssue({
        code: client.protocol === "vmess" ? "XCK_SEMANTIC_INVALID_VMESS_UUID" : "XCK_SEMANTIC_INVALID_VLESS_UUID",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/clients/${clientIndex}/id`,
        message: `${client.protocol.toUpperCase()} client id must be a valid UUID.`
      }));
    }

    const secret = client.protocol === "hysteria" ? client.auth : client.protocol === "trojan" || client.protocol === "shadowsocks" ? client.password : undefined;
    if (secret !== undefined && secret.length < 12) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_WEAK_CLIENT_SECRET",
        severity: "warning",
        category: "security",
        path: `/inbounds/${inboundIndex + 1}/clients/${clientIndex}/${client.protocol === "hysteria" ? "auth" : "password"}`,
        message: "Client password is short enough to be risky.",
        suggestion: "Use at least 16 random bytes encoded as base64url or hex."
      }));
    }
  });

  return issues;
}

function validateReality(inbound: Inbound, inboundIndex: number): Issue[] {
  const security = inbound.protocol !== "unmanaged" && "security" in inbound ? inbound.security : undefined;
  if (security?.type !== "reality") return [];
  const issues: Issue[] = [];
  const privateKeyLength = base64UrlByteLength(security.privateKey);

  if (privateKeyLength !== 32) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_REALITY_PRIVATE_KEY",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/security/privateKey`,
      message: "REALITY privateKey must be a 32-byte base64url value."
    }));
  }

  if (security.publicKey && base64UrlByteLength(security.publicKey) !== 32) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_REALITY_PUBLIC_KEY",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/security/publicKey`,
      message: "REALITY publicKey must be a 32-byte base64url value when provided."
    }));
  }

  if (security.shortIds.length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_EMPTY_REALITY_SHORT_IDS",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/security/shortIds`,
      message: "REALITY requires at least one shortId."
    }));
  }

  security.shortIds.forEach((shortId, shortIdIndex) => {
    if (!shortIdRegex.test(shortId) || shortId.length > 16 || shortId.length % 2 !== 0) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_INVALID_REALITY_SHORT_ID",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/security/shortIds/${shortIdIndex}`,
        message: "REALITY shortId must be even-length hex and at most 16 characters."
      }));
    }
    if (shortId.length < 4) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_WEAK_REALITY_SHORT_ID",
        severity: "warning",
        category: "security",
        path: `/inbounds/${inboundIndex + 1}/security/shortIds/${shortIdIndex}`,
        message: "Very short REALITY shortIds reduce client separation entropy.",
        suggestion: "Use 8 to 16 hex characters for each shortId."
      }));
    }
  });

  if (security.mldsa65Seed && security.mldsa65Seed === security.privateKey) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_REALITY_SEED_REUSES_PRIVATE_KEY",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/security/mldsa65Seed`,
      message: "mldsa65Seed must not reuse the REALITY privateKey."
    }));
  }

  return issues;
}

function validateFallbacks(inbound: Inbound, inboundIndex: number): Issue[] {
  if (inbound.protocol === "unmanaged" || !("fallbacks" in inbound)) return [];
  return (inbound.fallbacks ?? []).flatMap((fallback, fallbackIndex) => {
    if (!fallback.path || fallback.path.startsWith("/")) return [];
    return [
      makeIssue({
        code: "XCK_SEMANTIC_INVALID_FALLBACK_PATH",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/fallbacks/${fallbackIndex}/path`,
        message: "Fallback path must start with '/'."
      })
    ];
  });
}

function isValidPortNumber(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function isValidPortSegment(segment: string): boolean {
  const trimmed = segment.trim();
  if (trimmed === "") return false;
  if (envPortRegex.test(trimmed)) return true;
  if (/^\d+$/.test(trimmed)) return isValidPortNumber(Number(trimmed));

  const range = trimmed.match(/^(\d+)-(\d+)$/);
  if (!range) return false;
  const from = Number(range[1]);
  const to = Number(range[2]);
  return isValidPortNumber(from) && isValidPortNumber(to) && from <= to;
}

function validatePortList(port: XrayPortList, path: string, label: string): Issue[] {
  if (typeof port === "number" && isValidPortNumber(port)) return [];
  if (typeof port === "string" && port.split(",").every(isValidPortSegment)) return [];
  return [
    makeIssue({
      code: "XCK_SEMANTIC_INVALID_PORT",
      severity: "error",
      category: "semantic",
      path,
      message: `${label} must be an integer port or Xray port list string such as "443,8443" or "10000-10010".`
    })
  ];
}

function validateInboundPort(port: InboundPort, inboundIndex: number): Issue[] {
  return validatePortList(port, `/inbounds/${inboundIndex + 1}/port`, "Inbound port");
}

function validateRoutingRule(rule: RoutingRule, ruleIndex: number): Issue[] {
  const issues: Issue[] = [];
  if (!rule.outboundTag && !rule.balancerTag) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_ROUTING_TARGET_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `/routing/rules/${ruleIndex}`,
      message: "Routing rule requires outboundTag or balancerTag."
    }));
  }

  if (rule.outboundTag && rule.balancerTag) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_ROUTING_TARGET_AMBIGUOUS",
      severity: "warning",
      category: "semantic",
      path: `/routing/rules/${ruleIndex}`,
      message: "Routing rule has both outboundTag and balancerTag; Xray uses outboundTag first.",
      suggestion: "Keep only one target in the rule draft."
    }));
  }

  const ports: readonly [keyof RoutingRule, XrayPortList | undefined, string][] = [
    ["port", rule.port, "Routing rule port"],
    ["sourcePort", rule.sourcePort, "Routing rule sourcePort"],
    ["vlessRoute", rule.vlessRoute, "Routing rule vlessRoute"],
    ["localPort", rule.localPort, "Routing rule localPort"]
  ];
  for (const [field, value, label] of ports) {
    if (value !== undefined) {
      issues.push(...validatePortList(value, `/routing/rules/${ruleIndex}/${field}`, label));
    }
  }

  return issues;
}

function validateRoutingBalancers(profile: Profile): Issue[] {
  const balancers = profile.routing?.balancers ?? [];
  const seen = new Map<string, number>();
  const issues: Issue[] = [];

  balancers.forEach((balancer, index) => {
    const previous = seen.get(balancer.tag);
    if (previous !== undefined) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_DUPLICATE_BALANCER_TAG",
        severity: "error",
        category: "semantic",
        path: `/routing/balancers/${index}/tag`,
        message: `Routing balancer tag "${balancer.tag}" is duplicated.`,
        suggestion: `Rename this balancer or merge it with /routing/balancers/${previous}.`
      }));
    }
    seen.set(balancer.tag, index);

    if (balancer.selector.length === 0) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_EMPTY_BALANCER_SELECTOR",
        severity: "error",
        category: "semantic",
        path: `/routing/balancers/${index}/selector`,
        message: "Routing balancer requires at least one outbound selector."
      }));
    }
  });

  return issues;
}

function validateLocalInbound(inbound: Inbound, inboundIndex: number): Issue[] {
  if (inbound.protocol === "unmanaged") return [];
  const issues: Issue[] = [];

  if (inbound.protocol !== "tun") {
    const portValue = "port" in inbound ? inbound.port : undefined;
    if (portValue !== undefined) {
      issues.push(...validateInboundPort(portValue, inboundIndex));
    }
  }

  if (inbound.listen && inbound.listen.trim() === "") {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_LISTEN",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/listen`,
      message: "Inbound listen address cannot be blank."
    }));
  }

  if (inbound.protocol === "http" && inbound.accounts?.some((account) => !account.user || !account.pass)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_HTTP_ACCOUNT",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/accounts`,
      message: "HTTP inbound accounts require both user and pass."
    }));
  }

  if (inbound.protocol === "mixed" || inbound.protocol === "socks") {
    const auth = inbound.auth ?? (inbound.accounts && inbound.accounts.length > 0 ? "password" : "noauth");
    if (auth === "password" && (!inbound.accounts || inbound.accounts.length === 0)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_MIXED_AUTH_WITHOUT_ACCOUNTS",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/accounts`,
        message: "Mixed/SOCKS password auth requires at least one account."
      }));
    }
  }

  if (inbound.protocol === "wireguard" && inbound.peers.length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_WIREGUARD_NO_PEERS",
      severity: "warning",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/peers`,
      message: "WireGuard inbound has no peers configured."
    }));
  }

  if (inbound.protocol === "wireguard" && Array.isArray(inbound.reserved) && inbound.reserved.length !== 3) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_WIREGUARD_RESERVED_LENGTH",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/reserved`,
      message: "WireGuard reserved must be exactly 3 bytes when provided as an array."
    }));
  }

  if (inbound.protocol === "hysteria") {
    if (inbound.version !== 2 || inbound.transport.version !== 2) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_HYSTERIA_VERSION",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/version`,
        message: "Xray-core Hysteria JSON support currently requires version 2."
      }));
    }
    const timeout = inbound.transport.udpIdleTimeout;
    if (timeout !== undefined && timeout !== 0 && (timeout < 2 || timeout > 600)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_HYSTERIA_UDP_IDLE_TIMEOUT",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/transport/udpIdleTimeout`,
        message: "Hysteria udpIdleTimeout must be between 2 and 600 seconds when set."
      }));
    }
  }

  if ((inbound.protocol === "dokodemo-door" || inbound.protocol === "tunnel") && inbound.targetPort !== undefined && (inbound.targetPort < 1 || inbound.targetPort > 65535 || !Number.isInteger(inbound.targetPort))) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_DOKODEMO_TARGET_PORT",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex + 1}/targetPort`,
      message: "Dokodemo targetPort must be an integer between 1 and 65535."
    }));
  }

  if ("transport" in inbound && inbound.transport?.type === "httpupgrade") {
    const hasHostHeader = Object.keys(inbound.transport.headers ?? {}).some((key) => key.toLowerCase() === "host");
    if (hasHostHeader) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_HTTPUPGRADE_HOST_HEADER",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/transport/headers`,
        message: "HTTPUpgrade headers cannot contain Host; use transport.host instead."
      }));
    }
  }

  if ("transport" in inbound && inbound.transport?.type === "xhttp") {
    const hasHostHeader = Object.keys(inbound.transport.extra?.headers ?? {}).some((key) => key.toLowerCase() === "host");
    if (hasHostHeader) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_XHTTP_HOST_HEADER",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex + 1}/transport/extra/headers`,
        message: "XHTTP headers cannot contain Host; use transport.host instead."
      }));
    }
  }

  return issues;
}

function semanticIssues(profile: Profile, options: ValidateOptions): Issue[] {
  return [
    ...validateInboundTags(profile),
    ...validateOutboundTags(profile),
    ...validateRoutingBalancers(profile),
    ...validateRawPatches(profile.raw?.patches, "/raw/patches", options),
    ...(profile.routing?.rules ?? []).flatMap(validateRoutingRule),
    ...profile.inbounds.flatMap((inbound, index) => [
      ...validateRawPatches(inbound.protocol === "unmanaged" ? undefined : inbound.raw, `/inbounds/${index + 1}/raw`, options),
      ...validateRawPatches(inbound.protocol !== "unmanaged" && "streamAdvanced" in inbound ? inbound.streamAdvanced?.patches : undefined, `/inbounds/${index + 1}/streamAdvanced/patches`, options),
      ...validateLocalInbound(inbound, index),
      ...validateClients(inbound, index),
      ...validateReality(inbound, index),
      ...validateFallbacks(inbound, index)
    ])
  ];
}

export function validateProfile(input: unknown, options: ValidateOptions = {}): ValidationResult {
  const adapter = getXrayAdapter(options.xrayVersion);
  const parsed = profileSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map((zodIssue) => makeIssue({
        code: "XCK_SCHEMA_INVALID_PROFILE",
        severity: "error",
        category: "schema",
        path: pathForZod(zodIssue.path.filter((part): part is string | number => typeof part === "string" || typeof part === "number")),
        message: zodIssue.message,
        adapterId: adapter.id
      })),
      adapterId: adapter.id
    };
  }

  const profile = normalizeProfile(parsed.data as Profile);
  const issues = [
    ...(adapter.issues ?? []),
    ...semanticIssues(profile, options),
    ...adapter.validateCompatibility(profile)
  ];
  const strict = options.mode !== "permissive";
  const adapterHasErrors = (adapter.issues ?? []).some((issue) => issue.severity === "error");
  const ok = adapterHasErrors ? false : strict ? !hasErrors(issues) : true;

  return {
    ok,
    profile,
    issues,
    adapterId: adapter.id
  };
}
