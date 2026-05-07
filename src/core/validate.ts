import { getXrayAdapter } from "../adapters/xray/registry.js";
import { profileSchema } from "../schemas/profile.js";
import { base64UrlByteLength } from "./base64.js";
import { hasErrors, makeIssue, pathForZod } from "./issues.js";
import { normalizeProfile } from "./profile.js";
import type { Client, Inbound, Issue, Profile, RawPatch, ValidateOptions, ValidationResult } from "./types.js";

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const shortIdRegex = /^[0-9a-fA-F]*$/;

function clientKey(client: Client): string {
  if (client.protocol === "vmess") return `vmess:${client.id.toLowerCase()}`;
  if (client.protocol === "vless") return `vless:${client.id.toLowerCase()}`;
  if (client.protocol === "trojan") return `trojan:${client.password}`;
  if (client.protocol === "shadowsocks") return `shadowsocks:${client.password}`;
  return `hysteria:${client.auth}`;
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
        path: `/inbounds/${index}/tag`,
        message: `Inbound tag "${inbound.tag}" is duplicated.`,
        suggestion: `Rename this tag or merge it with /inbounds/${previous}.`
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
        path: `/outbounds/${index}/tag`,
        message: `Outbound tag "${outbound.tag}" is duplicated.`,
        suggestion: `Rename this tag or merge it with /outbounds/${previous}.`
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
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/clients`,
      message: `${inbound.protocol.toUpperCase()} inbound requires at least one enabled client.`
    }));
  }

  if (inbound.protocol === "shadowsocks" && !inbound.password && clients.filter((client) => client.enabled !== false).length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_MISSING_SHADOWSOCKS_CREDENTIALS",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}`,
      message: "Shadowsocks inbound requires either a server password or at least one enabled client."
    }));
  }

  if (inbound.protocol === "shadowsocks" && inbound.method.startsWith("2022-") && clients.length > 0 && !inbound.password) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_SHADOWSOCKS_2022_MISSING_SERVER_PASSWORD",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/password`,
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
        path: `/inbounds/${inboundIndex}/clients/${clientIndex}`,
        message: "Client credential is duplicated within the same inbound.",
        suggestion: `Remove this client or rotate its credential. First occurrence is /inbounds/${inboundIndex}/clients/${previous}.`
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
          path: `/inbounds/${inboundIndex}/clients/${clientIndex}/email`,
          message: `Client email "${client.email}" is duplicated within the same inbound.`,
          suggestion: `Use unique emails if the control plane maps traffic or subscriptions by email. First occurrence is /inbounds/${inboundIndex}/clients/${previousEmail}.`
        }));
      }
      emails.set(client.email, clientIndex);
    }

    if ((client.protocol === "vmess" || client.protocol === "vless") && !uuidRegex.test(client.id)) {
      issues.push(makeIssue({
        code: client.protocol === "vmess" ? "XCK_SEMANTIC_INVALID_VMESS_UUID" : "XCK_SEMANTIC_INVALID_VLESS_UUID",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex}/clients/${clientIndex}/id`,
        message: `${client.protocol.toUpperCase()} client id must be a valid UUID.`
      }));
    }

    const secret = client.protocol === "hysteria" ? client.auth : client.protocol === "trojan" || client.protocol === "shadowsocks" ? client.password : undefined;
    if (secret !== undefined && secret.length < 12) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_WEAK_CLIENT_SECRET",
        severity: "warning",
        category: "security",
        path: `/inbounds/${inboundIndex}/clients/${clientIndex}/${client.protocol === "hysteria" ? "auth" : "password"}`,
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
      path: `/inbounds/${inboundIndex}/security/privateKey`,
      message: "REALITY privateKey must be a 32-byte base64url value."
    }));
  }

  if (security.publicKey && base64UrlByteLength(security.publicKey) !== 32) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_REALITY_PUBLIC_KEY",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/security/publicKey`,
      message: "REALITY publicKey must be a 32-byte base64url value when provided."
    }));
  }

  if (security.shortIds.length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_EMPTY_REALITY_SHORT_IDS",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/security/shortIds`,
      message: "REALITY requires at least one shortId."
    }));
  }

  security.shortIds.forEach((shortId, shortIdIndex) => {
    if (!shortIdRegex.test(shortId) || shortId.length > 16 || shortId.length % 2 !== 0) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_INVALID_REALITY_SHORT_ID",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex}/security/shortIds/${shortIdIndex}`,
        message: "REALITY shortId must be even-length hex and at most 16 characters."
      }));
    }
    if (shortId.length < 4) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_WEAK_REALITY_SHORT_ID",
        severity: "warning",
        category: "security",
        path: `/inbounds/${inboundIndex}/security/shortIds/${shortIdIndex}`,
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
      path: `/inbounds/${inboundIndex}/security/mldsa65Seed`,
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
        path: `/inbounds/${inboundIndex}/fallbacks/${fallbackIndex}/path`,
        message: "Fallback path must start with '/'."
      })
    ];
  });
}

function validateLocalInbound(inbound: Inbound, inboundIndex: number): Issue[] {
  if (inbound.protocol === "unmanaged") return [];
  const issues: Issue[] = [];

  if (inbound.protocol !== "tun" && (inbound.port < 1 || inbound.port > 65535 || !Number.isInteger(inbound.port))) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_PORT",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/port`,
      message: "Inbound port must be an integer between 1 and 65535."
    }));
  }

  if (inbound.listen && inbound.listen.trim() === "") {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_LISTEN",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/listen`,
      message: "Inbound listen address cannot be blank."
    }));
  }

  if (inbound.protocol === "http" && inbound.accounts?.some((account) => !account.user || !account.pass)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_HTTP_ACCOUNT",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/accounts`,
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
        path: `/inbounds/${inboundIndex}/accounts`,
        message: "Mixed/SOCKS password auth requires at least one account."
      }));
    }
  }

  if (inbound.protocol === "wireguard" && inbound.peers.length === 0) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_WIREGUARD_NO_PEERS",
      severity: "warning",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/peers`,
      message: "WireGuard inbound has no peers configured."
    }));
  }

  if (inbound.protocol === "wireguard" && Array.isArray(inbound.reserved) && inbound.reserved.length !== 3) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_WIREGUARD_RESERVED_LENGTH",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/reserved`,
      message: "WireGuard reserved must be exactly 3 bytes when provided as an array."
    }));
  }

  if (inbound.protocol === "hysteria") {
    if (inbound.version !== 2 || inbound.transport.version !== 2) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_HYSTERIA_VERSION",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex}/version`,
        message: "Xray-core Hysteria JSON support currently requires version 2."
      }));
    }
    const timeout = inbound.transport.udpIdleTimeout;
    if (timeout !== undefined && timeout !== 0 && (timeout < 2 || timeout > 600)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_HYSTERIA_UDP_IDLE_TIMEOUT",
        severity: "error",
        category: "semantic",
        path: `/inbounds/${inboundIndex}/transport/udpIdleTimeout`,
        message: "Hysteria udpIdleTimeout must be between 2 and 600 seconds when set."
      }));
    }
  }

  if ((inbound.protocol === "dokodemo-door" || inbound.protocol === "tunnel") && inbound.targetPort !== undefined && (inbound.targetPort < 1 || inbound.targetPort > 65535 || !Number.isInteger(inbound.targetPort))) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_INVALID_DOKODEMO_TARGET_PORT",
      severity: "error",
      category: "semantic",
      path: `/inbounds/${inboundIndex}/targetPort`,
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
        path: `/inbounds/${inboundIndex}/transport/headers`,
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
        path: `/inbounds/${inboundIndex}/transport/extra/headers`,
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
    ...validateRawPatches(profile.raw?.patches, "/raw/patches", options),
    ...profile.inbounds.flatMap((inbound, index) => [
      ...validateRawPatches(inbound.protocol === "unmanaged" ? undefined : inbound.raw, `/inbounds/${index}/raw`, options),
      ...validateRawPatches(inbound.protocol !== "unmanaged" && "streamAdvanced" in inbound ? inbound.streamAdvanced?.patches : undefined, `/inbounds/${index}/streamAdvanced/patches`, options),
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
