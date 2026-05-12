import { validateProfile } from "../core/validate.js";
import { makeIssue } from "../core/issues.js";
import type { AnalyzeOptions, Inbound, Issue, JsonObject, Profile, RoutingRule } from "../core/types.js";

function isPublicListen(listen: string | undefined): boolean {
  return listen === undefined || listen === "" || listen === "0.0.0.0" || listen === "::" || listen === "[::]";
}

function isCatchAllRule(rule: RoutingRule): boolean {
  return !rule.inboundTag &&
    !rule.domain &&
    !rule.domains &&
    !rule.ip &&
    !rule.port &&
    !rule.sourceIP &&
    !rule.source &&
    !rule.sourcePort &&
    !rule.user &&
    !rule.vlessRoute &&
    !rule.protocol &&
    !rule.network &&
    !rule.attrs &&
    !rule.localIP &&
    !rule.localPort &&
    !rule.process &&
    !rule.webhook;
}

function rawString(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

function analyzeInboundSecurity(inbound: Inbound, index: number): Issue[] {
  if (inbound.protocol === "unmanaged") {
    const protocol = typeof inbound.raw.protocol === "string" ? inbound.raw.protocol : "";
    const settings = inbound.raw.settings;
    const publicListen = isPublicListen(typeof inbound.raw.listen === "string" ? inbound.raw.listen : undefined);
    const hasAccounts = rawString(settings).includes("accounts") || rawString(settings).includes("auth");
    if ((protocol === "http" || protocol === "socks") && publicListen && !hasAccounts) {
      return [
        makeIssue({
          code: "XCK_SECURITY_PUBLIC_UNAUTHENTICATED_PROXY",
          severity: "warning",
          category: "security",
          path: `/inbounds/${index + 1}`,
          message: `Imported ${protocol.toUpperCase()} inbound appears public and unauthenticated.`,
          suggestion: "Bind management proxies to localhost or require authentication."
        })
      ];
    }
    return [];
  }

  const issues: Issue[] = [];
  const security = "security" in inbound ? inbound.security : undefined;
  if ((inbound.protocol === "http" || inbound.protocol === "mixed" || inbound.protocol === "socks") && isPublicListen(inbound.listen)) {
    const hasAuth = inbound.protocol === "http"
      ? (inbound.accounts?.length ?? 0) > 0
      : (inbound.auth === "password" || (inbound.accounts?.length ?? 0) > 0) && (inbound.accounts?.length ?? 0) > 0;
    if (!hasAuth) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_PUBLIC_UNAUTHENTICATED_PROXY",
        severity: "warning",
        category: "security",
        path: `/inbounds/${index + 1}`,
        message: `${inbound.protocol.toUpperCase()} inbound is public and unauthenticated.`,
        suggestion: "Bind local proxy inbounds to 127.0.0.1 or require password authentication."
      }));
    }
  }

  if (security?.type === "tls" && security.allowInsecure) {
    issues.push(makeIssue({
      code: "XCK_SECURITY_ALLOW_INSECURE",
      severity: "warning",
      category: "security",
      path: `/inbounds/${index + 1}/security/allowInsecure`,
      message: "allowInsecure disables certificate verification and is scheduled for removal by Xray-core.",
      suggestion: "Use pinnedPeerCertSha256 and verifyPeerCertByName."
    }));
  }

  if (security?.type === "tls" && !security.serverName) {
    issues.push(makeIssue({
      code: "XCK_SUGGESTION_TLS_SERVER_NAME_MISSING",
      severity: "info",
      category: "suggestion",
      path: `/inbounds/${index + 1}/security/serverName`,
      message: "TLS serverName is empty; generated client links may need an explicit SNI value.",
      suggestion: "Set security.serverName when clients should connect through a domain name."
    }));
  }

  if (security?.type === "reality") {
    if (security.show) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_REALITY_SHOW_ENABLED",
        severity: "warning",
        category: "security",
        path: `/inbounds/${index + 1}/security/show`,
        message: "REALITY show mode should not be enabled in production configs."
      }));
    }
    if (!security.publicKey) {
      issues.push(makeIssue({
        code: "XCK_SUGGESTION_REALITY_PUBLIC_KEY_MISSING",
        severity: "info",
        category: "suggestion",
        path: `/inbounds/${index + 1}/security/publicKey`,
        message: "REALITY publicKey is not required for server config but is needed for client link generation."
      }));
    }
    if (security.serverNames.some((name) => /apple|icloud/i.test(name))) {
      issues.push(makeIssue({
        code: "XCK_SECURITY_RISKY_REALITY_TARGET_NAME",
        severity: "warning",
        category: "security",
        path: `/inbounds/${index + 1}/security/serverNames`,
        message: "REALITY serverNames include Apple/iCloud-looking names, which Xray-core warns may be operationally risky."
      }));
    }
  }

  return issues;
}

function analyzeRawExposure(profile: Profile): Issue[] {
  const issues: Issue[] = [];
  const topLevel = profile.raw?.topLevel;
  if (!topLevel) return issues;

  if (topLevel.api || topLevel.stats || topLevel.metrics) {
    issues.push(makeIssue({
      code: "XCK_SECURITY_RUNTIME_ENDPOINTS_RAW",
      severity: "warning",
      category: "security",
      path: "/raw/topLevel",
      message: "Raw API/stats/metrics sections are present and should be protected by routing and localhost-only inbounds.",
      suggestion: "Keep API/stats routing rules before catch-all rules and avoid public management listeners."
    }));
  }
  return issues;
}

function analyzeRouting(profile: Profile): Issue[] {
  const rules = profile.routing?.rules ?? [];
  const issues: Issue[] = [];
  const firstCatchAll = rules.findIndex(isCatchAllRule);
  const apiRuleIndex = rules.findIndex((rule) => rule.inboundTag?.includes("api"));
  if (firstCatchAll >= 0 && (apiRuleIndex === -1 || firstCatchAll < apiRuleIndex)) {
    issues.push(makeIssue({
        code: "XCK_SECURITY_ROUTING_CATCH_ALL_BEFORE_API",
        severity: "warning",
        category: "security",
        path: `/routing/rules/${firstCatchAll}`,
        message: "A catch-all routing rule appears before API/stats protection.",
        suggestion: "Place API/stats routing rules before broad domain or fallback rules."
      }));
  }

  const domainRules = rules.filter((rule) => (rule.domain?.length ?? 0) > 0);
  if (domainRules.length > 0) {
    const scopedTags = new Set(domainRules.flatMap((rule) => rule.inboundTag ?? []));
    for (const [index, inbound] of profile.inbounds.entries()) {
      if (inbound.protocol === "unmanaged" || inbound.protocol === "http" || inbound.protocol === "mixed" || inbound.protocol === "socks" || inbound.protocol === "wireguard" || inbound.protocol === "tun" || inbound.protocol === "dokodemo-door" || inbound.protocol === "tunnel") continue;
      if (scopedTags.size > 0 && !scopedTags.has(inbound.tag)) continue;
      const sniffing = inbound.sniffing;
      if (!sniffing?.enabled || !(sniffing.destOverride ?? []).some((value) => value === "http" || value === "tls")) {
        issues.push(makeIssue({
          code: "XCK_SUGGESTION_SNIFFING_DISABLED_FOR_DOMAIN_ROUTING",
          severity: "info",
          category: "suggestion",
          path: `/inbounds/${index + 1}/sniffing`,
          message: "Domain routing rules are present but this inbound does not sniff HTTP/TLS destinations.",
          suggestion: "Enable sniffing with destOverride [\"http\", \"tls\"] when domain routing should see client-requested names."
        }));
      }
    }
  }

  return issues;
}

function analyzeDns(profile: Profile): Issue[] {
  const servers = profile.dns?.servers ?? [];
  const publicPlainDns = servers.some((server) => {
    if (typeof server === "string") return /^\d+\.\d+\.\d+\.\d+$/.test(server);
    return /^\d+\.\d+\.\d+\.\d+$/.test(server.address);
  });
  if (!publicPlainDns) return [];
  return [
    makeIssue({
      code: "XCK_SECURITY_PLAIN_PUBLIC_DNS",
      severity: "info",
      category: "security",
      path: "/dns/servers",
      message: "Plain public DNS is easy to deploy but may leak resolver metadata.",
      suggestion: "Use regional resolvers or DoH/DoQ presets when that matches the deployment model."
    })
  ];
}

export function analyzeProfile(profile: Profile, options: AnalyzeOptions = {}): { ok: boolean; profile?: Profile; issues: Issue[]; adapterId: string } {
  const validation = validateProfile(profile, options);
  const audits = new Set(options.audits ?? ["security", "compatibility", "suggestions"]);
  const extraIssues: Issue[] = [];

  if (validation.profile && audits.has("security")) {
    extraIssues.push(
      ...validation.profile.inbounds.flatMap(analyzeInboundSecurity),
      ...analyzeRawExposure(validation.profile),
      ...analyzeRouting(validation.profile),
      ...analyzeDns(validation.profile)
    );
  }

  if (validation.profile && audits.has("suggestions") && validation.profile.inbounds.length === 0) {
    extraIssues.push(makeIssue({
      code: "XCK_SUGGESTION_EMPTY_PROFILE",
      severity: "info",
      category: "suggestion",
      path: "/inbounds",
      message: "Profile has no inbounds."
    }));
  }

  return {
    ok: validation.ok,
    profile: validation.profile,
    issues: [...validation.issues, ...extraIssues],
    adapterId: validation.adapterId
  };
}
