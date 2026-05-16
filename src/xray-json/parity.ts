import { makeIssue } from "../core/issues.js";
import { isJsonObject } from "../core/json.js";
import type { Issue, IssueCategory, IssueSeverity, JsonObject, JsonValue, ValidationMode, XrayConfig } from "../core/types.js";
import { xrayParityManifest } from "./parity-manifest.js";

export type XrayParityStructField = {
  readonly json: string;
  readonly go: string;
  readonly type: string;
};

export type XrayParityLoaderEntry = {
  readonly protocol: string;
  readonly config: string;
};

export type XrayParityFeatureNotice = {
  readonly feature: string;
  readonly replacement?: string;
  readonly source: string;
  readonly keys: readonly string[];
};

export type XrayParityRelease = {
  readonly tag: string;
  readonly version: string;
  readonly commit: string;
  readonly removedFeatures: readonly XrayParityFeatureNotice[];
  readonly deprecatedFeatures: readonly XrayParityFeatureNotice[];
  readonly topLevelKeys: readonly string[];
  readonly inboundProtocols: readonly XrayParityLoaderEntry[];
  readonly outboundProtocols: readonly XrayParityLoaderEntry[];
  readonly streamFields: readonly XrayParityStructField[];
  readonly transportAliases: Readonly<Record<string, string>>;
  readonly securityTypes: readonly string[];
  readonly fingerprints: readonly string[];
  readonly alpn: readonly string[];
  readonly jsonLoaders: Readonly<Record<string, readonly XrayParityLoaderEntry[]>>;
  readonly structs: Readonly<Record<string, readonly XrayParityStructField[]>>;
};

export type XrayParityReleaseResolution = {
  readonly ok: true;
  readonly release: XrayParityRelease;
  readonly issue?: Issue;
  readonly requestedVersion?: string;
  readonly latestGeneratedVersion: string;
} | {
  readonly ok: false;
  readonly release?: XrayParityRelease;
  readonly issue: Issue;
  readonly requestedVersion?: string;
  readonly latestGeneratedVersion: string;
};

export type StrictXrayValidationOptions = {
  readonly xrayVersion?: string;
  readonly releaseTag?: string;
  readonly mode?: ValidationMode;
};

export type StrictXrayValidationResult = {
  readonly ok: boolean;
  readonly config?: XrayConfig;
  readonly release: XrayParityRelease;
  readonly issues: Issue[];
};

const manifest = xrayParityManifest as unknown as {
  readonly source: {
    readonly selectedTags: readonly string[];
    readonly tags: readonly string[];
  };
  readonly releases: readonly XrayParityRelease[];
};

function parseVersion(version: string): readonly [number, number, number] {
  const match = version.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  return [
    Number(match?.[1] ?? 0),
    Number(match?.[2] ?? 0),
    Number(match?.[3] ?? 0)
  ];
}

function compareVersion(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  for (let index = 0; index < 3; index += 1) {
    const delta = (left[index] ?? 0) - (right[index] ?? 0);
    if (delta !== 0) return delta;
  }
  return 0;
}

function normalizeVersionInput(version: string): string {
  return version.replace(/^v/i, "");
}

function latestRelease(): XrayParityRelease {
  return [...manifest.releases].sort((a, b) => compareVersion(a.version, b.version)).at(-1)!;
}

function issue(
  code: string,
  path: string,
  message: string,
  suggestion?: string,
  severity: IssueSeverity = "error",
  category: IssueCategory = "schema"
): Issue {
  return makeIssue({
    code,
    severity,
    category,
    path,
    message,
    suggestion
  });
}

function futureVersionIssue(requestedVersion: string, latestGeneratedVersion: string): Issue {
  return issue(
    "XCK_XRAY_PARITY_VERSION_UNGENERATED",
    "/version",
    `Xray ${requestedVersion} is newer than generated parity data (${latestGeneratedVersion}).`,
    "Fetch Xray-core tags and run bun run generate:parity.",
    "error",
    "compatibility"
  );
}

function approximatedVersionIssue(requestedVersion: string, release: XrayParityRelease): Issue {
  return issue(
    "XCK_XRAY_PARITY_VERSION_APPROXIMATED",
    "/version",
    `Xray ${requestedVersion} is not generated exactly; using ${release.tag} parity data.`,
    "Add this exact Xray release to xray-parity.config.ts and run bun run generate:parity if exact behavior matters.",
    "warning",
    "compatibility"
  );
}

function pointer(path: string, key: string | number): string {
  const segment = String(key).replace(/~/g, "~0").replace(/\//g, "~1");
  return path === "/" ? `/${segment}` : `${path}/${segment}`;
}

function fieldNames(fields: readonly XrayParityStructField[] | undefined): Set<string> {
  return new Set((fields ?? []).map((field) => field.json));
}

function structFieldNames(release: XrayParityRelease, structName: string | undefined): Set<string> {
  const allowed = fieldNames(structName === undefined ? undefined : release.structs[structName]);
  if (structName === "WireGuardConfig") {
    allowed.add("DNS");
    allowed.add("kernelMode");
  }
  return allowed;
}

function normalizeGoType(type: string): string | undefined {
  let next = type.trim();
  next = next.replace(/^\*/, "");
  next = next.replace(/^\[\]\*/, "");
  next = next.replace(/^\[\]/, "");
  if (next.startsWith("map[")) return undefined;
  if (next.includes(".")) next = next.split(".").pop() ?? next;
  if (!/^[A-Z]\w+$/.test(next)) return undefined;
  return next;
}

function validateKnownFields(
  value: JsonObject,
  allowed: Set<string>,
  path: string,
  label: string,
  issues: Issue[],
  mode: ValidationMode
): void {
  for (const key of Object.keys(value)) {
    if (allowed.has(key)) continue;
    const nextIssue = issue(
      "XCK_XRAY_STRICT_UNKNOWN_FIELD",
      pointer(path, key),
      `${label} field "${key}" does not exist in the selected xray-core release.`
    );
    issues.push(mode === "permissive" ? { ...nextIssue, severity: "warning" } : nextIssue);
  }
}

function validateStructObject(
  value: JsonValue | undefined,
  release: XrayParityRelease,
  structName: string | undefined,
  path: string,
  label: string,
  issues: Issue[],
  mode: ValidationMode
): void {
  if (value === undefined || structName === undefined) return;
  const fields = release.structs[structName];
  if (!fields) return;
  if (!isJsonObject(value)) {
    issues.push(issue("XCK_XRAY_STRICT_EXPECTED_OBJECT", path, `${label} must be a JSON object.`));
    return;
  }
  validateKnownFields(value, structFieldNames(release, structName), path, label, issues, mode);
}

function protocolConfig(release: XrayParityRelease, direction: "inbound" | "outbound", protocol: string): string | undefined {
  const entries = direction === "inbound" ? release.inboundProtocols : release.outboundProtocols;
  return entries.find((entry) => entry.protocol === protocol)?.config;
}

function validateStreamSettings(
  value: JsonValue | undefined,
  release: XrayParityRelease,
  path: string,
  issues: Issue[],
  mode: ValidationMode
): void {
  if (value === undefined) return;
  if (!isJsonObject(value)) {
    issues.push(issue("XCK_XRAY_STRICT_EXPECTED_OBJECT", path, "streamSettings must be a JSON object."));
    return;
  }

  const streamFields = release.structs.StreamConfig ?? release.streamFields;
  validateKnownFields(value, fieldNames(streamFields), path, "streamSettings", issues, mode);

  const network = typeof value.network === "string" ? value.network.toLowerCase() : undefined;
  if (network && !release.transportAliases[network]) {
    issues.push(issue(
      "XCK_XRAY_STRICT_UNKNOWN_TRANSPORT",
      pointer(path, "network"),
      `Transport network "${network}" is not accepted by ${release.tag}.`
    ));
  }

  const security = typeof value.security === "string" ? value.security.toLowerCase() : undefined;
  if (security && security !== "" && security !== "none" && !release.securityTypes.includes(security)) {
    issues.push(issue(
      "XCK_XRAY_STRICT_UNKNOWN_SECURITY",
      pointer(path, "security"),
      `Security "${security}" is not accepted by ${release.tag}.`
    ));
  }
  if (security === "xtls") {
    issues.push(issue(
      "XCK_XRAY_STRICT_REMOVED_SECURITY",
      pointer(path, "security"),
      "Legacy XTLS is recognized by xray-core only to report a removed-feature error.",
      "Use xtls-rprx-vision with TLS or REALITY."
    ));
  }

  for (const field of streamFields) {
    const nested = normalizeGoType(field.type);
    if (nested) validateStructObject(value[field.json], release, nested, pointer(path, field.json), field.json, issues, mode);
  }
}

function validateDetour(
  value: JsonValue,
  release: XrayParityRelease,
  direction: "inbound" | "outbound",
  index: number,
  issues: Issue[],
  mode: ValidationMode
): void {
  const path = `/${direction === "inbound" ? "inbounds" : "outbounds"}/${index + 1}`;
  if (!isJsonObject(value)) {
    issues.push(issue("XCK_XRAY_STRICT_EXPECTED_OBJECT", path, `${direction} entry must be a JSON object.`));
    return;
  }

  const envelope = direction === "inbound" ? "InboundDetourConfig" : "OutboundDetourConfig";
  const envelopeFields = release.structs[envelope];
  validateKnownFields(value, fieldNames(envelopeFields), path, envelope, issues, mode);

  const protocol = typeof value.protocol === "string" ? value.protocol.toLowerCase() : undefined;
  if (!protocol) {
    issues.push(issue("XCK_XRAY_STRICT_MISSING_PROTOCOL", pointer(path, "protocol"), `${direction} protocol is required.`));
    return;
  }

  const configName = protocolConfig(release, direction, protocol);
  if (!configName) {
    issues.push(issue(
      direction === "inbound" ? "XCK_XRAY_STRICT_UNKNOWN_INBOUND_PROTOCOL" : "XCK_XRAY_STRICT_UNKNOWN_OUTBOUND_PROTOCOL",
      pointer(path, "protocol"),
      `${direction} protocol "${protocol}" is not accepted by ${release.tag}.`
    ));
    return;
  }

  validateStructObject(value.settings, release, configName, pointer(path, "settings"), `${protocol} settings`, issues, mode);
  validateStructObject(value.sniffing, release, "SniffingConfig", pointer(path, "sniffing"), "sniffing", issues, mode);
  validateStreamSettings(value.streamSettings, release, pointer(path, "streamSettings"), issues, mode);
  if (direction === "outbound") {
    validateStructObject(value.mux, release, "MuxConfig", pointer(path, "mux"), "mux", issues, mode);
    validateStructObject(value.proxySettings, release, "ProxyConfig", pointer(path, "proxySettings"), "proxySettings", issues, mode);
  }
}

export function getXrayParityReleases(): readonly XrayParityRelease[] {
  return manifest.releases;
}

export function resolveXrayParityRelease(options: { readonly xrayVersion?: string; readonly releaseTag?: string } = {}): XrayParityReleaseResolution {
  const sorted = [...manifest.releases].sort((a, b) => compareVersion(a.version, b.version));
  const latest = sorted.at(-1)!;
  const latestGeneratedVersion = latest.version;

  if (options.releaseTag) {
    const byTag = manifest.releases.find((release) => release.tag === options.releaseTag);
    if (byTag) return { ok: true, release: byTag, requestedVersion: byTag.version, latestGeneratedVersion };
    const requestedVersion = normalizeVersionInput(options.releaseTag);
    if (compareVersion(requestedVersion, latest.version) > 0) {
      return {
        ok: false,
        release: latest,
        issue: futureVersionIssue(requestedVersion, latestGeneratedVersion),
        requestedVersion,
        latestGeneratedVersion
      };
    }
    return {
      ok: false,
      release: latest,
      issue: issue(
        "XCK_XRAY_PARITY_RELEASE_UNKNOWN",
        "/version",
        `Xray release ${options.releaseTag} is not present in generated parity data.`,
        "Use xrayVersion for nearest-lower matching or add this exact release to xray-parity.config.ts.",
        "error",
        "compatibility"
      ),
      requestedVersion,
      latestGeneratedVersion
    };
  }

  if (options.xrayVersion) {
    const requestedVersion = normalizeVersionInput(options.xrayVersion);
    const exact = manifest.releases.find((release) => release.version === requestedVersion || release.tag === options.xrayVersion);
    if (exact) return { ok: true, release: exact, requestedVersion, latestGeneratedVersion };
    if (compareVersion(requestedVersion, latest.version) > 0) {
      return {
        ok: false,
        release: latest,
        issue: futureVersionIssue(requestedVersion, latestGeneratedVersion),
        requestedVersion,
        latestGeneratedVersion
      };
    }
    const release = [...sorted].reverse().find((item) => compareVersion(item.version, requestedVersion) <= 0) ?? sorted[0]!;
    return {
      ok: true,
      release,
      issue: approximatedVersionIssue(requestedVersion, release),
      requestedVersion,
      latestGeneratedVersion
    };
  }

  return { ok: true, release: latest, latestGeneratedVersion };
}

export function getXrayParityRelease(options: { readonly xrayVersion?: string; readonly releaseTag?: string } = {}): XrayParityRelease {
  const resolved = resolveXrayParityRelease(options);
  if (resolved.ok) return resolved.release;
  throw new RangeError(resolved.issue.message);
}

export function validateStrictXrayConfig(input: unknown, options: StrictXrayValidationOptions = {}): StrictXrayValidationResult {
  const resolved = resolveXrayParityRelease(options);
  const release = resolved.release ?? latestRelease();
  const mode = options.mode ?? "strict";
  const issues: Issue[] = resolved.issue ? [resolved.issue] : [];

  if (!resolved.ok) {
    return {
      ok: false,
      release,
      issues
    };
  }

  if (!isJsonObject(input)) {
    return {
      ok: false,
      release,
      issues: [issue("XCK_XRAY_STRICT_EXPECTED_OBJECT", "/", "Xray config must be a JSON object.")]
    };
  }

  const topLevelAllowed = new Set(release.topLevelKeys);
  validateKnownFields(input, topLevelAllowed, "/", "top-level config", issues, mode);

  const configFields = release.structs.Config ?? [];
  for (const field of configFields) {
    const nested = normalizeGoType(field.type);
    if (nested && field.json !== "inbounds" && field.json !== "outbounds") {
      validateStructObject(input[field.json], release, nested, pointer("/", field.json), field.json, issues, mode);
    }
  }

  if (input.inbounds !== undefined) {
    if (!Array.isArray(input.inbounds)) {
      issues.push(issue("XCK_XRAY_STRICT_EXPECTED_ARRAY", "/inbounds", "inbounds must be an array."));
    } else {
      input.inbounds.forEach((item, index) => validateDetour(item, release, "inbound", index, issues, mode));
    }
  }

  if (input.outbounds !== undefined) {
    if (!Array.isArray(input.outbounds)) {
      issues.push(issue("XCK_XRAY_STRICT_EXPECTED_ARRAY", "/outbounds", "outbounds must be an array."));
    } else {
      input.outbounds.forEach((item, index) => validateDetour(item, release, "outbound", index, issues, mode));
    }
  }

  const strictErrors = issues.filter((item) => item.severity === "error");
  return {
    ok: strictErrors.length === 0,
    config: strictErrors.length === 0 ? input as XrayConfig : undefined,
    release,
    issues
  };
}

export { xrayParityManifest };
