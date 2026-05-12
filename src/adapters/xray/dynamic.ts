import { makeIssue } from "../../core/issues.js";
import type { Inbound, Issue, Profile, Transport } from "../../core/types.js";
import { resolveXrayParityRelease } from "../../xray-json/parity.js";
import {
  generatedXrayCapabilitiesByTag,
  generatedXrayReleaseTags,
  latestGeneratedXrayReleaseTag
} from "./generated-capabilities.js";
import type { CompatibilityMatrix, FeatureSupport, XrayAdapter, XrayCapabilities } from "./types.js";

const capabilitiesByTag = generatedXrayCapabilitiesByTag as Readonly<Record<string, XrayCapabilities>>;

function issue(adapter: XrayAdapter, input: Omit<Issue, "adapterId">): Issue {
  return { ...input, adapterId: adapter.id };
}

function withAdapter(issueInput: Issue, adapterId: string): Issue {
  return { ...issueInput, adapterId };
}

function transportFeature(transport: Transport): string {
  if (transport.type === "ws") return "websocket";
  if (transport.type === "kcp") return "mkcp";
  return transport.type;
}

function featureDeprecationCode(feature: string): string {
  if (feature === "vmess") return "XCK_COMPAT_VMESS_DEPRECATED";
  if (feature === "trojan") return "XCK_COMPAT_TROJAN_DEPRECATED";
  if (feature === "shadowsocks") return "XCK_COMPAT_SHADOWSOCKS_DEPRECATED";
  return "XCK_COMPAT_FEATURE_DEPRECATED";
}

function validateFeature(adapter: XrayAdapter, feature: string, path: string, label: string): Issue[] {
  const support = adapter.capabilities.compatibilityMatrix[feature];
  if (!support?.supported) {
    return [issue(adapter, {
      code: "XCK_COMPAT_FEATURE_UNSUPPORTED",
      severity: "error",
      category: "compatibility",
      path,
      message: `${label} is not supported by ${adapter.id}.`,
      suggestion: support?.replacement
    })];
  }
  if (support.deprecated) {
    return [issue(adapter, {
      code: featureDeprecationCode(feature),
      severity: "warning",
      category: "compatibility",
      path,
      message: `${label} is deprecated or discouraged in ${adapter.id}.`,
      suggestion: support.replacement
    })];
  }
  return [];
}

function validateInbound(adapter: XrayAdapter, inbound: Inbound, index: number): Issue[] {
  if (inbound.protocol === "unmanaged") return [];
  const path = `/inbounds/${index + 1}`;
  const issues: Issue[] = [
    ...validateFeature(adapter, inbound.protocol, `${path}/protocol`, `Inbound protocol "${inbound.protocol}"`)
  ];

  if (inbound.protocol === "shadowsocks" && !inbound.transport) return issues;
  if (inbound.protocol === "http" || inbound.protocol === "mixed" || inbound.protocol === "socks" || inbound.protocol === "wireguard" || inbound.protocol === "dokodemo-door" || inbound.protocol === "tunnel" || inbound.protocol === "tun") {
    return issues;
  }

  if (!("transport" in inbound) || !inbound.transport) return issues;
  const transport = inbound.transport;
  const security = "security" in inbound ? inbound.security : undefined;
  issues.push(...validateFeature(adapter, transportFeature(transport), `${path}/transport/type`, `Transport "${transport.type}"`));

  if ((inbound.protocol === "vless" || inbound.protocol === "trojan") && security?.type === "reality") {
    if (!["tcp", "grpc", "xhttp"].includes(transport.type)) {
      issues.push(issue(adapter, {
        code: "XCK_COMPAT_REALITY_TRANSPORT",
        severity: "error",
        category: "compatibility",
        path: `${path}/security`,
        message: "REALITY is only supported on RAW/TCP, XHTTP, and gRPC in this Xray adapter.",
        suggestion: "Use transport.type \"tcp\", \"xhttp\", or \"grpc\"."
      }));
    }
  }

  if (inbound.protocol === "hysteria" && security?.type === "reality") {
    issues.push(issue(adapter, {
      code: "XCK_COMPAT_HYSTERIA_REALITY",
      severity: "error",
      category: "compatibility",
      path: `${path}/security`,
      message: "Hysteria transport uses TLS-oriented QUIC and does not support REALITY."
    }));
  }

  return issues;
}

export function createXrayAdapter(versionInput?: string): XrayAdapter {
  const resolved = resolveXrayParityRelease({ xrayVersion: versionInput });
  const capabilityTag = resolved.ok ? resolved.release.tag : latestGeneratedXrayReleaseTag;
  const capabilities = capabilitiesByTag[capabilityTag] ?? capabilitiesByTag[latestGeneratedXrayReleaseTag]!;
  const adapterIssues = resolved.issue ? [withAdapter(resolved.issue, capabilities.adapterId)] : [];
  const adapter: XrayAdapter = {
    id: capabilities.adapterId,
    versionRange: capabilities.xrayVersionRange,
    latestTestedVersion: capabilities.latestTestedVersion,
    capabilities,
    issues: adapterIssues,
    validateCompatibility(profile: Profile): Issue[] {
      return profile.inbounds.flatMap((inbound, index) => validateInbound(adapter, inbound, index));
    }
  };
  return adapter;
}

export function getGeneratedXrayAdapters(): readonly XrayAdapter[] {
  return generatedXrayReleaseTags.map((tag) => createXrayAdapter(capabilitiesByTag[tag]?.latestTestedVersion));
}

export const latestXrayAdapter = createXrayAdapter(capabilitiesByTag[latestGeneratedXrayReleaseTag]?.latestTestedVersion);
export const latestXrayCapabilities = latestXrayAdapter.capabilities;
export const latestCompatibilityMatrix: CompatibilityMatrix = latestXrayCapabilities.compatibilityMatrix;

export type { FeatureSupport };
