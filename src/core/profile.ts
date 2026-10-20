import { applyPresets } from "../presets/index.js";
import { coerceVerifyPeerCertByNameList, stringifyVerifyPeerCertByName } from "./tls-fields.js";
import type { CreateProfileInput, JsonObject, Inbound, Outbound, Profile, TlsSecurity } from "./types.js";

function asPortMapStrings(value: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    out[key] = typeof entry === "string" ? entry : entry === null || entry === undefined ? "" : String(entry);
  }
  return out;
}

/**
 * `portMap` is only part of the strict profile schema for `tunnel` / `dokodemo-door`.
 * Draft merges or hand-edited profiles can leak it onto other inbound kinds and block
 * `validateProfile` (empty strict compile).
 */
function stripPortMapFromNonTunnelDokodemoInbounds(inbound: Inbound): Inbound {
  if (inbound.protocol === "tunnel" || inbound.protocol === "dokodemo-door") return inbound;
  if (!("portMap" in inbound)) return inbound;
  const { portMap: _removed, ...rest } = inbound as unknown as Record<string, unknown>;
  return rest as unknown as Inbound;
}

/**
 * `remoteDNS` is only part of the strict profile schema for `masque`. A protocol switch
 * in a form draft can leak it onto other inbound kinds and block `validateProfile`.
 */
function stripRemoteDnsFromNonMasqueInbounds(inbound: Inbound): Inbound {
  if (inbound.protocol === "masque") return inbound;
  if (!("remoteDNS" in inbound)) return inbound;
  const { remoteDNS: _removed, ...rest } = inbound as unknown as Record<string, unknown>;
  return rest as unknown as Inbound;
}

/**
 * An empty MASQUE `remoteDNS` list means "not set". Invalid values are left for validation:
 * an unchanged import is returned from the raw source, so repairs here would make the
 * validated profile and the emitted config disagree.
 */
function dropEmptyMasqueRemoteDns(inbound: Inbound): Inbound {
  if (inbound.protocol !== "masque") return inbound;
  if (!Array.isArray(inbound.remoteDNS) || inbound.remoteDNS.length > 0) return inbound;
  const { remoteDNS: _removed, ...rest } = inbound;
  return rest;
}

/**
 * Canonical tunnel/dokodemo shape keeps `portMap` on the inbound (validated by `.strict()`).
 * `raw` `/settings/portMap` patches are redundant once compiled; lifting them survives API round‑trips
 * and avoids losing mappings when drafts only carried `raw`.
 */
export function normalizeDokodemoTunnelInboundPortMap(inbound: Inbound): Inbound {
  if (inbound.protocol !== "tunnel" && inbound.protocol !== "dokodemo-door") return inbound;

  const raw = inbound.raw;
  let portMap: Record<string, string> | undefined =
    inbound.portMap !== undefined && Object.keys(inbound.portMap).length > 0 ? { ...inbound.portMap } : undefined;

  const patches =
    Array.isArray(raw)
      ? raw.filter(
          (entry) =>
            typeof entry === "object" && entry !== null && !Array.isArray(entry) &&
            (entry as { path?: string }).path === "/settings/portMap"
        )
      : [];

  if (portMap === undefined && patches.length > 0) {
    const firstValue = patches[0]?.value;
    if (
      typeof firstValue === "object" &&
      firstValue !== null &&
      !Array.isArray(firstValue)
    ) {
      portMap = asPortMapStrings(firstValue as Record<string, unknown>);
    }
    if (portMap !== undefined && Object.keys(portMap).length === 0) portMap = undefined;
  }

  const filteredRaw =
    Array.isArray(raw) && raw.length > 0
      ? raw.filter(
          (entry) =>
            !(
              typeof entry === "object" &&
              entry !== null &&
              !Array.isArray(entry) &&
              (entry as { path?: string }).path === "/settings/portMap"
            )
        )
      : undefined;

  const nextRaw = filteredRaw !== undefined && filteredRaw.length > 0 ? filteredRaw : undefined;

  const base: Record<string, unknown> = { ...inbound, raw: nextRaw };
  if (portMap !== undefined && Object.keys(portMap).length > 0) base.portMap = portMap;
  else delete base.portMap;

  return base as unknown as Inbound;
}

const defaultOutbounds: Outbound[] = [
  { protocol: "freedom", tag: "direct", settings: { domainStrategy: "AsIs" } },
  { protocol: "blackhole", tag: "block", settings: { response: { type: "none" } } }
];

const defaultPolicy: JsonObject = {
  levels: {
    "0": {
      statsUserOnline: true
    }
  }
};

function applyDefaultPolicy(profile: Partial<Profile>, includeDefaultPolicy: boolean): Partial<Profile> {
  if (!includeDefaultPolicy) return profile;
  return {
    ...profile,
    raw: {
      ...profile.raw,
      topLevel: {
        policy: defaultPolicy,
        ...profile.raw?.topLevel
      }
    }
  };
}

export function createProfile(input: CreateProfileInput = {}): Profile {
  const { presets, includeDefaultPolicy = true, ...profileInput } = input;
  const withPresets = applyDefaultPolicy(applyPresets(profileInput, presets), includeDefaultPolicy);
  return normalizeProfile({
    ...withPresets,
    schemaVersion: "xck.v1",
    inbounds: withPresets.inbounds ?? []
  });
}

export function profileSourceFingerprint(profile: Profile): string {
  const raw = profile.raw
    ? {
        ...profile.raw,
        source: undefined,
        sourceProfileFingerprint: undefined
      }
    : undefined;
  const cleanedRaw = raw && Object.values(raw).some((value) => value !== undefined) ? raw : undefined;
  return JSON.stringify({
    ...profile,
    raw: cleanedRaw
  });
}

function normalizeInboundTlsVerifyPeerCertByName(inbound: Inbound): Inbound {
  if (!("security" in inbound) || !inbound.security || inbound.security.type !== "tls") return inbound
  const current = inbound.security.verifyPeerCertByName
  const next = coerceVerifyPeerCertByNameList(current)
  if (next === undefined) {
    if (current === undefined) return inbound
    const { verifyPeerCertByName: _removed, ...security } = inbound.security
    return { ...inbound, security: security as TlsSecurity }
  }
  if (Array.isArray(current) && current.length === next.length && current.every((item, index) => item === next[index])) {
    return inbound
  }
  return { ...inbound, security: { ...inbound.security, verifyPeerCertByName: next } }
}

function normalizeOutboundTlsVerifyPeerCertByName(outbound: Outbound): Outbound {
  if (outbound.protocol === "unmanaged") return outbound
  const streamSettings = outbound.streamSettings
  if (!streamSettings || typeof streamSettings !== "object") return outbound
  const tlsSettings = streamSettings.tlsSettings
  if (!tlsSettings || typeof tlsSettings !== "object" || Array.isArray(tlsSettings)) return outbound
  if (!("verifyPeerCertByName" in tlsSettings)) return outbound

  const next = stringifyVerifyPeerCertByName(tlsSettings.verifyPeerCertByName)
  const tls = { ...tlsSettings } as Record<string, unknown>
  if (next === undefined) delete tls.verifyPeerCertByName
  else if (tls.verifyPeerCertByName === next) return outbound
  else tls.verifyPeerCertByName = next

  return {
    ...outbound,
    streamSettings: {
      ...streamSettings,
      tlsSettings: tls
    }
  } as Outbound
}

export function normalizeProfile(profile: Profile): Profile {
  const outbounds = profile.outbounds && profile.outbounds.length > 0
    ? profile.outbounds
    : profile.raw?.source
      ? profile.outbounds
      : defaultOutbounds;
  const inbounds = profile.inbounds ?? [];
  return {
    ...profile,
    schemaVersion: "xck.v1",
    inbounds: inbounds.map((ib) =>
      normalizeInboundTlsVerifyPeerCertByName(
        dropEmptyMasqueRemoteDns(
          stripRemoteDnsFromNonMasqueInbounds(
            normalizeDokodemoTunnelInboundPortMap(stripPortMapFromNonTunnelDokodemoInbounds(ib))
          )
        )
      )
    ),
    outbounds: outbounds?.map(normalizeOutboundTlsVerifyPeerCertByName)
  };
}
