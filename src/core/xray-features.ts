/**
 * Xray behavior gated on generated parity data instead of version literals. Internal to the kit.
 *
 * Some Xray rules are code, not infra/conf struct fields, so parity data cannot show them. Those rules are gated
 * on a field or loader entry that arrived in the same Xray release.
 */
import { getXrayParityReleases, resolveXrayParityRelease, xrayParityManifest } from "../xray-json/parity.js";
import type { XrayParityRelease } from "../xray-json/parity.js";

export type XrayRuleFeatures = {
  /** XDriveConfig.xmux: XDrive reads xmux (with Xray's maxConnections and maxConcurrency conflict check). */
  readonly xdriveXmux: boolean;
  /**
   * XDrive over h3 (TLS alpn exactly ["h3"]) and its finalmask rules. Xray added it in the same release as
   * XDrive xmux, so XDriveConfig.xmux marks it.
   */
  readonly xdriveH3: boolean;
};

const withdrawnTags: ReadonlySet<string> = new Set((xrayParityManifest.source as { readonly withdrawnTags?: readonly string[] }).withdrawnTags ?? []);

export function hasStructField(release: XrayParityRelease, structName: string, field: string): boolean {
  return release.structs[structName]?.some((entry) => entry.json === field) === true;
}

export function xrayRuleFeatures(release: XrayParityRelease): XrayRuleFeatures {
  const xdriveXmux = hasStructField(release, "XDriveConfig", "xmux");
  return { xdriveXmux, xdriveH3: xdriveXmux };
}

/** The parity release used for `xrayVersion`: the newest generated one when no version is given or it is too new. */
export function parityReleaseFor(xrayVersion: string | undefined): XrayParityRelease {
  const resolved = resolveXrayParityRelease({ xrayVersion });
  return resolved.release ?? resolveXrayParityRelease().release!;
}

/**
 * The oldest generated release that matches `predicate` and can still be downloaded (not withdrawn upstream),
 * for messages that tell users which Xray release to install.
 */
export function firstAvailableRelease(predicate: (release: XrayParityRelease) => boolean): XrayParityRelease | undefined {
  return getXrayParityReleases().find((release) => !withdrawnTags.has(release.tag) && predicate(release));
}
