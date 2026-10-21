/**
 * Xray behavior gated on generated parity data instead of version literals. Internal to the kit.
 *
 * Some Xray rules are code, not infra/conf struct fields, so parity data cannot show them. Those rules are gated
 * on a field or loader entry that arrived in the same Xray release.
 */
import { finalmaskLoaderEntry, resolveXrayParityRelease } from "../xray-json/parity.js";
import type { XrayParityRelease } from "../xray-json/parity.js";

export { firstAvailableRelease } from "../xray-json/parity.js";

export type XrayRuleFeatures = {
  /** XDriveConfig.xmux: XDrive reads xmux (with Xray's maxConnections and maxConcurrency conflict check). */
  readonly xdriveXmux: boolean;
  /**
   * XDrive over h3 (TLS alpn exactly ["h3"]) and its finalmask rules. Xray added it in the same release as
   * XDrive xmux, so XDriveConfig.xmux marks it.
   */
  readonly xdriveH3: boolean;
  /** The finalmask "filter" mask (tcp and udp). */
  readonly finalmaskFilter: boolean;
};

export function hasStructField(release: XrayParityRelease, structName: string, field: string): boolean {
  return release.structs[structName]?.some((entry) => entry.json === field) === true;
}

export function hasFinalmaskType(release: XrayParityRelease, type: string): boolean {
  return finalmaskLoaderEntry(release, "tcp", type) !== undefined || finalmaskLoaderEntry(release, "udp", type) !== undefined;
}

export function xrayRuleFeatures(release: XrayParityRelease): XrayRuleFeatures {
  const xdriveXmux = hasStructField(release, "XDriveConfig", "xmux");
  return { xdriveXmux, xdriveH3: xdriveXmux, finalmaskFilter: hasFinalmaskType(release, "filter") };
}

/**
 * The parity release used for `xrayVersion`: the newest generated one when no version is given or it is too new.
 * Otherwise it is the release resolveXrayParityRelease picks, which the adapter and strict validation use too. That
 * includes the oldest generated release for a version it cannot parse (validateProfile then warns with
 * XCK_XRAY_PARITY_VERSION_APPROXIMATED), so one validation never mixes two releases.
 */
export function parityReleaseFor(xrayVersion: string | undefined): XrayParityRelease {
  const resolved = resolveXrayParityRelease({ xrayVersion });
  return resolved.release ?? resolveXrayParityRelease().release!;
}
