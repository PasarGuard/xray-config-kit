import { buildXrayConfig, importXrayConfig } from "../../src/index.js";
import type { BuildResult, Inbound, JsonObject, Outbound, Profile } from "../../src/index.js";
import { latestGeneratedRelease } from "./xray-releases.js";

function buildForLatestRelease(profile: Profile): BuildResult {
  return buildXrayConfig(profile, { xrayVersion: latestGeneratedRelease.version });
}

/** Imports `raw`, drops the kept source JSON, and builds from the profile model alone. */
export function rebuildWithoutSource(raw: JsonObject) {
  const imported = importXrayConfig(raw);
  const { raw: _source, ...profile } = imported.profile;
  return { imported, built: buildForLatestRelease(profile as Profile) };
}

/**
 * Imports `raw` (keeping its source JSON), applies `edit` to the first inbound, and builds with a
 * one-element inbound list, so every other inbound in `raw` is dropped from the output.
 */
export function editAndBuild(raw: JsonObject, edit: (inbound: Inbound) => Inbound): BuildResult {
  const imported = importXrayConfig(raw);
  return buildForLatestRelease({ ...imported.profile, inbounds: [edit(imported.profile.inbounds[0]!)] });
}

/**
 * Imports `raw` (keeping its source JSON), applies `edit` to the first outbound, and builds with a
 * one-element outbound list, so every other outbound in `raw` is dropped from the output.
 */
export function editOutboundAndBuild(raw: JsonObject, edit: (outbound: Outbound) => Outbound): BuildResult {
  const imported = importXrayConfig(raw);
  return buildForLatestRelease({ ...imported.profile, outbounds: [edit(imported.profile.outbounds![0]!)] });
}
