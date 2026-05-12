import { buildXrayConfig } from "./compiler.js";
import { isJsonObject } from "./json.js";
import type { BuildOptions, ExplainEntry, Profile, XrayConfig } from "./types.js";

function looksLikeProfile(input: unknown): input is Profile {
  return isJsonObject(input) && input.schemaVersion === "xck.v1";
}

export function explainConfig(input: Profile | XrayConfig, options: BuildOptions = {}): ExplainEntry[] {
  if (!looksLikeProfile(input)) {
    return [
      {
        path: "/",
        title: "Raw Xray config",
        source: "import",
        detail: "Input is already Xray JSON; no profile compiler decisions are available."
      }
    ];
  }

  const built = buildXrayConfig(input, { ...options, mode: options.mode ?? "permissive" });
  const entries: ExplainEntry[] = [
    {
      path: "/",
      title: "Profile compiled",
      source: "profile",
      detail: `Compiled with ${built.adapterId}.`
    }
  ];

  input.inbounds.forEach((inbound, index) => {
    entries.push({
      path: `/inbounds/${index + 1}`,
      title: inbound.protocol === "unmanaged" ? "Unmanaged inbound preserved" : `${inbound.protocol.toUpperCase()} inbound`,
      source: inbound.protocol === "unmanaged" ? "import" : "profile",
      detail: inbound.protocol === "unmanaged"
        ? "This inbound is round-tripped as raw JSON because it is not editable by the current model."
        : `Emits Xray protocol "${inbound.protocol}" with tag "${inbound.tag}".`
    });
  });

  if (input.raw?.topLevel) {
    entries.push({
      path: "/raw/topLevel",
      title: "Raw top-level sections",
      source: "raw",
      detail: "Raw top-level sections are merged before typed compiler output, so typed sections win on key conflict."
    });
  }

  if (input.raw?.patches?.length) {
    entries.push({
      path: "/raw/patches",
      title: "Raw JSON patches",
      source: "raw",
      detail: `${input.raw.patches.length} raw patch(es) are applied after typed compilation.`
    });
  }

  return entries;
}

