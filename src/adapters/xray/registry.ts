import type { XrayAdapter, XrayCapabilities } from "./types.js";
import { buildCapabilitySummary, type CapabilitySummary } from "./capabilities.js";
import {
  createXrayAdapter,
  getGeneratedXrayAdapters,
  latestCompatibilityMatrix
} from "./dynamic.js";

export function getXrayAdapter(version?: string): XrayAdapter {
  return createXrayAdapter(version);
}

export function getCapabilities(options: { readonly xrayVersion?: string } = {}): XrayCapabilities {
  const adapter = getXrayAdapter(options.xrayVersion);
  const error = adapter.issues?.find((item) => item.severity === "error");
  if (error) throw new RangeError(error.message);
  return adapter.capabilities;
}

export function getCapabilitySummary(options: { readonly xrayVersion?: string } = {}): CapabilitySummary {
  return buildCapabilitySummary(getCapabilities(options));
}

export const compatibilityMatrix = latestCompatibilityMatrix;

export const registeredXrayAdapters = getGeneratedXrayAdapters();
