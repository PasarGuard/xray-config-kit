import { makeIssue } from "./issues.js";
import { isJsonObject } from "./json.js";
import { XDRIVE_LIMITS, XDRIVE_SERVICES } from "./masque-xdrive.js";
import type { Inbound, Issue, JsonObject, Outbound } from "./types.js";

function isNonBlankString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

/** The stream's transport name, lowercased. Xray reads `method` first and falls back to `network`. */
export function transportName(stream: JsonObject | undefined): string | undefined {
  const name = stream?.method ?? stream?.network;
  return typeof name === "string" ? name.toLowerCase() : undefined;
}

/** Checks one XDrive settings object (an inbound `transport` or an outbound `xdriveSettings` block) found at `path`. */
export function xdriveSettingsIssues(settings: JsonObject, path: string): Issue[] {
  const issues: Issue[] = [];
  const service = typeof settings.service === "string" ? settings.service : "";

  if (!(XDRIVE_SERVICES as readonly string[]).includes(service)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_SERVICE",
      severity: "error",
      category: "semantic",
      path: `${path}/service`,
      message: `XDrive service must be "local", "Google Drive", or "template".`
    }));
  }

  if ((service === "local" || service === "Google Drive") && !isNonBlankString(settings.remoteFolder)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_REMOTE_FOLDER_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${path}/remoteFolder`,
      message: `XDrive "${service}" needs remoteFolder (a directory for local, a folder ID for Google Drive).`
    }));
  }

  const secrets = settings.secrets;
  if (service === "Google Drive" && !(Array.isArray(secrets) && secrets.length === 3 && secrets.every(isNonBlankString))) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_GOOGLE_DRIVE_SECRETS",
      severity: "error",
      category: "semantic",
      path: `${path}/secrets`,
      message: "Google Drive needs 3 secrets in order: ClientID, ClientSecret, RefreshToken."
    }));
  }

  if (service === "template" && !isJsonObject(settings.template)) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_TEMPLATE_REQUIRED",
      severity: "error",
      category: "semantic",
      path: `${path}/template`,
      message: "The template service needs a template object."
    }));
  }

  if (typeof settings.segmentBytes === "number" && settings.segmentBytes > XDRIVE_LIMITS.segmentBytes) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_SEGMENT_BYTES_CAPPED",
      severity: "warning",
      category: "semantic",
      path: `${path}/segmentBytes`,
      message: "Xray caps segmentBytes at 16777216 (16 MiB)."
    }));
  }

  if (typeof settings.concurrency === "number" && settings.concurrency > XDRIVE_LIMITS.concurrency) {
    issues.push(makeIssue({
      code: "XCK_SEMANTIC_XDRIVE_CONCURRENCY_CAPPED",
      severity: "warning",
      category: "semantic",
      path: `${path}/concurrency`,
      message: "Xray caps concurrency at 64."
    }));
  }

  return issues;
}

export function inboundTransportIssues(inbound: Inbound, inboundIndex: number): Issue[] {
  const transport = inbound.protocol !== "unmanaged" && "transport" in inbound ? inbound.transport : undefined;
  if (transport?.type !== "xdrive") return [];
  return xdriveSettingsIssues(transport, `/inbounds/${inboundIndex + 1}/transport`);
}

export function outboundTransportIssues(outbound: Outbound, outboundIndex: number): Issue[] {
  if (outbound.protocol === "unmanaged") return [];
  const stream = outbound.streamSettings as JsonObject | undefined;
  const settings = stream?.xdriveSettings;
  const path = `/outbounds/${outboundIndex + 1}/streamSettings/xdriveSettings`;
  // Xray builds every *Settings block that is present, even when the stream selects another transport.
  if (isJsonObject(settings)) return xdriveSettingsIssues(settings, path);
  if (transportName(stream) === "xdrive") return xdriveSettingsIssues({}, path);
  return [];
}
