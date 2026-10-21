/**
 * Storage services Xray accepts in xdriveSettings.service. "Google Drive" and "google-drive" are the same service:
 * newer Xray renames it to "google-drive" and still reads "Google Drive", which is the only spelling older releases know.
 */
export const XDRIVE_SERVICES = ["local", "Google Drive", "google-drive", "template"] as const;

export type XDriveService = (typeof XDRIVE_SERVICES)[number];

/** The two spellings of the Google Drive service in XDRIVE_SERVICES. */
export const XDRIVE_GOOGLE_DRIVE_SERVICES: ReadonlySet<string> = new Set<XDriveService>(["Google Drive", "google-drive"]);

/** Values Xray uses when an xdriveSettings number is left out (or set to 0). */
export const XDRIVE_DEFAULTS = {
  segmentBytes: 524288,
  flushIntervalMs: 20,
  pollIntervalMs: 50,
  maxPollIntervalMs: 500,
  sessionTtlSeconds: 300,
  concurrency: 8,
  eagerWindowMs: 2000,
  holeTimeoutMs: 30000
} as const;

/** Upper bounds Xray clamps xdriveSettings values to. */
export const XDRIVE_LIMITS = {
  segmentBytes: 16777216,
  concurrency: 64
} as const;

/** Values Xray uses when a MASQUE field is left out. `mtu` 0 also means 1280. */
export const MASQUE_DEFAULTS = {
  path: "/.well-known/masque/ip/*/*/",
  mtu: 1280,
  warpHost: "cloudflareaccess.com",
  warpPath: "/",
  clientRemoteDNS: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
} as const;

/** Bounds Xray accepts for a non-zero MASQUE `mtu`. */
export const MASQUE_LIMITS = {
  minMtu: 1280,
  maxMtu: 65535
} as const;

/** Template variables Xray expands in a masque `path`, in Xray's argument order. */
const masquePathVariables: readonly (readonly [string, string])[] = [
  ["{target}", "*"],
  ["{ipproto}", "*"],
  ["{?target,ipproto}", "?target=*&ipproto=*"],
  ["{?ipproto,target}", "?ipproto=*&target=*"],
  ["{&target,ipproto}", "&target=*&ipproto=*"],
  ["{&ipproto,target}", "&ipproto=*&target=*"]
];
const masquePathVariablePattern = new RegExp(masquePathVariables.map(([variable]) => variable.replace(/[{}?]/g, "\\$&")).join("|"), "g");
const masquePathVariableValues = new Map(masquePathVariables);

/** Mirrors Xray's strings.NewReplacer in infra/conf/transport_method.go MasqueConfig.Build. */
export function expandMasquePathTemplate(path: string): string {
  return path.replace(masquePathVariablePattern, (variable) => masquePathVariableValues.get(variable) ?? variable);
}
