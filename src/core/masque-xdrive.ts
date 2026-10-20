/** Storage services Xray accepts in xdriveSettings.service. */
export const XDRIVE_SERVICES = ["local", "Google Drive", "template"] as const;

export type XDriveService = (typeof XDRIVE_SERVICES)[number];

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
