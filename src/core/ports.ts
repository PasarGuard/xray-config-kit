/**
 * Xray port list segment parsing (infra/conf/common.go PortList), shared by the port list check and the XDrive port
 * count. Internal to the kit.
 */

/** One port list segment: an `env:NAME` port that Xray reads when it starts, or the ports `from` to `to`. */
export type PortSegment = { readonly env: string } | { readonly from: number; readonly to: number };

const envPortPattern = /^env:[A-Za-z_][A-Za-z0-9_]*$/;
const portRangePattern = /^(\d+)(?:-(\d+))?$/;

/**
 * Parses one comma-separated port list segment after trimming it: "env:NAME", "n", or "a-b" with a <= b.
 * Undefined for an empty segment or one that does not parse. Port numbers are not bounds-checked here.
 */
export function parsePortSegment(segment: string): PortSegment | undefined {
  const trimmed = segment.trim();
  if (envPortPattern.test(trimmed)) return { env: trimmed.slice("env:".length) };
  const range = portRangePattern.exec(trimmed);
  if (!range) return undefined;
  const from = Number(range[1]);
  const to = range[2] === undefined ? from : Number(range[2]);
  return from <= to ? { from, to } : undefined;
}
