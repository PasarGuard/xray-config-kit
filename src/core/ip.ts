/**
 * IP address and prefix parsing with Go `net/netip` semantics, plus the MASQUE
 * address pool check from Xray `proxy/masque/pool.go`. Internal to the kit.
 */

export type IpFamily = 4 | 6;
export type ParsedIpAddress = { readonly family: IpFamily; readonly bytes: readonly number[]; readonly ipv4Mapped: boolean; readonly zone?: string };
export type ParsedIpPrefix = { readonly address: ParsedIpAddress; readonly bits: number };
export type MasquePoolProblem = "invalid" | "not-host" | "no-pool";

const ipv4Octet = /^(?:0|[1-9][0-9]{0,2})$/;
const ipv6Group = /^[0-9a-fA-F]{1,4}$/;
const prefixBits = /^(?:0|[1-9][0-9]*)$/;

/** Mirrors `netip.ParseAddr`: the first `.`, `:` or `%` decides how the input is read. */
export function parseIpAddress(input: string): ParsedIpAddress | undefined {
  for (const char of input) {
    if (char === ".") {
      const bytes = parseIpv4Octets(input);
      return bytes ? { family: 4, bytes, ipv4Mapped: false } : undefined;
    }
    if (char === ":") return parseIpv6(input);
    if (char === "%") return undefined;
  }
  return undefined;
}

/** Mirrors `netip.ParsePrefix`: no zone, and decimal bits without sign or leading zeros. */
export function parseIpPrefix(input: string): ParsedIpPrefix | undefined {
  const slash = input.lastIndexOf("/");
  if (slash === -1) return undefined;
  const address = parseIpAddress(input.slice(0, slash));
  if (!address || address.zone) return undefined;
  const bitsText = input.slice(slash + 1);
  if (!prefixBits.test(bitsText)) return undefined;
  const bits = Number(bitsText);
  if (bits > (address.family === 4 ? 32 : 128)) return undefined;
  return { address, bits };
}

/** Mirrors `newAddressPool`: the entry must be the server's host address and leave at least one address to assign. */
export function masquePoolProblem(prefix: ParsedIpPrefix): MasquePoolProblem | undefined {
  const { address, bits } = prefix;
  if (address.ipv4Mapped || address.zone) return "invalid";
  const isIpv4 = address.family === 4;
  const network = maskBytes(address.bytes, bits, false);
  const last = maskBytes(address.bytes, bits, true);
  if (sameBytes(address.bytes, network) || (isIpv4 && sameBytes(address.bytes, last))) return "not-host";
  const lastUsable = isIpv4 ? stepBytes(last, -1) : last;
  if (sameBytes(stepBytes(network, 1), lastUsable)) return "no-pool";
  return undefined;
}

/** The first host address of an IPv4 subnet that has one (bits <= 30), keeping the prefix length. */
export function firstHostPrefix(prefix: ParsedIpPrefix): string | undefined {
  if (prefix.address.family !== 4 || prefix.bits > 30) return undefined;
  const [a, b, c, d] = stepBytes(maskBytes(prefix.address.bytes, prefix.bits, false), 1);
  return `${a}.${b}.${c}.${d}/${prefix.bits}`;
}

function parseIpv4Octets(text: string): number[] | undefined {
  const parts = text.split(".");
  if (parts.length !== 4) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    if (!ipv4Octet.test(part)) return undefined;
    const value = Number(part);
    if (value > 255) return undefined;
    octets.push(value);
  }
  return octets;
}

function parseIpv6(input: string): ParsedIpAddress | undefined {
  const percent = input.indexOf("%");
  const text = percent === -1 ? input : input.slice(0, percent);
  const zone = percent === -1 ? undefined : input.slice(percent + 1);
  if (zone === "") return undefined;

  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const compressed = halves.length === 2;
  const head = parseIpv6Groups(halves[0] ?? "", !compressed);
  const tail = compressed ? parseIpv6Groups(halves[1] ?? "", true) : [];
  if (!head || !tail) return undefined;

  let bytes: number[];
  if (compressed) {
    // `::` stands for at least one zero group.
    if (head.length + tail.length > 14) return undefined;
    bytes = [...head, ...new Array<number>(16 - head.length - tail.length).fill(0), ...tail];
  } else {
    if (head.length !== 16) return undefined;
    bytes = head;
  }

  const ipv4Mapped = bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  return zone === undefined ? { family: 6, bytes, ipv4Mapped } : { family: 6, bytes, ipv4Mapped, zone };
}

/** Colon-separated hex groups; a dotted IPv4 is allowed only as the last group of the whole address. */
function parseIpv6Groups(text: string, ipv4Tail: boolean): number[] | undefined {
  if (text === "") return [];
  const groups = text.split(":");
  const bytes: number[] = [];
  for (const [index, group] of groups.entries()) {
    if (ipv4Tail && index === groups.length - 1 && group.includes(".")) {
      const octets = parseIpv4Octets(group);
      if (!octets) return undefined;
      bytes.push(...octets);
    } else {
      if (!ipv6Group.test(group)) return undefined;
      const value = Number.parseInt(group, 16);
      bytes.push(value >> 8, value & 0xff);
    }
  }
  return bytes;
}

function maskBytes(bytes: readonly number[], bits: number, setHostBits: boolean): number[] {
  return bytes.map((byte, index) => {
    const networkBits = Math.min(Math.max(bits - index * 8, 0), 8);
    const mask = (0xff << (8 - networkBits)) & 0xff;
    return setHostBits ? byte | (~mask & 0xff) : byte & mask;
  });
}

function stepBytes(bytes: readonly number[], delta: 1 | -1): number[] {
  const result = [...bytes];
  for (let index = result.length - 1; index >= 0; index -= 1) {
    const value = (result[index] ?? 0) + delta;
    result[index] = value & 0xff;
    if (value >= 0 && value <= 0xff) break;
  }
  return result;
}

function sameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
