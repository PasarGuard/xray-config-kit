import { describe, expect, it } from "bun:test";
import { firstHostPrefix, masquePoolProblem, parseIpAddress, parseIpPrefix } from "../../src/core/ip.js";

describe("netip-compatible IP parsing for MASQUE", () => {
  const problem = (input: string) => {
    const prefix = parseIpPrefix(input);
    if (!prefix) throw new Error(`unparsed ${input}`);
    return masquePoolProblem(prefix);
  };

  it("parses IPv4 and IPv6 prefixes with netip rules", () => {
    expect(parseIpPrefix("10.0.0.1/24")).toEqual({ address: { family: 4, bytes: [10, 0, 0, 1], ipv4Mapped: false }, bits: 24 });
    expect(parseIpPrefix("fd00::1/64")?.address.family).toBe(6);
    expect(parseIpPrefix("fd00::1/64")?.address.bytes).toEqual([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect(parseIpPrefix("::ffff:10.0.0.1/120")?.address.ipv4Mapped).toBe(true);
    for (const bad of ["10.0.0.1", "010.0.0.1/24", "10.0.0.1/024", "10.0.0.1/33", "10.0.0.256/24", "fd00::1/129", "fe80::1%eth0/64", "1:2:3:4:5:6:7:8:9/64", "fd00:::1/64", "", " 10.0.0.1/24"]) {
      expect(parseIpPrefix(bad), bad).toBeUndefined();
    }
  });

  it("parses bare addresses including IPv6 zones like netip.ParseAddr", () => {
    expect(parseIpAddress("1.1.1.1")).toEqual({ family: 4, bytes: [1, 1, 1, 1], ipv4Mapped: false });
    expect(parseIpAddress("2606:4700:4700::1111")?.family).toBe(6);
    expect(parseIpAddress("fe80::1%eth0")?.zone).toBe("eth0");
    expect(parseIpAddress("dns.google")).toBeUndefined();
    expect(parseIpAddress("1.1.1.1%eth0")).toBeUndefined();
  });

  it("matches Xray's MASQUE address pool rules", () => {
    for (const notHost of ["10.0.0.0/24", "10.0.0.255/24", "10.0.0.1/31", "10.0.0.1/32", "10.0.0.3/30", "fd00::/64"]) expect(problem(notHost), notHost).toBe("not-host");
    expect(problem("fd00::1/127")).toBe("no-pool");
    expect(problem("::ffff:10.0.0.1/120")).toBe("invalid");
    for (const ok of ["10.0.0.1/24", "10.0.0.1/30", "10.14.0.1/16", "fd00::1/64", "fd00::3/126"]) expect(problem(ok), ok).toBeUndefined();
  });

  it("suggests the first host address for IPv4 subnets", () => {
    expect(firstHostPrefix(parseIpPrefix("10.0.0.0/24")!)).toBe("10.0.0.1/24");
    expect(firstHostPrefix(parseIpPrefix("10.0.0.255/24")!)).toBe("10.0.0.1/24");
    expect(firstHostPrefix(parseIpPrefix("10.0.0.1/31")!)).toBeUndefined();
    expect(firstHostPrefix(parseIpPrefix("fd00::/64")!)).toBeUndefined();
  });
});
