/**
 * IP rules for finalmask filter tests. Each rule was run through `xray run -test` inside a filter mask on the first
 * Xray release with that mask, and gets the same verdict there as in the kit. Rules that need a geo file only use codes
 * present in the release zips.
 */
export const acceptedIpRules = ["192.0.2.0/24", "192.0.2.1", "2001:db8::/32", "::1", "!10.0.0.0/8", "!!1.2.3.4", "geoip:private", "geoip:!cn", "!geoip:ir",
  "ext:geoip.dat:ir", "ext-ip:geoip.dat:private", "[::1]/128", "1.2.3.4/", "::ffff:1.2.3.4/32", "10.0.0.0/024", " 1.2.3.4", "1.2.3.4/0"];

export const rejectedIpRules = ["192.0.2.0/33", "2001:db8::/129", "::ffff:1.2.3.4/96", "example.com", "1.2.3.4/abc", "1.2.3.4/-1", "1.2.3.4/+8", "geoip:",
  "ext:geoip.dat", "ext::cn", "ext:geoip.dat:!", "fe80::1%eth0", "", "01.2.3.4", "1.2.3", "geosite:ir"];
