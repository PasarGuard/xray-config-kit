import { firstAvailableRelease } from "../xray-json/parity.js";
import { parseIpAddress } from "./ip.js";
import { makeIssue } from "./issues.js";
import { isJsonObject } from "./json.js";
import type { Issue, JsonObject } from "./types.js";
import { hasFinalmaskType } from "./xray-features.js";
import type { XrayRuleFeatures } from "./xray-features.js";

const filterIpRuleKeys = ["blockedSourceIPs", "allowedSourceIPs"] as const;
const alphanumeric = /^[0-9A-Za-z]$/;
const decimal = /^[0-9]+$/;

function cutReversePrefix(text: string): string {
  let rest = text;
  while (rest.startsWith("!")) rest = rest.slice(1);
  return rest;
}

/**
 * Why Xray's geodata.ParseIPRules would refuse `rule`, or undefined when it parses. Accepts IPs, CIDRs, `geoip:<code>`,
 * `ext:<file>:<code>` and `ext-ip:<file>:<code>`, each optionally negated with "!". Whether a geo file and code exist is
 * checked by Xray when it loads the config and cannot be checked here.
 */
export function xrayIpRuleProblem(rule: string): string | undefined {
  let rest = cutReversePrefix(rule);
  if (rest.startsWith("geoip:")) rest = `ext:geoip.dat:${rest.slice("geoip:".length)}`;

  const extPrefix = ["ext:", "ext-ip:"].find((prefix) => rest.startsWith(prefix));
  if (extPrefix) {
    const geo = rest.slice(extPrefix.length);
    const colon = geo.indexOf(":");
    if (colon === -1) return "a geo rule needs a file and a code, as in ext:geoip.dat:cn";
    if (colon === 0) return "the geo file name is empty";
    if (cutReversePrefix(geo.slice(colon + 1)) === "") return "the geo code is empty";
    return undefined;
  }

  // parseCIDR: net.ParseAddress on the text before the first "/", then an optional decimal prefix length.
  const slash = rest.indexOf("/");
  let host = slash === -1 ? rest : rest.slice(0, slash);
  const bitsText = slash === -1 ? "" : rest.slice(slash + 1);
  if (host.length >= 2 && host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.length > 0 && (!alphanumeric.test(host[0]!) || !alphanumeric.test(host.at(-1)!))) host = host.trim();
  const address = parseIpAddress(host);
  // net.ParseIP has no zones; Xray treats an IPv4-mapped IPv6 address as IPv4.
  if (!address || address.zone !== undefined) return "it is not an IP address, a CIDR, geoip:<code> or ext:<file>:<code>";
  const maxBits = address.family === 4 || address.ipv4Mapped ? 32 : 128;
  if (bitsText === "") return undefined;
  if (!decimal.test(bitsText) || Number(bitsText) > 0xffffffff) return `the CIDR prefix length "${bitsText}" is not a number`;
  if (Number(bitsText) > maxBits) return `the CIDR prefix length ${Number(bitsText)} exceeds ${maxBits}`;
  return undefined;
}

function filterSettingsIssues(settings: unknown, path: string): Issue[] {
  if (settings === undefined || settings === null) return [];
  if (!isJsonObject(settings)) {
    return [makeIssue({
      code: "XCK_SEMANTIC_FINALMASK_FILTER_SETTINGS",
      severity: "error",
      category: "semantic",
      path,
      message: "Finalmask filter settings must be an object with blockedSourceIPs and/or allowedSourceIPs."
    })];
  }

  const issues: Issue[] = [];
  for (const key of filterIpRuleKeys) {
    const rules = settings[key];
    if (rules === undefined || rules === null) continue;
    if (!Array.isArray(rules)) {
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_FINALMASK_FILTER_SETTINGS",
        severity: "error",
        category: "semantic",
        path: `${path}/${key}`,
        message: `Finalmask filter ${key} must be a list of IP rules.`
      }));
      continue;
    }
    rules.forEach((rule, ruleIndex) => {
      const problem = typeof rule === "string" ? xrayIpRuleProblem(rule) : "it is not a string";
      if (!problem) return;
      issues.push(makeIssue({
        code: "XCK_SEMANTIC_FINALMASK_FILTER_IP_RULE",
        severity: "error",
        category: "semantic",
        path: `${path}/${key}/${ruleIndex}`,
        message: `Finalmask filter ${key} entry ${JSON.stringify(rule)} is not a valid IP rule: ${problem}.`,
        suggestion: "Use an IP, a CIDR such as 192.0.2.0/24, geoip:<code> or ext:<file>:<code>, optionally prefixed with \"!\"."
      }));
    });
  }
  return issues;
}

/**
 * Checks the "filter" masks of a stream's finalmask block found at `path`. Other mask types are left to Xray, so a type
 * the kit does not know never becomes an error here.
 */
export function finalmaskIssues(finalmask: JsonObject | undefined, path: string, features: XrayRuleFeatures): Issue[] {
  if (!finalmask) return [];
  const issues: Issue[] = [];
  for (const side of ["tcp", "udp"] as const) {
    const masks = finalmask[side];
    if (!Array.isArray(masks)) continue;
    masks.forEach((mask, maskIndex) => {
      // Xray's JSONConfigLoader lowercases the type.
      if (!isJsonObject(mask) || typeof mask.type !== "string" || mask.type.toLowerCase() !== "filter") return;
      const maskPath = `${path}/${side}/${maskIndex}`;
      if (!features.finalmaskFilter) {
        const first = firstAvailableRelease((release) => hasFinalmaskType(release, "filter"));
        issues.push(makeIssue({
          code: "XCK_SEMANTIC_FINALMASK_FILTER_UNSUPPORTED",
          severity: "error",
          category: "semantic",
          path: `${maskPath}/type`,
          message: `The finalmask "filter" mask needs ${first ? `Xray ${first.tag} or newer` : "a newer Xray release"}.`,
          suggestion: "Remove the filter mask, or run that release or newer on every node that gets this config."
        }));
        return;
      }
      issues.push(...filterSettingsIssues(mask.settings, `${maskPath}/settings`));
    });
  }
  return issues;
}
