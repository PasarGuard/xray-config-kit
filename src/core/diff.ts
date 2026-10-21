import { escapePointerSegment, isJsonObject } from "./json.js";
import type { DiffEntry, JsonValue } from "./types.js";

function sameJson(a: JsonValue | undefined, b: JsonValue | undefined): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function joinPath(base: string, key: string | number): string {
  const encoded = escapePointerSegment(key);
  return base === "/" ? `/${encoded}` : `${base}/${encoded}`;
}

function walk(before: JsonValue | undefined, after: JsonValue | undefined, path: string, output: DiffEntry[]): void {
  if (sameJson(before, after)) return;

  if (before === undefined) {
    output.push({ op: "added", path, after });
    return;
  }
  if (after === undefined) {
    output.push({ op: "removed", path, before });
    return;
  }

  if (Array.isArray(before) && Array.isArray(after)) {
    const max = Math.max(before.length, after.length);
    for (let index = 0; index < max; index += 1) {
      walk(before[index], after[index], joinPath(path, index), output);
    }
    return;
  }

  if (isJsonObject(before) && isJsonObject(after)) {
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const key of [...keys].sort()) {
      walk(before[key], after[key], joinPath(path, key), output);
    }
    return;
  }

  output.push({ op: "changed", path, before, after });
}

export function diffConfigs(before: JsonValue, after: JsonValue): DiffEntry[] {
  const output: DiffEntry[] = [];
  walk(before, after, "/", output);
  return output;
}

