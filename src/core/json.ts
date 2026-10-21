import type { JsonObject, JsonValue, RawPatch } from "./types.js";

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function cloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function stableStringify(value: JsonValue): string {
  return JSON.stringify(sortJson(value), null, 2);
}

export function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isJsonObject(value)) return value;
  const sorted: Record<string, JsonValue> = {};
  for (const key of Object.keys(value).sort()) {
    const child = value[key];
    if (child !== undefined) sorted[key] = sortJson(child);
  }
  return sorted;
}

/** Escapes one JSON-pointer segment (RFC 6901): `~` becomes `~0` and `/` becomes `~1`. */
export function escapePointerSegment(key: string | number): string {
  return String(key).replace(/~/g, "~0").replace(/\//g, "~1");
}

function decodePointer(pointer: string): string[] {
  if (!pointer.startsWith("/")) {
    throw new Error(`Invalid JSON pointer "${pointer}"`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
}

function mutableContainer(value: JsonValue): Record<string, JsonValue> | JsonValue[] {
  if (Array.isArray(value)) return value as JsonValue[];
  if (isJsonObject(value)) return value as Record<string, JsonValue>;
  throw new Error("Patch target is not an object or array");
}

export function applyRawPatch<T extends JsonValue>(input: T, patch: RawPatch): T {
  const target = cloneJson(input);
  const parts = decodePointer(patch.path);
  let cursor: JsonValue = target;
  for (let index = 0; index < parts.length - 1; index += 1) {
    const part = parts[index];
    if (part === undefined) throw new Error(`Invalid JSON pointer "${patch.path}"`);
    const container = mutableContainer(cursor);
    const next = Array.isArray(container) ? container[Number(part)] : container[part];
    if (next === undefined) throw new Error(`Patch path does not exist: ${patch.path}`);
    cursor = next;
  }

  const leaf = parts.at(-1);
  if (leaf === undefined || leaf === "") throw new Error(`Invalid JSON pointer "${patch.path}"`);
  const container = mutableContainer(cursor);

  if (Array.isArray(container)) {
    const idx = leaf === "-" ? container.length : Number(leaf);
    if (!Number.isInteger(idx) || idx < 0 || idx > container.length) {
      throw new Error(`Invalid array patch index in ${patch.path}`);
    }
    if (patch.op === "remove") {
      if (idx >= container.length) throw new Error(`Patch path does not exist: ${patch.path}`);
      container.splice(idx, 1);
    } else if (patch.op === "add") {
      if (patch.value === undefined) throw new Error(`Patch "${patch.op}" requires a value`);
      container.splice(idx, 0, patch.value);
    } else {
      if (idx >= container.length) throw new Error(`Patch path does not exist: ${patch.path}`);
      if (patch.value === undefined) throw new Error(`Patch "${patch.op}" requires a value`);
      container[idx] = patch.value;
    }
    return target;
  }

  if (patch.op === "remove") {
    delete container[leaf];
  } else {
    if (patch.value === undefined) throw new Error(`Patch "${patch.op}" requires a value`);
    container[leaf] = patch.value;
  }
  return target;
}

export function mergeTopLevel(base: JsonObject, topLevel: Record<string, JsonValue> | undefined): JsonObject {
  if (!topLevel) return base;
  return { ...topLevel, ...base };
}
