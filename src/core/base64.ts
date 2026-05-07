const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function base64EncodeUtf8(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const triple = (first << 16) | (second << 8) | third;
    output += chars[(triple >> 18) & 63];
    output += chars[(triple >> 12) & 63];
    output += index + 1 < bytes.length ? chars[(triple >> 6) & 63] : "=";
    output += index + 2 < bytes.length ? chars[triple & 63] : "=";
  }
  return output;
}

function normalizeBase64(input: string): string {
  const normalized = input.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  if (remainder === 1) throw new Error("Invalid base64 input.");
  return remainder === 0 ? normalized : `${normalized}${"=".repeat(4 - remainder)}`;
}

export function base64DecodeUtf8(input: string): string {
  const normalized = normalizeBase64(input);
  const bytes: number[] = [];

  for (let index = 0; index < normalized.length; index += 4) {
    const first = chars.indexOf(normalized[index] ?? "");
    const second = chars.indexOf(normalized[index + 1] ?? "");
    const thirdChar = normalized[index + 2];
    const fourthChar = normalized[index + 3];
    const third = thirdChar === "=" ? 0 : chars.indexOf(thirdChar ?? "");
    const fourth = fourthChar === "=" ? 0 : chars.indexOf(fourthChar ?? "");

    if (first < 0 || second < 0 || (thirdChar !== "=" && third < 0) || (fourthChar !== "=" && fourth < 0)) {
      throw new Error("Invalid base64 input.");
    }

    const triple = (first << 18) | (second << 12) | (third << 6) | fourth;
    bytes.push((triple >> 16) & 255);
    if (thirdChar !== "=") bytes.push((triple >> 8) & 255);
    if (fourthChar !== "=") bytes.push(triple & 255);
  }

  return new TextDecoder().decode(new Uint8Array(bytes));
}

export function base64UrlByteLength(input: string): number | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) return undefined;
  const mod = input.length % 4;
  if (mod === 1) return undefined;
  const paddedLength = input.length + (mod === 0 ? 0 : 4 - mod);
  let padding = 0;
  if (mod === 2) padding = 2;
  if (mod === 3) padding = 1;
  return (paddedLength / 4) * 3 - padding;
}
