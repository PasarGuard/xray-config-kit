import { generateKeyPairSync } from "node:crypto";

/**
 * Fresh WARP test keys in the base64 DER form Xray decodes: a P-256 PKCS#8 client private key and
 * a P-256 SPKI server public key.
 */
export function warpKeys(): { readonly privateKey: string; readonly publicKey: string } {
  const client = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const server = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    privateKey: client.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    publicKey: server.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  };
}
