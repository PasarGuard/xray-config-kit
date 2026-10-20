/**
 * A matching VLESS Encryption pair (server decryption, client encryption over the same X25519 key) in the format
 * "xray vlessenc" prints, as Xray's own XDrive config tests use it. XDrive needs VLESS Encryption on both sides.
 */
export const vlessEncryptionPair = {
  decryption: "mlkem768x25519plus.native.600s.UKfUEMDdjlEnycTMBP0a08acky8vRRKSrM1MRnaYk3s",
  encryption: "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I"
} as const;
