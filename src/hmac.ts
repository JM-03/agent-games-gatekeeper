/**
 * HMAC-SHA256 untuk memverifikasi request masuk dan menandatangani respons.
 * Sumber: https://agentgames.zkverify.io/build
 * "compute the HMAC over the RAW request body and compare it to the
 *  x-agent-games-signature header BEFORE parsing JSON"
 * "Every response is signed with x-agent-games-signature over the raw response body."
 *
 * Format header yang dipakai: hex HMAC-SHA256 dari raw body.
 * Saat verifikasi, format "sha256=<hex>" juga diterima (beberapa layanan
 * memakai prefix itu). Format persisnya HARUS dikonfirmasi di practice run
 * pertama — kalau platform menolak signature, cek log dan sesuaikan di sini.
 */

import * as crypto from "crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

export function computeHmacHex(secret: Buffer, rawBody: Buffer): string {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function normalizeSignature(value: string): string {
  const v = value.trim().toLowerCase();
  return v.startsWith("sha256=") ? v.slice("sha256=".length) : v;
}

/** Bandingkan dengan timingSafeEqual supaya tidak bocor lewat timing attack. */
export function verifyHmac(
  secret: Buffer,
  rawBody: Buffer,
  headerValue: string | undefined
): boolean {
  if (!headerValue) return false;
  const expected = computeHmacHex(secret, rawBody);
  const received = normalizeSignature(headerValue);
  if (!/^[0-9a-f]{64}$/.test(received)) return false;
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(received, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** Decode nilai signature dari header ke byte mentah.
 *  Platform bisa mengirim hex (64 char) atau base64 (44 char, 32 byte).
 *  Mengembalikan null kalau formatnya tidak dikenali. */
export function decodeSignature(
  headerValue: string | undefined
): { bytes: Buffer; encoding: string } | null {
  if (!headerValue) return null;
  const v = normalizeSignature(headerValue);
  if (/^[0-9a-f]{64}$/.test(v)) {
    return { bytes: Buffer.from(v, "hex"), encoding: "hex" };
  }
  if (/^[A-Za-z0-9+/=_-]{43,44}$/.test(v)) {
    try {
      const decoded = Buffer.from(
        v.replace(/-/g, "+").replace(/_/g, "/"),
        "base64"
      );
      if (decoded.length === 32) return { bytes: decoded, encoding: "base64" };
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Verifikasi toleran (perbaikan 2026-11-13): coba SEMUA kandidat kunci
 * (hex / base64 / UTF-8 dari nilai env) terhadap signature header
 * (hex atau base64). Diterima kalau salah satu kombinasi cocok.
 * Mengembalikan kandidat mana yang cocok (-1 kalau tidak ada) plus
 * encoding signature — dipakai server untuk logging diagnosis TANPA
 * mencatat nilai secret/signature.
 */
export function verifyHmacAny(
  secrets: Buffer[],
  rawBody: Buffer,
  headerValue: string | undefined
): { ok: boolean; secretIndex: number; sigEncoding: string; headerPresent: boolean; headerLength: number } {
  const headerPresent = typeof headerValue === "string" && headerValue.length > 0;
  const headerLength = headerValue ? headerValue.length : 0;
  const decoded = decodeSignature(headerValue);
  if (!decoded) {
    return { ok: false, secretIndex: -1, sigEncoding: "unknown", headerPresent, headerLength };
  }
  for (let i = 0; i < secrets.length; i++) {
    const expected = crypto.createHmac("sha256", secrets[i]).update(rawBody).digest();
    if (expected.length === decoded.bytes.length && crypto.timingSafeEqual(expected, decoded.bytes)) {
      return { ok: true, secretIndex: i, sigEncoding: decoded.encoding, headerPresent, headerLength };
    }
  }
  return { ok: false, secretIndex: -1, sigEncoding: decoded.encoding, headerPresent, headerLength };
}
