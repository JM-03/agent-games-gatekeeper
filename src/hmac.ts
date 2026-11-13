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
