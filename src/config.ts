/**
 * Konfigurasi dari environment variable.
 * TIDAK ADA secret / nilai asli di file ini — semuanya dari env.
 *
 * Nilai default yang tertera di bawah ini adalah FAKTA PUBLIK dari halaman
 * resmi Agent Games (bukan tebakan):
 * - GATEKEEPER_VK_HASH: dari https://agentgames.zkverify.io/api/circuit-info
 *   (diambil 2026-11-13, network "mainnet", circuits.gatekeeper.vkHash)
 * - KURIER_API_URL: dari source halaman https://agentgames.zkverify.io/build
 *   (contoh kode Kurier di halaman itu: "https://api.kurier.xyz/api/v1")
 */

import * as path from "path";

export const GATEKEEPER_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const KURIER_API_URL =
  process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";

export function getKurierApiKey(): string {
  return process.env.KURIER_API_KEY || "";
}

/** Dibaca LAZY (saat dipanggil), bukan saat import — supaya test dan
 *  proses yang mengisi env belakangan tetap kebaca. */
export function getHmacSecretRaw(): string {
  return process.env.AGENT_GAMES_HMAC_SECRET || "";
}

/** Secret HMAC platform: 32 byte acak, ditampilkan sekali saat registrasi agent. */
export function hmacSecretBytes(): Buffer {
  const HMAC_SECRET_RAW = getHmacSecretRaw();
  if (!HMAC_SECRET_RAW) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET belum diset. Ambil dari dashboard Agent Games (Rotate Secret) dan isi di env — jangan taruh di kode."
    );
  }
  // Kalau secret berbentuk 64 karakter hex (32 byte), pakai sebagai byte.
  // Kalau bukan hex, pakai byte UTF-8 dari string-nya.
  if (/^[0-9a-fA-F]{64}$/.test(HMAC_SECRET_RAW.trim())) {
    return Buffer.from(HMAC_SECRET_RAW.trim(), "hex");
  }
  return Buffer.from(HMAC_SECRET_RAW, "utf8");
}

export const PORT = Number(process.env.PORT || "3000");

/** Batas aman internal: harus di bawah deadline 60 detik platform. */
export const RESPONSE_DEADLINE_MS = Number(
  process.env.RESPONSE_DEADLINE_MS || "55000"
);

/** Batas waktu pembuatan proof lokal (snarkjs). Kalau lewat, respons tetap
 *  dikirim tanpa proof (keputusan tetap dihitung) — jangan sampai timeout. */
export const PROOF_TIMEOUT_MS = Number(process.env.PROOF_TIMEOUT_MS || "30000");

export const CIRCUIT_WASM_PATH = path.resolve(
  process.env.CIRCUIT_WASM_PATH || path.join(__dirname, "..", "circuits", "gatekeeper.wasm")
);

export const CIRCUIT_ZKEY_PATH = path.resolve(
  process.env.CIRCUIT_ZKEY_PATH || path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey")
);

/** File penyimpanan proof yang sudah diterima (anti-reuse) + task yang sudah dijawab. */
export const SEEN_STORE_PATH = path.resolve(
  process.env.SEEN_STORE_PATH || path.join(__dirname, "..", "data", "seen.json")
);

export const CIRCUIT_INFO = {
  protocol: "groth16",
  curve: "bn128",
  /** Jumlah public signal — diverifikasi dari file .zkey asli (nPublic = 13). */
  nPublic: 13,
  vkHash: GATEKEEPER_VK_HASH,
  wasmUrl: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
  zkeyUrl: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
};
