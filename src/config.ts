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

/** Secret HMAC platform: 32 byte acak, ditampilkan sekali saat registrasi agent.
 *
 * PELAJARAN 2026-11-13: tiga kali rotate → paste → redeploy tetap 401,
 * padahal nilai di Railway sudah diverifikasi SAMA dengan yang ditampilkan
 * dashboard. Jadi format kunci / signature platform TIDAK BOLEH ditebak
 * satu macam saja. Fungsi ini mengembalikan SEMUA penafsiran byte yang
 * masuk akal dari nilai env, urut dari yang paling mungkin kunci mentah:
 * hex-decode (64 hex), base64-decode (44 char, 32 byte), lalu UTF-8.
 * Verifikasi menerima kalau SALAH SATU kandidat cocok — lihat verifyHmacAny
 * di hmac.ts. */
export function hmacSecretCandidates(): Buffer[] {
  const raw = getHmacSecretRaw().trim();
  if (!raw) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET belum diset. Ambil dari dashboard Agent Games (Rotate Secret) dan isi di env — jangan taruh di kode."
    );
  }
  const out: Buffer[] = [];
  const push = (b: Buffer) => {
    if (b.length > 0 && !out.some((x) => x.equals(b))) out.push(b);
  };
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    push(Buffer.from(raw, "hex"));
  }
  if (/^[A-Za-z0-9+/=_-]{43,44}$/.test(raw)) {
    try {
      const decoded = Buffer.from(raw.replace(/-/g, "+").replace(/_/g, "/"), "base64");
      if (decoded.length === 32) push(decoded);
    } catch {
      // bukan base64 valid — abaikan kandidat ini
    }
  }
  push(Buffer.from(raw, "utf8"));
  return out;
}

/** Kandidat pertama = penafsiran utama (dipakai untuk menandatangani respons). */
export function hmacSecretBytes(): Buffer {
  return hmacSecretCandidates()[0];
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
