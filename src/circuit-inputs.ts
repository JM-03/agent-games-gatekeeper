/**
 * PEMETAAN INPUT CIRCUIT GATEKEEPER — *** TODO, BELUM DIISI ***
 *
 * FAKTA YANG SUDAH DIVERIFIKASI (2026-11-13):
 * - Circuit: Groth16 / bn128, Circom 2.x — dari /build dan /api/circuit-info.
 * - vkHash Gatekeeper: 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 * - File asli sudah diunduh ke circuits/: gatekeeper.wasm (1.755.820 byte,
 *   sha256 be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f)
 *   dan gatekeeper_final.zkey (309.750 byte,
 *   sha256 adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d).
 * - Verification key yang diekstrak dari .zkey: protocol groth16,
 *   curve bn128, nPublic = 13 (13 public signal).
 * - Template di dalam circuit memakai Poseidon (Ark/Mix/PoseidonEx).
 *
 * YANG ***TIDAK*** DIPUBLIKASIKAN DI HALAMAN RESMI YANG SAYA BACA
 * (/build, /guide, /rules, /events/proof-gatekeeper, /api/circuit-info,
 *  dan docs.zkverify.io Quickstart):
 * - Nama sinyal input circuit (file .sym tidak dipublikasikan).
 * - Pemetaan dari field task (registered_vk, proof_vk, minimum,
 *   public_balance, expiry_block, current_block, recipient,
 *   condition_recipient, amount, max_transfer, proof_tx, decision)
 *   ke sinyal input circuit tersebut.
 *
 * Saya TIDAK mengarang pemetaan itu. Kalau dikarang, proof yang dihasilkan
 * tidak akan terverifikasi oleh platform (skor -2 per task + kehilangan
 * reliability bonus) — lebih buruk daripada mengirim keputusan tanpa proof.
 *
 * CARA MENGISI TODO INI (pilih satu):
 *  1. Jalankan satu PRACTICE TASK dari dashboard (practice = format sama
 *     dengan scored task). Perhatikan respons / dokumentasi practice-nya:
 *     platform kadang menampilkan public_signals yang diharapkan.
 *  2. Tanya di Discord resmi zkVerify: https://discord.gg/zkverify
 *     (link ini ada di footer halaman /build). Tanyakan: "What are the
 *     input signal names and public input layout of the gatekeeper
 *     circuit (gatekeeper.wasm / gatekeeper_final.zkey, nPublic=13)?"
 *  3. Cek "protocol documentation" yang dirujuk halaman /build sebagai
 *     source of truth untuk format proof.
 *
 * Setelah pemetaan diketahui, isi fungsi buildCircuitInputs() di bawah
 * (kembalikan object { namaSinyal: nilai, ... } sesuai .sym circuit),
 * lalu ubah CIRCUIT_INPUTS_CONFIGURED menjadi true dan jalankan
 * `npm test` — test "proof generation" akan mencoba fullProve sungguhan.
 *
 * SELAMA TODO INI BELUM DIISI:
 * - Agent tetap bekerja penuh sebagai penilai: keputusan APPROVE/REJECT
 *   dihitung dari 7 cek deterministik dan dikirim dengan signature HMAC.
 * - Respons dikirim TANPA field proof/public_signals (persis bentuk
 *   contoh respons di halaman event: { decision, reason_code, proof_tx }).
 * - Konsekuensi skor (dari halaman event): keputusan benar tetap +12,
 *   tapi ada penalti -2 "Missing / invalid proof" per task yang bisa
 *   dibuktikan, dan tidak ada reliability bonus (+0..+5).
 */

import type { GatekeeperTask } from "./decision";

export const CIRCUIT_INPUTS_CONFIGURED = false;

export class CircuitInputMappingNotConfigured extends Error {
  constructor() {
    super(
      "Pemetaan input circuit Gatekeeper belum diisi. " +
        "Lihat src/circuit-inputs.ts: nama sinyal input circuit tidak dipublikasikan " +
        "di halaman resmi; isi buildCircuitInputs() setelah mendapatkannya dari " +
        "practice task / Discord zkVerify / protocol docs, lalu set " +
        "CIRCUIT_INPUTS_CONFIGURED = true."
    );
    this.name = "CircuitInputMappingNotConfigured";
  }
}

/**
 * TODO: kembalikan input untuk snarkjs.groth16.fullProve().
 * Contoh bentuk (JANGAN dipakai sebelum dikonfirmasi — ini hanya contoh
 * bentuk, bukan pemetaan asli):
 *   return { registeredVk: ..., proofVk: ..., minimum: ..., ... }
 */
export function buildCircuitInputs(
  _task: GatekeeperTask,
  _decision: "APPROVE" | "REJECT"
): Record<string, unknown> {
  throw new CircuitInputMappingNotConfigured();
}
