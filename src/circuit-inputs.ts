/**
 * PEMETAAN INPUT CIRCUIT GATEKEEPER — NAMA SINYAL TERBUKTI, ENCODING TERBUKTI
 *
 * NAMA SINYAL (TERBUKTI 2026-11-13, lihat CIRCUIT_RESEARCH.md):
 * - 13 input ke witness calculator (nPublic = 13), template
 *   GatekeeperEvaluation_79: registeredVkHash, proofVkHash, minimum,
 *   publicBalance, expiryBlock, currentBlock, recipient,
 *   conditionRecipient, amount, maxTransfer, taskId, decision, salt.
 *   Dari 13 input itu, 12 muncul sebagai public signal; salt adalah
 *   satu-satunya input PRIVAT (lihat catatan evaluationCommitment di bawah).
 * - Nama-nama ini DIBUKTIKAN dengan probing file WASM resmi lewat circom
 *   witness calculator (48.539 kandidat diuji per circuit) — BUKAN tebakan.
 *   Witness berhasil dihitung untuk kasus REJECT (decision=0, vk beda) dan
 *   APPROVE (decision=1, semua cek lolos); keputusan yang salah gagal di
 *   assert GatekeeperEvaluation_79:102. Jadi decision 0 = REJECT,
 *   1 = APPROVE, dan circuit memaksanya.
 * - vk itu sendiri BUKAN input — hanya hash-nya. proof_tx juga BUKAN input.
 * - Salt adalah SATU-SATUNYA input privat: ia TIDAK MUNCUL di public
 *   signals. Sebagai gantinya, publicSignals[0] adalah `evaluationCommitment`
 *   — hash commitment yang dihitung circuit dari input + salt (platform
 *   TIDAK memeriksa index 0 karena tidak bisa menghitungnya tanpa salt;
 *   ini dikonfirmasi pecker: binding assert mereka melewati index 0).
 *   Layout publicSignals (TERBUKTI 2026-11-14 lewat dump proof lokal):
 *   [0]=evaluationCommitment, [1]=registeredVkHash, [2]=proofVkHash,
 *   [3]=minimum, [4]=publicBalance, [5]=expiryBlock, [6]=currentBlock,
 *   [7]=recipient, [8]=conditionRecipient, [9]=amount, [10]=maxTransfer,
 *   [11]=decision, [12]=taskId. Perhatikan: decision dan taskId BERURUTAN
 *   terbalik dibanding urutan kunci di buildCircuitInputs() — urutan objek
 *   TIDAK menentukan urutan public signals; urutan ditentukan circuit.
 *
 * ENCODING (TERBUKTI 2026-11-14, lihat
 * ~/workspace/wildcard-research/LEADERBOARD-RESEARCH-REPORT.md §5.2/§6):
 * - registeredVkHash / proofVkHash: BigInt(hex) % P, P = prima field bn128.
 * - taskId: keccak256(byte UTF-8 task_id) % P.
 * - recipient / conditionRecipient, minimum, publicBalance, expiryBlock,
 *   currentBlock, amount, maxTransfer: BigInt langsung (nilainya < P,
 *   jadi identik dengan BigInt % P).
 * - decision: 0n (REJECT) atau 1n (APPROVE).
 * - salt: 0n (konstan). Platform tidak bisa memeriksa public signal[0]
 *   tanpa salt (signal[0] adalah commitment yang melibatkan salt privat),
 *   jadi nilai salt apa pun yang tetap valid untuk pembuatan proof.
 *
 * BUKTI (bukan tebakan):
 * - Skor leaderboard Ronde 01 terurai persis: skor = 80 + 2,625 x proof
 *   terverifikasi. Semua 7 agent teratas 8/8 benar, 0 timeout; pecker
 *   87,9 = 3/8 proof terverifikasi, enam agent di 80,0 = 0/8 terverifikasi.
 * - Zeel (vk-sentinel) mencatat perbandingan terkontrol: encoding UUID-tail
 *   mereka 0/6 proof terverifikasi pada 13 Nov, sementara proof pecker
 *   dengan keccak256(utf8 task_id) mod p terverifikasi pada task yang sama.
 * - Skema yang sama dipakai pecker, zeel, chandra, nestic.
 *
 * SKEMA LAMA (DIGANTI 2026-11-14 — JANGAN dipakai lagi):
 * - vk: Poseidon (circomlibjs) atas dua limb 16-byte; taskId: Poseidon
 *   chunked atas byte UTF-8. Tidak ada satu pun agent teratas yang memakai
 *   skema ini, dan tidak ada bukti skema ini pernah terverifikasi di
 *   platform. Badge "Proof: VERIFIED" di dashboard practice TIDAK BISA
 *   dijadikan bukti — badge itu muncul di practice #1 padahal tidak ada
 *   proof yang dikirim sama sekali.
 *
 * KONSEKUENSI SKOR: encoding yang SALAH membuat proof ditolak platform ->
 * penalti -2 yang SAMA dengan tidak mengirim proof. Encoding yang BENAR ->
 * proof valid, tidak ada -2, dan membuka reliability bonus +0..+5.
 * Kegagalan proof TIDAK PERNAH menggagalkan task — server selalu fallback
 * ke respons tanpa proof (lihat src/server.ts langkah 6).
 */

import { keccak256 } from "viem";
import type { GatekeeperTask } from "./decision";

/** Prima field bn128 (BN254) — dipakai semua repo peserta teratas. */
export const BN128_FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Nama sinyal sudah terbukti — proof generation aktif. */
export const CIRCUIT_INPUTS_CONFIGURED = true;

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
 * vk 32-byte (hex 0x...) -> field element: BigInt(hex) % P.
 * Skema yang dipakai pecker/zeel/chandra/nestic (terverifikasi di Ronde 01).
 * Mengembalikan decimal string (format yang diterima snarkjs fullProve).
 */
export function vkHashToField(vkHex: string): string {
  const hex = vkHex.startsWith("0x") ? vkHex.slice(2) : vkHex;
  const bytes = Buffer.from(hex.padStart(64, "0"), "hex");
  if (bytes.length !== 32) {
    throw new Error(`vk harus 32 byte, dapat ${bytes.length} byte dari ${vkHex}`);
  }
  return (BigInt(vkHex) % BN128_FIELD_PRIME).toString();
}

/**
 * string task_id -> field element: keccak256(byte UTF-8 task_id) % P.
 * Skema yang dipakai pecker/zeel/chandra/nestic (terverifikasi di Ronde 01).
 * Mengembalikan decimal string (format yang diterima snarkjs fullProve).
 */
export function taskIdToField(taskId: string): string {
  const hashHex = keccak256(Buffer.from(taskId, "utf8"));
  return (BigInt(hashHex) % BN128_FIELD_PRIME).toString();
}

/** Address 0x... -> field element (BigInt dari hex; < P jadi identik dengan % P). */
export function addressToField(addressHex: string): string {
  return BigInt(addressHex).toString();
}

/**
 * Bangun 13 input circuit untuk snarkjs.groth16.fullProve().
 * Semua nilai dikembalikan sebagai decimal string — format yang diterima
 * witness calculator snarkjs untuk field element bn128.
 *
 * @throws Error kalau ada nilai task yang tidak bisa di-encode
 *         (mis. vk bukan 32 byte). Pemanggil HARUS menangkap dan fallback
 *         ke respons tanpa proof.
 */
export function buildCircuitInputs(
  task: GatekeeperTask,
  decision: "APPROVE" | "REJECT"
): Record<string, string> {
  const inp = task.input;
  return {
    registeredVkHash: vkHashToField(inp.registered_vk),
    proofVkHash: vkHashToField(inp.proof_vk),
    minimum: BigInt(inp.minimum).toString(),
    publicBalance: BigInt(inp.public_balance).toString(),
    expiryBlock: BigInt(inp.expiry_block).toString(),
    currentBlock: BigInt(inp.current_block).toString(),
    recipient: addressToField(inp.recipient),
    conditionRecipient: addressToField(inp.condition_recipient),
    amount: BigInt(inp.amount).toString(),
    maxTransfer: BigInt(inp.max_transfer).toString(),
    taskId: taskIdToField(task.task_id),
    decision: decision === "APPROVE" ? "1" : "0",
    // Salt 0 (konstan) — lihat alasan di header file ini.
    salt: "0",
  };
}
