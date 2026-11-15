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
 * ~/workspace/wildcard-research/LEADERBOARD-RESEARCH-REPORT.md §5.2/§6;
 * taskId DIPERBAIKI 2026-11-16 — lihat di bawah):
 * - registeredVkHash / proofVkHash: BigInt(hex) % P, P = prima field bn128.
 * - taskId: UUID di ujung task_id sebagai integer 128-bit untuk id format
 *   R03 (`task_R03_<uuid>`); keccak256(byte UTF-8 task_id) % P hanya
 *   fallback untuk id tanpa UUID (format R01 `gk_...`, `task_R03_aec58a03`).
 *   Sumber konfirmasi: zeel `wrangler.toml:43` TASKID_ENCODING="uuidTail"
 *   CONFIRMED 2026-11-15; regex identik di zeel
 *   `prover/maps/gatekeeper.mjs:34-40` dan chandra `src/encoding.ts:94-102`.
 *   Perbedaan R01 vs R03: id R01 (`gk_24_9d1`, tanpa UUID) jatuh ke fallback
 *   keccak sehingga keccak terverifikasi saat itu; id R03
 *   (`task_R03_<uuid>`) diharapkan platform sebagai integer 128-bit.
 *   Inilah root cause 0-verified kita di R02/R03: taskIdToField lama selalu
 *   keccak256(utf8 task_id) % P, sehingga publicSignals[12] tidak cocok
 *   dengan yang diharapkan platform untuk id format R03.
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
 * - Zeel (vk-sentinel) mencatat perbandingan terkontrol pada 13 Nov (id
 *   format R01, tanpa UUID): encoding UUID-tail mereka 0/6 proof
 *   terverifikasi, sementara proof pecker dengan keccak256(utf8 task_id)
 *   mod p terverifikasi pada task yang sama — konsisten dengan fallback
 *   keccak untuk id tanpa UUID. Untuk id format R03 (`task_R03_<uuid>`)
 *   platform mengharapkan uuidTail (zeel CONFIRMED 2026-11-15).
 * - Skema taskId sekarang mirror zeel/chandra: uuidTail + keccak fallback.
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
 * Kegagalan proof BISA menggagalkan task di ronde skor: respons tanpa proof
 * untuk PROOF_REUSED di Ronde 03 (task_R03_aec58a03, 15 Nov 2026) ditolak
 * platform (redelivery 2x lalu TIMEOUT) meski keputusan REJECT-nya benar.
 * Karena itu fallback sekarang melampirkan sinyal publik yang jujur +
 * proof:null (lihat buildPublicSignals + src/server.ts langkah 6) — proof
 * REJECT memang tidak mungkin dibuat untuk replay: circuit memaksa
 * decision=1 (assert GatekeeperEvaluation_79:102).
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
 * string task_id -> field element.
 * - Id format R03 (`task_R03_<uuid>`): UUID di ujung task_id sebagai
 *   integer 128-bit (hex tanpa dash) — ini yang diharapkan platform.
 * - Id tanpa UUID (format R01 `gk_...`, `task_R03_aec58a03`):
 *   keccak256(byte UTF-8 task_id) % P (fallback).
 * Mirror persis zeel/chandra (lihat header file ini).
 * Mengembalikan decimal string (format yang diterima snarkjs fullProve).
 */
/** Trailing UUID di ujung task_id, mis. `task_R03_16e835e2-9c68-4307-30da-4b8a25ebd319`. */
const UUID_TAIL = /[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;

export function taskIdToField(taskId: string): string {
  const m = UUID_TAIL.exec(taskId);
  if (m) return BigInt("0x" + m[0].replace(/-/g, "")).toString();
  const hashHex = keccak256(Buffer.from(taskId, "utf8"));
  return (BigInt(hashHex) % BN128_FIELD_PRIME).toString();
}

/** Address 0x... -> field element (BigInt dari hex; < P jadi identik dengan % P). */
export function addressToField(addressHex: string): string {
  return BigInt(addressHex).toString();
}

/**
 * Sinyal publik (13) untuk suatu keputusan — dipakai sebagai FALLBACK saat
 * proof tidak bisa dibuat (khususnya PROOF_REUSED: circuit memaksa
 * decision=1 karena semua cek on-chain lolos, jadi proof REJECT tidak
 * mungkin dibuat — assert GatekeeperEvaluation_79:102).
 *
 * [1..12] adalah encoding jujur dari input task + keputusan (sama persis
 * dengan yang dihasilkan buildCircuitInputs, hanya diurutkan sesuai layout
 * public signals). [0] adalah evaluationCommitment — hash yang dihitung
 * circuit dari input + salt, TIDAK bisa dihitung tanpa proof yang berhasil;
 * platform melewati index 0 (lihat catatan di atas), jadi diisi "0" sebagai
 * placeholder eksplisit. proof yang dilampirkan bersama sinyal ini adalah
 * null (jujur: tidak ada proof) — platform tetap bisa membaca keputusan +
 * sinyalnya, dan untuk replay memang tidak ada proof yang bisa diserahkan.
 */
export function buildPublicSignals(
  task: GatekeeperTask,
  decision: "APPROVE" | "REJECT"
): string[] {
  const w = buildCircuitInputs(task, decision);
  return [
    "0", // [0] evaluationCommitment — placeholder, platform melewati index 0
    w.registeredVkHash, // [1]
    w.proofVkHash, // [2]
    w.minimum, // [3]
    w.publicBalance, // [4]
    w.expiryBlock, // [5]
    w.currentBlock, // [6]
    w.recipient, // [7]
    w.conditionRecipient, // [8]
    w.amount, // [9]
    w.maxTransfer, // [10]
    w.decision, // [11]
    w.taskId, // [12]
  ];
}

/**
 * Bangun 13 input circuit untuk snarkjs.groth16.fullProve().
 * Semua nilai dikembalikan sebagai decimal string — format yang diterima
 * witness calculator snarkjs untuk field element bn128.
 *
 * @throws Error kalau ada nilai task yang tidak bisa di-encode
 *         (mis. vk bukan 32 byte). Pemanggil HARUS menangkap dan fallback
 *         ke sinyal publik (buildPublicSignals) + proof:null.
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
