/**
 * PEMETAAN INPUT CIRCUIT GATEKEEPER — NAMA SINYAL TERBUKTI, ENCODING BEST-EFFORT
 *
 * NAMA SINYAL (TERBUKTI 2026-11-13, lihat CIRCUIT_RESEARCH.md):
 * - 13 input, semuanya public (nPublic = 13), template GatekeeperEvaluation_79:
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   taskId, decision, salt.
 * - Nama-nama ini DIBUKTIKAN dengan probing file WASM resmi lewat circom
 *   witness calculator (48.539 kandidat diuji per circuit) — BUKAN tebakan.
 *   Witness berhasil dihitung untuk kasus REJECT (decision=0, vk beda) dan
 *   APPROVE (decision=1, semua cek lolos); keputusan yang salah gagal di
 *   assert GatekeeperEvaluation_79:102. Jadi decision 0 = REJECT,
 *   1 = APPROVE, dan circuit memaksanya.
 * - vk itu sendiri BUKAN input — hanya hash-nya. proof_tx juga BUKAN input.
 *
 * ENCODING (*** UNVERIFIED / BEST-EFFORT *** — platform TIDAK mempublikasikan
 * cara mengubah nilai task menjadi field element di mana pun: sudah dicek
 * /build, /guide, /rules, halaman event, /api/circuit-info, docs.zkverify.io,
 * DAN starter prompt di /build yang dibaca lewat browser asli pada 2026-11-13
 * 22:32 WIB — tidak ada satu pun aturan "field element" di sana):
 * - registeredVkHash / proofVkHash: Poseidon (circomlibjs, sama dengan
 *   template Poseidon di circomlib) atas vk 32-byte yang dipecah menjadi
 *   dua limb 16-byte big-endian, masing-masing sebagai field element.
 *   Alasan pilihan ini: vk 32-byte (256-bit) lebih besar dari field bn128
 *   (~254-bit) sehingga tidak bisa langsung jadi satu field element; split
 *   dua limb + Poseidon adalah cara kanonik circom untuk hash 32 byte.
 * - recipient / conditionRecipient: BigInt dari hex address 0x...
 * - minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer:
 *   BigInt dari string desimal task.
 * - taskId: Poseidon atas byte UTF-8 dari string task_id, tiap byte sebagai
 *   field element. Karena Poseidon WASM circomlibjs maksimal 16 input per
 *   panggilan dan task_id nyata lebih panjang dari itu, byte dirangkai
 *   sponge-style dalam potongan 15 byte dengan digest berjalan sebagai
 *   elemen pertama panggilan berikutnya (lihat poseidonHashLong).
 * - decision: 0n (REJECT) atau 1n (APPROVE).
 * - salt: 0n (konstan). Penalaran: platform tidak bisa tahu salt kita —
 *   tidak ada salt yang dikirim di task — jadi nilai salt apa pun yang
 *   tetap valid untuk pembuatan proof; yang penting konsistensi antara
 *   public signal dan proof yang kita kirim. Kalau platform ternyata
 *   mengharapkan salt tertentu, proof akan ditolak — sama saja dengan
 *   tidak mengirim proof (penalti -2), bukan lebih buruk.
 *
 * KONSEKUENSI SKOR (dari halaman event): encoding yang SALAH membuat proof
 * ditolak platform -> penalti -2 yang SAMA dengan tidak mengirim proof.
 * Encoding yang BENAR -> proof valid, tidak ada -2, dan membuka reliability
 * bonus +0..+5. Jadi mencoba mengirim proof adalah free upside: kegagalan
 * proof TIDAK PERNAH menggagalkan task — server selalu fallback ke respons
 * tanpa proof (lihat src/server.ts langkah 6).
 *
 * Kalau suatu hari encoding resmi diketahui (Discord / protocol docs),
 * perbaiki fungsi-fungsi *_toField di bawah — nama sinyalnya sudah benar
 * dan tidak perlu diubah.
 */

import type { GatekeeperTask } from "./decision";

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

/** Instance Poseidon (circomlibjs) — diinisialisasi malas, sekali saja.
 *  buildPoseidon() async karena ia memuat implementasi WASM Poseidon. */
let poseidonPromise: Promise<{
  (inputs: bigint[]): Uint8Array;
  F: { toString: (x: Uint8Array) => string };
}> | null = null;

async function getPoseidon(): Promise<{
  (inputs: bigint[]): Uint8Array;
  F: { toString: (x: Uint8Array) => string };
}> {
  if (!poseidonPromise) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { buildPoseidon } = require("circomlibjs") as {
      buildPoseidon: () => Promise<{
        (inputs: bigint[]): Uint8Array;
        F: { toString: (x: Uint8Array) => string };
      }>;
    };
    poseidonPromise = buildPoseidon();
  }
  return poseidonPromise;
}

/**
 * Poseidon atas daftar field element -> nilai field sebagai BigInt.
 * Satu panggilan, maksimal 16 input (batas implementasi WASM circomlibjs).
 */
async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  if (inputs.length < 1 || inputs.length > 16) {
    throw new Error(`Poseidon satu panggilan butuh 1..16 input, dapat ${inputs.length}`);
  }
  const poseidon = await getPoseidon();
  const out = poseidon(inputs);
  return BigInt(poseidon.F.toString(out));
}

/**
 * Poseidon atas daftar field element yang panjangnya sebarang — dirangkai
 * (sponge-style) dalam potongan 15 elemen, digest berjalan dibawa sebagai
 * elemen pertama panggilan berikutnya. Dipakai untuk taskId yang panjangnya
 * tidak terbatas (string task_id nyata > 16 byte, mis. practice_... 45 byte).
 */
async function poseidonHashLong(inputs: bigint[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  let state = 0n;
  for (let i = 0; i < inputs.length; i += 15) {
    const chunk = inputs.slice(i, i + 15);
    const out = poseidon([state, ...chunk]);
    state = BigInt(poseidon.F.toString(out));
  }
  return state;
}

/**
 * *** UNVERIFIED (best-effort) *** — vk 32-byte -> field element.
 * Pecah menjadi dua limb 16-byte big-endian, Poseidon atas keduanya.
 * Mengembalikan decimal string (format yang diterima snarkjs fullProve).
 */
export async function vkHashToField(vkHex: string): Promise<string> {
  const hex = vkHex.startsWith("0x") ? vkHex.slice(2) : vkHex;
  const bytes = Buffer.from(hex.padStart(64, "0"), "hex");
  if (bytes.length !== 32) {
    throw new Error(`vk harus 32 byte, dapat ${bytes.length} byte dari ${vkHex}`);
  }
  const limbHi = BigInt("0x" + bytes.subarray(0, 16).toString("hex"));
  const limbLo = BigInt("0x" + bytes.subarray(16, 32).toString("hex"));
  return (await poseidonHash([limbHi, limbLo])).toString();
}

/**
 * *** UNVERIFIED (best-effort) *** — string task_id -> field element.
 * Poseidon atas byte UTF-8 dari string, tiap byte sebagai field element.
 */
export async function taskIdToField(taskId: string): Promise<string> {
  const bytes = Buffer.from(taskId, "utf8");
  const inputs = [...bytes].map((b) => BigInt(b));
  return (await poseidonHashLong(inputs)).toString();
}

/** Address 0x... -> field element (BigInt dari hex). */
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
export async function buildCircuitInputs(
  task: GatekeeperTask,
  decision: "APPROVE" | "REJECT"
): Promise<Record<string, string>> {
  const inp = task.input;
  const [registeredVkHash, proofVkHash, taskId] = await Promise.all([
    vkHashToField(inp.registered_vk),
    vkHashToField(inp.proof_vk),
    taskIdToField(task.task_id),
  ]);
  return {
    registeredVkHash,
    proofVkHash,
    minimum: BigInt(inp.minimum).toString(),
    publicBalance: BigInt(inp.public_balance).toString(),
    expiryBlock: BigInt(inp.expiry_block).toString(),
    currentBlock: BigInt(inp.current_block).toString(),
    recipient: addressToField(inp.recipient),
    conditionRecipient: addressToField(inp.condition_recipient),
    amount: BigInt(inp.amount).toString(),
    maxTransfer: BigInt(inp.max_transfer).toString(),
    taskId,
    decision: decision === "APPROVE" ? "1" : "0",
    // Salt 0 (konstan) — lihat alasan di header file ini.
    salt: "0",
  };
}
