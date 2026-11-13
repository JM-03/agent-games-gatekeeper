/**
 * Logika keputusan Proof Gatekeeper — DETERMINISTIK, tanpa model bahasa.
 * Sumber: https://agentgames.zkverify.io/events/proof-gatekeeper
 * ("Trap encyclopedia" — 7 varian) dan Security checklist di
 * https://agentgames.zkverify.io/build
 *
 * Aturan skor (dari halaman event):
 *   APPROVE benar  +12 | REJECT benar +12 | APPROVE salah -6
 *   REJECT salah -3 | timeout -2 | proof tidak valid -2
 * Jadi: APPROVE hanya kalau SEMUA cek lolos. Ragu sedikit pun -> REJECT.
 *
 * Bentuk task (dari halaman event, "Sample task payload"):
 *   { type: "agent-games.proof-gatekeeper.v1", task_id, mode,
 *     issued_at, deadline_at,
 *     input: { registered_vk, proof_vk, minimum, public_balance,
 *              expiry_block, current_block, recipient,
 *              condition_recipient, amount, max_transfer, proof_tx } }
 *
 * Bentuk respons (dari halaman event + starter prompt di /build):
 *   { decision: "APPROVE" | "REJECT", reason_code, proof_tx,
 *     proof?, public_signals? }
 */

export type Decision = "APPROVE" | "REJECT";

/** reason_code resmi dari Trap Encyclopedia + 1 kode tambahan untuk
 *  task yang strukturnya tidak valid (fail-closed). */
export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "PROOF_REUSED"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "INVALID_TASK";

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

export interface GatekeeperTask {
  type: string;
  task_id: string;
  mode?: string;
  issued_at?: string | number;
  deadline_at?: string | number;
  input: GatekeeperInput;
}

export interface DecisionResult {
  decision: Decision;
  reason_code: ReasonCode;
  /** Alasan manusiawi (untuk log saja, tidak dikirim sebagai field terpisah). */
  detail: string;
}

function isHexString(v: unknown): v is string {
  return typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v);
}

function toBigInt(v: unknown): bigint | null {
  try {
    if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
    if (typeof v === "string" && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
    return null;
  } catch {
    return null;
  }
}

function toBlockNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return Number(v.trim());
  return null;
}

function parseTimestamp(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) {
    // Detik atau milidetik — normalisasi ke milidetik.
    return v < 1e12 ? v * 1000 : v;
  }
  if (typeof v === "string" && v.trim() !== "") {
    const asNumber = Number(v);
    if (Number.isFinite(asNumber) && /^\d+$/.test(v.trim())) {
      return asNumber < 1e12 ? asNumber * 1000 : asNumber;
    }
    const asDate = Date.parse(v);
    return Number.isNaN(asDate) ? null : asDate;
  }
  return null;
}

/**
 * Validasi struktur task. Mengembalikan GatekeeperTask yang sudah bersih,
 * atau null + alasan kalau task tidak bisa dipercaya (fail-closed).
 */
export function parseTask(raw: unknown): { task: GatekeeperTask | null; error: string | null } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { task: null, error: "body bukan object JSON" };
  }
  const body = raw as Record<string, unknown>;
  if (body.type !== "agent-games.proof-gatekeeper.v1") {
    return { task: null, error: `type tidak dikenal: ${String(body.type)}` };
  }
  if (typeof body.task_id !== "string" || body.task_id.trim() === "") {
    return { task: null, error: "task_id kosong/tidak ada" };
  }
  const input = body.input as Record<string, unknown> | undefined;
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { task: null, error: "input kosong/tidak ada" };
  }
  const requiredHex: Array<[string, unknown]> = [
    ["registered_vk", input.registered_vk],
    ["proof_vk", input.proof_vk],
    ["recipient", input.recipient],
    ["condition_recipient", input.condition_recipient],
    ["proof_tx", input.proof_tx],
  ];
  for (const [name, value] of requiredHex) {
    if (!isHexString(value)) {
      return { task: null, error: `input.${name} bukan string hex 0x...` };
    }
  }
  const minimum = toBigInt(input.minimum);
  const publicBalance = toBigInt(input.public_balance);
  const amount = toBigInt(input.amount);
  const maxTransfer = toBigInt(input.max_transfer);
  if (minimum === null || publicBalance === null || amount === null || maxTransfer === null) {
    return { task: null, error: "minimum/public_balance/amount/max_transfer bukan angka desimal" };
  }
  if (minimum < 0n || publicBalance < 0n || amount < 0n || maxTransfer < 0n) {
    return { task: null, error: "nilai angka negatif" };
  }
  const expiryBlock = toBlockNumber(input.expiry_block);
  const currentBlock = toBlockNumber(input.current_block);
  if (expiryBlock === null || currentBlock === null) {
    return { task: null, error: "expiry_block/current_block bukan nomor blok" };
  }
  return {
    task: {
      type: body.type,
      task_id: body.task_id.trim(),
      mode: typeof body.mode === "string" ? body.mode : undefined,
      issued_at: body.issued_at as string | number | undefined,
      deadline_at: body.deadline_at as string | number | undefined,
      input: {
        registered_vk: input.registered_vk as string,
        proof_vk: input.proof_vk as string,
        minimum: minimum.toString(),
        public_balance: publicBalance.toString(),
        expiry_block: expiryBlock,
        current_block: currentBlock,
        recipient: (input.recipient as string).toLowerCase(),
        condition_recipient: (input.condition_recipient as string).toLowerCase(),
        amount: amount.toString(),
        max_transfer: maxTransfer.toString(),
        proof_tx: (input.proof_tx as string).toLowerCase(),
      },
    },
    error: null,
  };
}

/**
 * Keputusan deterministik. `isProofSeen` = apakah proof_tx ini SUDAH PERNAH
 * DITERIMA (APPROVE) di task sebelumnya — sesuai ensiklopedia: reuse berarti
 * "proof reference was already accepted in a previous task".
 *
 * Urutan cek: setiap task di kompetisi berisi SATU trap (ensiklopedia:
 * ~50% valid, sisanya terbagi ke 6 trap), jadi urutan antar-trap tidak
 * mengubah hasil. Yang penting: semua trap dicek, dan APPROVE hanya kalau
 * semuanya lolos.
 */
export function decide(
  task: GatekeeperTask,
  isProofSeen: (proofTx: string) => boolean,
  nowMs: number = Date.now()
): DecisionResult {
  const inp = task.input;

  // 0. Timestamp: signature + timestamp harus valid sebelum kerja apa pun.
  //    issued_at di masa depan (di luar toleransi 5 menit) atau deadline
  //    sudah lewat = task tidak bisa dipercaya -> REJECT.
  if (task.issued_at !== undefined) {
    const issued = parseTimestamp(task.issued_at);
    if (issued === null) {
      return { decision: "REJECT", reason_code: "INVALID_TASK", detail: "issued_at tidak bisa dibaca" };
    }
    if (issued > nowMs + 5 * 60 * 1000) {
      return { decision: "REJECT", reason_code: "INVALID_TASK", detail: "issued_at di masa depan" };
    }
  }
  if (task.deadline_at !== undefined) {
    const deadline = parseTimestamp(task.deadline_at);
    if (deadline === null) {
      return { decision: "REJECT", reason_code: "INVALID_TASK", detail: "deadline_at tidak bisa dibaca" };
    }
    if (nowMs > deadline) {
      return { decision: "REJECT", reason_code: "INVALID_TASK", detail: "deadline sudah lewat" };
    }
  } else {
    // Tanpa deadline, kita tidak bisa memastikan task masih berlaku.
    return { decision: "REJECT", reason_code: "INVALID_TASK", detail: "deadline_at tidak ada" };
  }

  // 1. VK_SUBSTITUTION — proof valid tapi VK-nya bukan VK kondisi terdaftar.
  if (inp.proof_vk.toLowerCase() !== inp.registered_vk.toLowerCase()) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", detail: "proof_vk != registered_vk" };
  }

  // 2. THRESHOLD_MISMATCH — saldo publik di bawah minimum yang disyaratkan.
  if (BigInt(inp.public_balance) < BigInt(inp.minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", detail: "public_balance < minimum" };
  }

  // 3. RECIPIENT_MISMATCH — penerima di proof beda dengan alamat kondisi.
  if (inp.recipient !== inp.condition_recipient) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", detail: "recipient != condition_recipient" };
  }

  // 4. AMOUNT_OVERFLOW — jumlah melebihi batas transfer tunggal.
  if (BigInt(inp.amount) > BigInt(inp.max_transfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", detail: "amount > max_transfer" };
  }

  // 5. EXPIRED_CONDITION — blok sekarang sudah lewat expiry.
  if (inp.current_block > inp.expiry_block) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", detail: "current_block > expiry_block" };
  }

  // 6. PROOF_REUSED — proof_tx ini sudah pernah DITERIMA sebelumnya.
  if (isProofSeen(inp.proof_tx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", detail: "proof_tx sudah pernah diterima" };
  }

  // Semua cek lolos -> APPROVE.
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", detail: "semua cek lolos" };
}
