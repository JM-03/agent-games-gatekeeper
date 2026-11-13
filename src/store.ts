/**
 * Penyimpanan idempotency + anti-reuse.
 * - task_id -> respons yang sudah dikirim (platform boleh retry setelah
 *   gangguan jaringan — Rules 1.2: "Handle task IDs as idempotency keys").
 *   Retry dengan task_id yang sama HARUS mengembalikan respons yang sama,
 *   tanpa mengevaluasi ulang dan tanpa mengubah seen-set.
 * - proof_tx yang sudah DITERIMA (keputusan APPROVE) -> anti PROOF_REUSED.
 *
 * Disimpan di memori + file JSON (SEEN_STORE_PATH) supaya selamat dari
 * restart proses di server yang sama. Di Railway, file ini hilang kalau
 * deployment dibuat ulang tanpa volume — itu keterbatasan yang dicatat di
 * README (untuk produksi idealnya Redis/Postgres).
 */

import * as fs from "fs";
import * as path from "path";

export interface StoredResponse {
  decision: string;
  reason_code: string;
  proof_tx: string;
  proof?: unknown;
  public_signals?: string[];
}

interface SeenFile {
  seenProofTx: string[];
  responsesByTaskId: Record<string, StoredResponse>;
}

export class SeenStore {
  private seenProofTx = new Set<string>();
  private responsesByTaskId = new Map<string, StoredResponse>();
  private filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.load();
  }

  private load(): void {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const data = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as SeenFile;
      for (const tx of data.seenProofTx || []) this.seenProofTx.add(tx.toLowerCase());
      for (const [k, v] of Object.entries(data.responsesByTaskId || {})) {
        this.responsesByTaskId.set(k, v);
      }
    } catch (err) {
      console.error(`[store] gagal membaca ${this.filePath}, mulai dari kosong:`, err);
    }
  }

  private save(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const data: SeenFile = {
        seenProofTx: [...this.seenProofTx],
        responsesByTaskId: Object.fromEntries(this.responsesByTaskId),
      };
      fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), "utf8");
    } catch (err) {
      console.error(`[store] gagal menyimpan ${this.filePath}:`, err);
    }
  }

  hasResponse(taskId: string): boolean {
    return this.responsesByTaskId.has(taskId);
  }

  getResponse(taskId: string): StoredResponse | undefined {
    return this.responsesByTaskId.get(taskId);
  }

  saveResponse(taskId: string, response: StoredResponse): void {
    this.responsesByTaskId.set(taskId, response);
    this.save();
  }

  isProofSeen(proofTx: string): boolean {
    return this.seenProofTx.has(proofTx.toLowerCase());
  }

  /** Hanya dipanggil saat keputusan APPROVE (proof DITERIMA). */
  markProofSeen(proofTx: string): void {
    this.seenProofTx.add(proofTx.toLowerCase());
    this.save();
  }

  get stats(): { seenProofs: number; answeredTasks: number } {
    return { seenProofs: this.seenProofTx.size, answeredTasks: this.responsesByTaskId.size };
  }
}
