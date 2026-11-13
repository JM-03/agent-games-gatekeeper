/**
 * Kurier — jalur verifikasi zkVerify yang direkomendasikan (REST).
 * Sumber:
 * - https://agentgames.zkverify.io/build (contoh kode submit-proof)
 * - https://docs.zkverify.io/handbook/quickstart (register-vk, submit-proof,
 *   job-status, status flow Queued -> Valid -> Submitted -> IncludedInBlock
 *   -> Finalized)
 * - API key utama didapat di https://kurier.xyz
 *
 * Endpoint (dari contoh kode di /build):
 *   POST {KURIER_API_URL}/register-vk/{KURIER_API_KEY}
 *   POST {KURIER_API_URL}/submit-proof/{KURIER_API_KEY}
 *   GET  {KURIER_API_URL}/job-status/{KURIER_API_KEY}/{jobId}
 * dengan KURIER_API_URL default https://api.kurier.xyz/api/v1
 * (nilai ini tertulis di contoh kode halaman /build itu sendiri).
 *
 * CATATAN DESAIN (penting): respons ke platform HARUS sampai dalam 60 detik.
 * Polling sampai Finalized bisa lebih lama dari itu (menunggu block), jadi
 * submit ke Kurier dilakukan di BACKGROUND setelah respons terkirim — bukan
 * sebagai syarat respons. Platform memverifikasi ulang proof yang kita
 * kirim dengan VK-nya sendiri, jadi Finalized di Kurier adalah konfirmasi
 * catatan on-chain, bukan prasyarat menjawab task.
 */

import { KURIER_API_URL, getKurierApiKey, GATEKEEPER_VK_HASH } from "./config";

export interface KurierResult {
  skipped: boolean;
  reason?: string;
  jobId?: string;
  finalStatus?: string;
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data: unknown = text;
  try {
    data = JSON.parse(text);
  } catch {
    /* biarkan sebagai teks */
  }
  if (!res.ok) {
    throw new Error(`Kurier ${res.status}: ${text.slice(0, 300)}`);
  }
  return data;
}

async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url, { method: "GET" });
  const text = await res.text();
  let data: unknown = text;
  try {
    data = JSON.parse(text);
  } catch {
    /* biarkan sebagai teks */
  }
  if (!res.ok) {
    throw new Error(`Kurier ${res.status}: ${text.slice(0, 300)}`);
  }
  return data;
}

/** Daftarkan verification key sekali (sebelum submit proof pertama).
 *  Mengembalikan vkHash yang dikembalikan Kurier (atau yang sudah ada). */
export async function registerVk(vk: unknown): Promise<{ vkHash: string; raw: unknown }> {
  const KURIER_API_KEY = getKurierApiKey();
  if (!KURIER_API_KEY) throw new Error("KURIER_API_KEY belum diset.");
  const raw = await postJson(`${KURIER_API_URL}/register-vk/${KURIER_API_KEY}`, {
    proofType: "groth16",
    proofOptions: { library: "snarkjs", curve: "bn128" },
    vk,
  });
  const rec = raw as Record<string, unknown>;
  const vkHash =
    (typeof rec.vkHash === "string" && rec.vkHash) ||
    (typeof rec.uniq_vk_hash === "string" && rec.uniq_vk_hash) ||
    GATEKEEPER_VK_HASH;
  return { vkHash, raw };
}

/** Submit satu proof. Mengembalikan jobId untuk polling. */
export async function submitProof(
  proof: unknown,
  publicSignals: string[]
): Promise<{ jobId: string; raw: unknown }> {
  const KURIER_API_KEY = getKurierApiKey();
  if (!KURIER_API_KEY) throw new Error("KURIER_API_KEY belum diset.");
  const raw = await postJson(`${KURIER_API_URL}/submit-proof/${KURIER_API_KEY}`, {
    proofType: "groth16",
    vkRegistered: true,
    proofOptions: { library: "snarkjs", curve: "bn128" },
    proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
  });
  const rec = raw as Record<string, unknown>;
  if (typeof rec.jobId !== "string" || !rec.jobId) {
    throw new Error(`Kurier submit-proof tidak mengembalikan jobId: ${JSON.stringify(raw).slice(0, 300)}`);
  }
  return { jobId: rec.jobId, raw };
}

/** Poll job-status sampai Finalized / Failed / timeout. */
export async function pollJobStatus(
  jobId: string,
  opts: { intervalMs?: number; timeoutMs?: number } = {}
): Promise<{ status: string; raw: unknown }> {
  const intervalMs = opts.intervalMs ?? 5000;
  const timeoutMs = opts.timeoutMs ?? 120000;
  const started = Date.now();
  let last: unknown = null;
  for (;;) {
    const raw = await getJson(`${KURIER_API_URL}/job-status/${getKurierApiKey()}/${jobId}`);
    last = raw;
    const status = String((raw as Record<string, unknown>).status || "");
    if (status === "Finalized" || status === "Failed") {
      return { status, raw };
    }
    if (Date.now() - started > timeoutMs) {
      return { status: `TIMEOUT(last=${status || "unknown"})`, raw };
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

/**
 * Alur background (dipanggil SETELAH respons ke platform terkirim):
 * submit proof ke Kurier lalu poll sampai Finalized. Tidak pernah melempar
 * ke pemanggil — semua error hanya dicatat di log.
 */
export async function submitProofInBackground(
  proof: unknown,
  publicSignals: string[],
  log: (msg: string) => void
): Promise<KurierResult> {
  if (!getKurierApiKey()) {
    return { skipped: true, reason: "KURIER_API_KEY belum diset — lewati submit Kurier." };
  }
  try {
    const { jobId } = await submitProof(proof, publicSignals);
    log(`[kurier] proof disubmit, jobId=${jobId}`);
    const { status } = await pollJobStatus(jobId);
    log(`[kurier] job ${jobId} status akhir: ${status}`);
    return { skipped: false, jobId, finalStatus: status };
  } catch (err) {
    log(`[kurier] gagal: ${(err as Error).message}`);
    return { skipped: false, reason: (err as Error).message };
  }
}
