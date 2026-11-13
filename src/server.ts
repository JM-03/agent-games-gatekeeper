/**
 * HTTP server: POST /agent (task + preflight), GET /health, GET /.
 * Framework: Express 5, raw body HANYA untuk /agent (HMAC harus dihitung
 * dari raw body sebelum JSON di-parse).
 *
 * Alur POST /agent:
 *  1. Verifikasi HMAC (x-agent-games-signature) atas raw body — gagal -> 401.
 *  2. Parse JSON — gagal -> 400 (tidak ada keputusan yang bisa dikirim).
 *  3. type preflight -> jawab { ok: true, protocolVersion: "v1" } (signed).
 *  4. type proof-gatekeeper -> parse task -> kalau task_id sudah pernah
 *     dijawab, kembalikan respons lama (idempotency).
 *  5. Hitung keputusan deterministik (fail-closed).
 *  6. Coba buat proof lokal (kalau pemetaan circuit sudah diisi dan masih
 *     dalam batas waktu) — gagal -> tetap kirim keputusan TANPA proof.
 *  7. Kirim respons JSON yang ditandatangani HMAC.
 *  8. Background: kalau ada proof + KURIER_API_KEY, submit ke Kurier.
 */

import express, { type Express, type Request, type Response } from "express";
import {
  PORT,
  RESPONSE_DEADLINE_MS,
  PROOF_TIMEOUT_MS,
  SEEN_STORE_PATH,
  hmacSecretBytes,
  hmacSecretCandidates,
} from "./config";
import { computeHmacHex, verifyHmacAny, SIGNATURE_HEADER } from "./hmac";
import { decide, parseTask, type GatekeeperTask } from "./decision";
import { SeenStore, type StoredResponse } from "./store";
import { generateDecisionProof, getCircuitInfo } from "./proof";
import { CircuitInputMappingNotConfigured } from "./circuit-inputs";
import { submitProofInBackground } from "./kurier";

function log(msg: string): void {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

/** Kirim JSON + header signature HMAC atas raw body respons. */
function sendSigned(res: Response, status: number, body: Record<string, unknown>): void {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  try {
    const secret = hmacSecretBytes();
    res.setHeader(SIGNATURE_HEADER, computeHmacHex(secret, raw));
  } catch {
    // Tanpa secret (mis. mode test lokal tanpa env), kirim tanpa signature
    // tapi catat — di produksi ini TIDAK BOLEH terjadi.
    log("[peringatan] AGENT_GAMES_HMAC_SECRET belum diset — respons tanpa signature.");
  }
  res.status(status).setHeader("content-type", "application/json").send(raw);
}

export function createApp(store: SeenStore): Express {
  const app = express();

  // Health check (Railway + dashboard). Tanpa HMAC — ini memang endpoint publik.
  app.get("/health", (_req, res) => {
    const circuit = getCircuitInfo();
    res.json({
      ok: true,
      service: "agent-games-gatekeeper",
      event: "proof-gatekeeper",
      circuit: {
        protocol: circuit.protocol,
        curve: circuit.curve,
        nPublic: circuit.nPublic,
        vkHash: circuit.vkHash,
        wasmPresent: circuit.wasmPresent,
        zkeyPresent: circuit.zkeyPresent,
      },
      store: store.stats,
    });
  });

  app.get("/", (_req, res) => {
    res.json({
      service: "agent-games-gatekeeper",
      event: "proof-gatekeeper",
      health: "/health",
      agent: "POST /agent",
    });
  });

  // Endpoint utama. express.raw supaya HMAC dihitung dari byte mentah.
  // type "*/*": body mentah harus tertangkap apa pun Content-Type yang
  // dikirim platform (kalau hanya "application/json", body dari Content-Type
  // lain tidak akan jadi Buffer dan verifikasi pasti gagal).
  app.post(
    "/agent",
    express.raw({ type: "*/*", limit: "1mb" }),
    async (req: Request, res: Response) => {
      const startedAt = Date.now();
      const rawBody = req.body as Buffer;
      let secretCandidates: Buffer[];
      try {
        secretCandidates = hmacSecretCandidates();
      } catch (err) {
        log(`[agent] ${(err as Error).message}`);
        res.status(500).json({ error: "server belum dikonfigurasi (HMAC secret kosong)" });
        return;
      }

      // 1. HMAC dulu, SEBELUM parse JSON — verifikasi toleran: coba semua
      // penafsiran kunci (hex/base64/UTF-8) dan format signature (hex/base64).
      const signature = req.header(SIGNATURE_HEADER);
      const check = verifyHmacAny(secretCandidates, rawBody, signature);
      log(
        `[agent] verifikasi HMAC: header=${check.headerPresent ? "ada" : "TIDAK ADA"} ` +
          `panjang=${check.headerLength} encoding=${check.sigEncoding} ` +
          `kandidat-cocok=${check.secretIndex} kandidat-total=${secretCandidates.length}.`
      );
      if (!check.ok) {
        // Preflight tanpa signature sama sekali: handshake saja, bukan task
        // bernilai — jawab 200 supaya health check tidak mati karena platform
        // mengirim preflight tanpa tanda tangan. Task tanpa signature tetap 401.
        if (!check.headerPresent) {
          try {
            const peeked = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
            if (peeked.type === "agent-games.preflight.v1") {
              log("[agent] preflight TANPA signature -> jawab ok (handshake).");
              sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
              return;
            }
          } catch {
            // bukan JSON — lanjut ke 401 di bawah
          }
        }
        log("[agent] HMAC tidak cocok — tolak (401).");
        res.status(401).json({ error: "invalid signature" });
        return;
      }

      // 2. Parse JSON.
      let body: unknown;
      try {
        body = JSON.parse(rawBody.toString("utf8"));
      } catch {
        log("[agent] body bukan JSON valid — tolak (400).");
        res.status(400).json({ error: "invalid json" });
        return;
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        res.status(400).json({ error: "body harus object JSON" });
        return;
      }
      const type = (body as Record<string, unknown>).type;

      // 3. Preflight handshake (Build page, block 3).
      if (type === "agent-games.preflight.v1") {
        log("[agent] preflight -> ok.");
        sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
        return;
      }

      if (type !== "agent-games.proof-gatekeeper.v1") {
        log(`[agent] type tidak dikenal: ${String(type)} — tolak (400).`);
        res.status(400).json({ error: `unknown type: ${String(type)}` });
        return;
      }

      // 4. Parse + validasi task.
      const { task, error } = parseTask(body);
      if (!task) {
        log(`[agent] task tidak valid: ${error} — REJECT INVALID_TASK.`);
        const responseBody: StoredResponse = {
          decision: "REJECT",
          reason_code: "INVALID_TASK",
          proof_tx: "0x",
        };
        // Tidak ada task_id yang bisa diandalkan -> jangan simpan idempotency.
        sendSigned(res, 200, responseBody as unknown as Record<string, unknown>);
        return;
      }

      // Idempotency: task_id yang sama -> respons yang sama.
      if (store.hasResponse(task.task_id)) {
        const previous = store.getResponse(task.task_id)!;
        log(`[agent] task ${task.task_id} sudah dijawab — kembalikan respons lama.`);
        sendSigned(res, 200, previous as unknown as Record<string, unknown>);
        return;
      }

      // 5. Keputusan deterministik (fail-closed).
      const result = decide(task, (tx) => store.isProofSeen(tx));
      log(`[agent] task ${task.task_id}: ${result.decision} (${result.reason_code}) — ${result.detail}`);

      // 6. Coba buat proof lokal (opsional — jangan sampai melewati deadline).
      let proof: unknown;
      let publicSignals: string[] | undefined;
      const remainingMs = RESPONSE_DEADLINE_MS - (Date.now() - startedAt);
      if (remainingMs > 5000) {
        try {
          const generated = await generateDecisionProof(
            task,
            result.decision,
            Math.min(PROOF_TIMEOUT_MS, remainingMs - 2000)
          );
          proof = generated.proof;
          publicSignals = generated.publicSignals;
          log(`[agent] proof lokal dibuat (${publicSignals.length} public signals).`);
        } catch (err) {
          if (err instanceof CircuitInputMappingNotConfigured) {
            log("[agent] proof dilewati: pemetaan input circuit belum diisi (lihat src/circuit-inputs.ts). Keputusan tetap dikirim.");
          } else {
            log(`[agent] proof gagal: ${(err as Error).message} — keputusan tetap dikirim tanpa proof.`);
          }
        }
      } else {
        log("[agent] sisa waktu < 5 detik — lewati pembuatan proof.");
      }

      // 7. Respons (bentuk contoh di halaman event + starter prompt /build).
      const responseBody: StoredResponse = {
        decision: result.decision,
        reason_code: result.reason_code,
        proof_tx: task.input.proof_tx,
      };
      if (proof !== undefined && publicSignals !== undefined) {
        responseBody.proof = proof;
        responseBody.public_signals = publicSignals;
      }
      store.saveResponse(task.task_id, responseBody);
      if (result.decision === "APPROVE") {
        store.markProofSeen(task.input.proof_tx);
      }
      sendSigned(res, 200, responseBody as unknown as Record<string, unknown>);

      // 8. Background: submit proof ke Kurier (jangan blokir respons).
      if (proof !== undefined && publicSignals !== undefined) {
        void submitProofInBackground(proof, publicSignals, log);
      }
    }
  );

  return app;
}

export function startServer(): void {
  const store = new SeenStore(SEEN_STORE_PATH);
  const app = createApp(store);
  app.listen(PORT, () => {
    log(`agent-games-gatekeeper jalan di port ${PORT} — POST /agent, GET /health`);
    log(`circuit: ${getCircuitInfo().protocol}/${getCircuitInfo().curve}, nPublic=${getCircuitInfo().nPublic}`);
  });
}

// Dipakai test: bangun app dengan store sementara tanpa listen.
export function createTestApp(store: SeenStore): Express {
  return createApp(store);
}
export type { GatekeeperTask };
