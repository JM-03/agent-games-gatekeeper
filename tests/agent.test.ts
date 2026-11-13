/**
 * Test agent Gatekeeper (lokal, tanpa jaringan ke platform / Kurier).
 * Jalankan: npm test
 *
 * Yang diuji:
 *  1. /health hidup + info circuit benar.
 *  2. Task VALID (signed) -> APPROVE / VALID_CONDITION + signature respons valid.
 *  3. Signature salah -> 401, tidak ada keputusan.
 *  4. Tiap trap dari ensiklopedia -> REJECT dengan reason_code yang benar.
 *  5. Replay task_id yang sama -> respons identik (idempotency).
 *  6. Proof yang sudah diterima lalu dipakai lagi -> PROOF_REUSED.
 *  7. Preflight -> { ok: true, protocolVersion: "v1" } + signed.
 *  8. Task rusak (field hilang) -> REJECT INVALID_TASK (fail-closed).
 *  9. Artefak circuit asli (.zkey) -> VK groth16/bn128/nPublic=13.
 * 10. Kurier tanpa API key -> dilewati (skipped), bukan error.
 * 11. Replay practice task asli (practice_9e6ef3da, 2026-11-13) -> REJECT /
 *     VK_SUBSTITUTION + proof Groth16 yang lolos groth16.verify.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import { createTestApp } from "../src/server";
import { SeenStore } from "../src/store";
import { verifyCircuitArtifacts, generateDecisionProof } from "../src/proof";
import { submitProofInBackground } from "../src/kurier";
import { decide } from "../src/decision";
import { CIRCUIT_ZKEY_PATH } from "../src/config";
import { baseTask, signBody, TEST_HMAC_SECRET } from "./fixtures";

process.env.AGENT_GAMES_HMAC_SECRET = TEST_HMAC_SECRET;
process.env.KURIER_API_KEY = ""; // test lokal: Kurier harus dilewati

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-test-"));
const store = new SeenStore(path.join(tmpDir, "seen.json"));
const app = createTestApp(store);

let server: http.Server;
let baseUrl: string;

function postAgent(body: unknown, signature: string): Promise<{ status: number; headers: Record<string, string | undefined>; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const raw = typeof body === "string" ? body : JSON.stringify(body);
    const req = http.request(
      `${baseUrl}/agent`,
      { method: "POST", headers: { "content-type": "application/json", connection: "close", "x-agent-games-signature": signature } },
      (res) => {
        let data = "";
        res.on("data", (c: Buffer) => (data += c.toString()));
        res.on("end", () => {
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(data);
          } catch {
            json = { _raw: data };
          }
          resolve({ status: res.statusCode || 0, headers: res.headers as Record<string, string | undefined>, json });
        });
      }
    );
    req.on("error", reject);
    req.write(raw);
    req.end();
  });
}

function get(pathname: string): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    http.get(`${baseUrl}${pathname}`, { headers: { connection: "close" } }, (res) => {
      let data = "";
      res.on("data", (c: Buffer) => (data += c.toString()));
      res.on("end", () => resolve({ status: res.statusCode || 0, json: JSON.parse(data) }));
    }).on("error", reject);
  });
}

before(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const addr = server.address() as { port: number };
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

after(async () => {
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

test("1. GET /health hidup dan info circuit benar", async () => {
  const { status, json } = await get("/health");
  assert.equal(status, 200);
  assert.equal(json.ok, true);
  assert.equal((json.circuit as Record<string, unknown>).protocol, "groth16");
  assert.equal((json.circuit as Record<string, unknown>).curve, "bn128");
  assert.equal((json.circuit as Record<string, unknown>).nPublic, 13);
  assert.equal(
    (json.circuit as Record<string, unknown>).vkHash,
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
  );
});

test("2. Task VALID yang ditandatangani benar -> APPROVE + respons ikut ditandatangani", async () => {
  const task = baseTask({ task_id: "gk_test_valid" });
  const { raw, signature } = signBody(TEST_HMAC_SECRET, task);
  const { status, headers, json } = await postAgent(raw, signature);
  assert.equal(status, 200);
  assert.equal(json.decision, "APPROVE");
  assert.equal(json.reason_code, "VALID_CONDITION");
  assert.equal(json.proof_tx, task.input.proof_tx);
  // Respons harus membawa proof + 13 public signals (wiring server langkah 6).
  assert.ok(json.proof, "respons harus membawa proof");
  assert.ok(Array.isArray(json.public_signals), "respons harus membawa public_signals");
  assert.equal((json.public_signals as string[]).length, 13);
  // Respons harus punya signature HMAC yang valid atas raw body-nya.
  assert.ok(headers["x-agent-games-signature"], "header signature respons harus ada");
  const expected = signBody(TEST_HMAC_SECRET, json).signature;
  assert.equal(headers["x-agent-games-signature"], expected);
});

test("3. Signature salah -> 401 dan tidak ada keputusan", async () => {
  const task = baseTask({ task_id: "gk_test_badsig" });
  const { raw } = signBody(TEST_HMAC_SECRET, task);
  const { status, json } = await postAgent(raw, "00".repeat(32));
  assert.equal(status, 401);
  assert.equal(json.error, "invalid signature");
  assert.equal(json.decision, undefined);
});

test("4. Tiap trap -> REJECT dengan reason_code yang benar", async () => {
  const cases: Array<{ name: string; task: ReturnType<typeof baseTask>; reason: string }> = [
    { name: "VK_SUBSTITUTION", task: baseTask({ task_id: "gk_trap_vk", input: { proof_vk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff" } }), reason: "VK_SUBSTITUTION" },
    { name: "THRESHOLD_MISMATCH", task: baseTask({ task_id: "gk_trap_threshold", input: { public_balance: "500" } }), reason: "THRESHOLD_MISMATCH" },
    { name: "RECIPIENT_MISMATCH", task: baseTask({ task_id: "gk_trap_recipient", input: { recipient: "0x1111000000000000000000000000000000002222" } }), reason: "RECIPIENT_MISMATCH" },
    { name: "AMOUNT_OVERFLOW", task: baseTask({ task_id: "gk_trap_amount", input: { amount: "1500" } }), reason: "AMOUNT_OVERFLOW" },
    { name: "EXPIRED_CONDITION", task: baseTask({ task_id: "gk_trap_expired", input: { current_block: 19850000 } }), reason: "EXPIRED_CONDITION" },
  ];
  for (const c of cases) {
    const { raw, signature } = signBody(TEST_HMAC_SECRET, c.task);
    const { status, json } = await postAgent(raw, signature);
    assert.equal(status, 200, c.name);
    assert.equal(json.decision, "REJECT", c.name);
    assert.equal(json.reason_code, c.reason, c.name);
  }
});

test("5. Replay task_id yang sama -> respons identik (idempotency)", async () => {
  const task = baseTask({ task_id: "gk_test_replay", input: { public_balance: "500" } });
  const { raw, signature } = signBody(TEST_HMAC_SECRET, task);
  const first = await postAgent(raw, signature);
  const second = await postAgent(raw, signature);
  assert.deepEqual(second.json, first.json);
  assert.equal(second.json.reason_code, "THRESHOLD_MISMATCH");
});

test("6. Proof yang sudah DITERIMA lalu dipakai lagi -> PROOF_REUSED", async () => {
  // gk_test_valid (test 2) sudah APPROVE dengan proof_tx 0xa4c1...8ff1.
  const reused = baseTask({ task_id: "gk_test_reuse", input: { proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1" } });
  const { raw, signature } = signBody(TEST_HMAC_SECRET, reused);
  const { status, json } = await postAgent(raw, signature);
  assert.equal(status, 200);
  assert.equal(json.decision, "REJECT");
  assert.equal(json.reason_code, "PROOF_REUSED");
});

test("7. Preflight -> { ok: true, protocolVersion: v1 } dan ditandatangani", async () => {
  const body = { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" };
  const { raw, signature } = signBody(TEST_HMAC_SECRET, body);
  const { status, headers, json } = await postAgent(raw, signature);
  assert.equal(status, 200);
  assert.equal(json.ok, true);
  assert.equal(json.protocolVersion, "v1");
  assert.ok(headers["x-agent-games-signature"]);
});

test("8. Task rusak (input hilang) -> REJECT INVALID_TASK, fail-closed", async () => {
  const body = { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_test_broken", mode: "competition" };
  const { raw, signature } = signBody(TEST_HMAC_SECRET, body);
  const { status, json } = await postAgent(raw, signature);
  assert.equal(status, 200);
  assert.equal(json.decision, "REJECT");
  assert.equal(json.reason_code, "INVALID_TASK");
});

test("9. Artefak circuit asli: VK groth16/bn128/nPublic=13", async () => {
  const info = await verifyCircuitArtifacts();
  assert.equal(info.ok, true, info.detail);
  assert.equal(info.protocol, "groth16");
  assert.equal(info.curve, "bn128");
  assert.equal(info.nPublic, 13);
});

test("10. Kurier tanpa API key -> dilewati, bukan error", async () => {
  const messages: string[] = [];
  const result = await submitProofInBackground({ dummy: true }, ["1", "2"], (m) => messages.push(m));
  assert.equal(result.skipped, true);
  assert.match(result.reason || "", /KURIER_API_KEY/);
});

test("11. Replay practice task asli practice_9e6ef3da -> REJECT + proof valid", async () => {
  // Payload persis seperti yang ditampilkan dashboard "Sanitized Request"
  // pada practice task 2026-11-13 22:17 WIB (task_id + semua field input).
  // issued_at/deadline_at dibuat segar supaya decide() tidak menolak
  // karena deadline asli sudah lewat — yang diuji di sini adalah keputusan
  // dan proof-nya, bukan timestamp aslinya.
  const task = baseTask({
    task_id: "practice_9e6ef3da-ead8-4ccd-b792-51dfcd7cf5cf",
    input: {
      registered_vk: "0x6d79c0012a6d8651f3e13bc4d2a20370280ab49780c99c5316d4168bfbad77b0",
      proof_vk: "0x6c65609f1c56fd1fd4e9737f90d2220f4b95f1d507f1adf6899085bd74be047",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 843000,
      current_block: 842000,
      recipient: "0xabcdef1234567890abcdef1234567890abcdef12",
      condition_recipient: "0xabcdef1234567890abcdef1234567890abcdef12",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0x9e6ef3daead84ccdb79251dfcd7cf5cf",
    },
  });
  // Keputusan harus sama dengan yang dicatat dashboard: REJECT karena
  // proof_vk != registered_vk (VK_SUBSTITUTION); semua cek lain lolos.
  const result = decide(task, () => false);
  assert.equal(result.decision, "REJECT");
  assert.equal(result.reason_code, "VK_SUBSTITUTION");
  // Proof harus berhasil dibuat dan lolos verifikasi Groth16 terhadap
  // verification key circuit resmi (.zkey).
  const t0 = Date.now();
  const generated = await generateDecisionProof(task, "REJECT", 60_000);
  const proofMs = Date.now() - t0;
  assert.equal(generated.publicSignals.length, 13);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const snarkjs = require("snarkjs");
  const vk = await snarkjs.zKey.exportVerificationKey(CIRCUIT_ZKEY_PATH);
  const ok = await snarkjs.groth16.verify(vk, generated.publicSignals, generated.proof);
  assert.equal(ok, true, "proof harus lolos groth16.verify");
  console.log(`   (proof practice task dibuat dalam ${proofMs}ms)`);
});
