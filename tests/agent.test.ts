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
 *  6. Proof yang sudah diterima lalu dipakai lagi -> PROOF_REUSED, respons
 *     membawa sinyal publik + proof:null (bukan respons kosong — respons
 *     kosong pernah ditolak platform di Ronde 03 -> TIMEOUT).
 *  7. Preflight -> { ok: true, protocolVersion: "v1" } + signed.
 *  8. Task rusak (field hilang) -> REJECT INVALID_TASK (fail-closed).
 *  9. Artefak circuit asli (.zkey) -> VK groth16/bn128/nPublic=13.
 * 10. Kurier tanpa API key -> dilewati (skipped), bukan error.
 * 11. Replay practice task asli (practice_9e6ef3da, 2026-11-13) -> REJECT /
 *     VK_SUBSTITUTION + proof Groth16 yang lolos groth16.verify.
 * 12. Registrasi VK Kurier saat start (tanpa jaringan, register di-mock):
 *     key diset -> tepat 1x register-vk dengan VK hasil export + log sukses;
 *     key kosong -> tidak ada register + log dilewati; gagal 2x lalu sukses
 *     -> 3 percobaan; export VK asli dari .zkey -> groth16/bn128/nPublic=13.
 * 13. Encoding BARU (mod-p + keccak, 2026-11-14): golden values untuk
 *     vkHashToField dan taskIdToField, termasuk reduksi nilai > P.
 * 14. Expiry SAMA DENGAN blok sekarang (current == expiry) -> REJECT /
 *     EXPIRED_CONDITION (circuit hanya menerima current < expiry).
 * 15. Task VALID_CONDITION -> proof Groth16 dengan encoding BARU, lolos
 *     groth16.verify, selfVerified=true, dan public signal taskId sama
 *     dengan keccak256(task_id) % P.
 * 16. buildPublicSignals (fallback saat proof gagal) == sinyal proof asli
 *     [1..12]; [0] placeholder "0" (platform melewati evaluationCommitment).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import { createTestApp } from "../src/server";
import { SeenStore } from "../src/store";
import { verifyCircuitArtifacts, generateDecisionProof, exportVerificationKey } from "../src/proof";
import { submitProofInBackground, registerKurierVkInBackground } from "../src/kurier";
import { decide } from "../src/decision";
import { CIRCUIT_ZKEY_PATH } from "../src/config";
import {
  BN128_FIELD_PRIME,
  vkHashToField,
  taskIdToField,
  buildPublicSignals,
} from "../src/circuit-inputs";
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
  const { status, headers, json } = await postAgent(raw, signature);
  assert.equal(status, 200);
  assert.equal(json.decision, "REJECT");
  assert.equal(json.reason_code, "PROOF_REUSED");
  // Akal PROOF_REUSED (task R03 ke-11 TIMEOUT karena respons tanpa proof
  // ditolak platform): respons harus membawa sinyal publik yang jujur +
  // proof:null eksplisit — bukan respons kosong.
  assert.equal(json.proof, null, "PROOF_REUSED tidak punya proof — harus null eksplisit");
  assert.ok(Array.isArray(json.public_signals), "respons harus membawa public_signals");
  const s = json.public_signals as string[];
  assert.equal(s.length, 13);
  assert.equal(s[0], "0", "index 0 placeholder — platform melewati evaluationCommitment");
  assert.equal(s[1], vkHashToField(reused.input.registered_vk));
  assert.equal(s[2], vkHashToField(reused.input.proof_vk));
  assert.equal(s[3], "1000"); // minimum (fixture)
  assert.equal(s[11], "0", "decision REJECT");
  assert.equal(s[12], taskIdToField("gk_test_reuse"));
  // Respons tetap ditandatangani (signature mencakup body baru).
  assert.ok(headers["x-agent-games-signature"], "header signature respons harus ada");
  const expected = signBody(TEST_HMAC_SECRET, json).signature;
  assert.equal(headers["x-agent-games-signature"], expected);
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

test("12. Registrasi VK Kurier saat start (register di-mock, tanpa jaringan)", async () => {
  const fakeVk = { protocol: "groth16", curve: "bn128", nPublic: 13, vk_alpha_1: ["1", "2"] };
  const prevKey = process.env.KURIER_API_KEY;
  try {
    // 12a. Key diset -> tepat 1x register dengan VK hasil export + log sukses.
    process.env.KURIER_API_KEY = "test-key-123";
    const calls: unknown[] = [];
    const logs: string[] = [];
    const res = await registerKurierVkInBackground((m) => logs.push(m), {
      exportVk: async () => fakeVk,
      register: async (vk) => {
        calls.push(vk);
        return { vkHash: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0", raw: {} };
      },
      delayMs: 0,
    });
    assert.equal(calls.length, 1, "register harus dipanggil tepat sekali");
    assert.deepEqual(calls[0], fakeVk, "register harus menerima VK hasil export");
    assert.equal(res.registered, true);
    assert.equal(res.skipped, false);
    assert.equal(res.attempts, 1);
    assert.match(logs.join("\n"), /VK terdaftar, vkHash=0x6b79/);

    // 12b. Key kosong -> tidak ada register + log dilewati.
    process.env.KURIER_API_KEY = "";
    const calls2: unknown[] = [];
    const logs2: string[] = [];
    const res2 = await registerKurierVkInBackground((m) => logs2.push(m), {
      exportVk: async () => fakeVk,
      register: async (vk) => {
        calls2.push(vk);
        return { vkHash: "0x00", raw: {} };
      },
      delayMs: 0,
    });
    assert.equal(calls2.length, 0, "tanpa API key, register tidak boleh dipanggil");
    assert.equal(res2.skipped, true);
    assert.equal(res2.registered, false);
    assert.match(logs2.join("\n"), /dilewati: KURIER_API_KEY belum diset/);

    // 12c. Gagal 2x lalu sukses -> 3 percobaan, akhirnya terdaftar.
    process.env.KURIER_API_KEY = "test-key-123";
    let failing = 0;
    const logs3: string[] = [];
    const res3 = await registerKurierVkInBackground((m) => logs3.push(m), {
      exportVk: async () => fakeVk,
      register: async () => {
        failing++;
        if (failing < 3) throw new Error("Kurier 503: boom");
        return { vkHash: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0", raw: {} };
      },
      delayMs: 0,
    });
    assert.equal(failing, 3, "harus retry sampai 3x");
    assert.equal(res3.registered, true);
    assert.equal(res3.attempts, 3);
    assert.match(logs3.join("\n"), /percobaan 1\/3/);
    assert.match(logs3.join("\n"), /percobaan 2\/3/);
  } finally {
    process.env.KURIER_API_KEY = prevKey;
  }

  // 12d. Export VK asli dari .zkey -> groth16/bn128/nPublic=13 (jalur
  // default yang dipakai saat start di produksi).
  const realVk = (await exportVerificationKey()) as {
    protocol: string;
    curve: string;
    nPublic: number;
  };
  assert.equal(realVk.protocol, "groth16");
  assert.equal(realVk.curve, "bn128");
  assert.equal(realVk.nPublic, 13);
});

test("13. Encoding BARU: vk BigInt % P, taskId keccak256 % P (golden values)", async () => {
  // Prima field bn128 (BN254) — sama dengan yang dipakai snarkjs/circom.
  assert.equal(
    BN128_FIELD_PRIME.toString(),
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
  );
  // vk hash resmi Gatekeeper (0x6b79...): BigInt % P.
  assert.equal(
    vkHashToField("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
    "4836144126773920907502496244340012141761656471453348073975163706578152814510"
  );
  // vk fixture (0x7d3a...f291): BigInt % P.
  assert.equal(
    vkHashToField("0x7d3a00000000000000000000000000000000000000000000000000000000f291"),
    "12865097458986894393288539788301931603300749965206523872066043227887187849871"
  );
  // taskId: UUID tail (128-bit) bila ada, fallback keccak256(UTF-8) % P.
  assert.equal(
    taskIdToField("gk_test_001"),
    "12285206862557242059294343006181173650373945713092228825753519331833957760831"
  );
  assert.equal(
    taskIdToField("practice_9e6ef3da-ead8-4ccd-b792-51dfcd7cf5cf"),
    "210594121958409637393372948959189595599"
  );
  // Reduksi benar-benar terjadi untuk nilai > P (0xff..ff 32 byte).
  assert.equal(
    vkHashToField("0x" + "ff".repeat(32)),
    ((2n ** 256n - 1n) % BN128_FIELD_PRIME).toString()
  );
  // Semua hasil harus < P (field element valid).
  for (const v of [
    vkHashToField("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
    taskIdToField("gk_test_001"),
  ]) {
    assert.ok(BigInt(v) < BN128_FIELD_PRIME, "hasil encoding harus < P");
  }
});

test("14. Expiry SAMA DENGAN blok sekarang -> REJECT EXPIRED_CONDITION", async () => {
  // current_block == expiry_block: circuit hanya menerima current < expiry.
  const equal = baseTask({
    task_id: "gk_test_expiry_equal",
    input: { current_block: 19842201 },
  });
  const result = decide(equal, () => false);
  assert.equal(result.decision, "REJECT");
  assert.equal(result.reason_code, "EXPIRED_CONDITION");
  // Satu blok sebelum expiry masih valid (bukan expired).
  const before = baseTask({
    task_id: "gk_test_expiry_before",
    input: { current_block: 19842200 },
  });
  const resultBefore = decide(before, () => false);
  assert.equal(resultBefore.decision, "APPROVE");
  assert.equal(resultBefore.reason_code, "VALID_CONDITION");
});

test("15. Task VALID_CONDITION -> proof dengan encoding BARU, verify OK", async () => {
  // max_transfer dibedakan dari minimum (2000 vs 1000) supaya urutan
  // publicSignals bisa dibedakan posisi per posisi.
  const task = baseTask({ task_id: "gk_test_valid_proof", input: { max_transfer: "2000" } });
  assert.equal(decide(task, () => false).decision, "APPROVE");
  const t0 = Date.now();
  const generated = await generateDecisionProof(task, "APPROVE", 60_000);
  const proofMs = Date.now() - t0;
  assert.equal(generated.publicSignals.length, 13);
  assert.equal(generated.selfVerified, true, "proof harus lolos self-verify lokal");
  // Verifikasi independen dengan VK resmi (bukan hanya self-verify internal).
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const snarkjs = require("snarkjs");
  const vk = await snarkjs.zKey.exportVerificationKey(CIRCUIT_ZKEY_PATH);
  const ok = await snarkjs.groth16.verify(vk, generated.publicSignals, generated.proof);
  assert.equal(ok, true, "proof VALID harus lolos groth16.verify");
  // Layout publicSignals (TERBUKTI lewat dump proof lokal — lihat header
  // src/circuit-inputs.ts): [0]=evaluationCommitment, [1]=registeredVkHash,
  // [2]=proofVkHash, [3]=minimum, [4]=publicBalance, [5]=expiryBlock,
  // [6]=currentBlock, [7]=recipient, [8]=conditionRecipient, [9]=amount,
  // [10]=maxTransfer, [11]=decision, [12]=taskId.
  const s = generated.publicSignals;
  assert.equal(s[1], vkHashToField(task.input.registered_vk));
  assert.equal(s[2], vkHashToField(task.input.proof_vk));
  assert.equal(s[3], "1000"); // minimum
  assert.equal(s[4], "1460"); // publicBalance
  assert.equal(s[5], "19842201"); // expiryBlock
  assert.equal(s[6], "19832000"); // currentBlock
  assert.equal(s[7], BigInt(task.input.recipient).toString()); // recipient
  assert.equal(s[8], BigInt(task.input.condition_recipient).toString()); // conditionRecipient
  assert.equal(s[9], "500"); // amount
  assert.equal(s[10], "2000"); // maxTransfer (bukan minimum — dibedakan di sini)
  assert.equal(s[11], "1"); // decision APPROVE
  assert.equal(s[12], taskIdToField(task.task_id)); // taskId = keccak256 % P
  // signal[0] = evaluationCommitment (dihitung circuit dari input + salt):
  // field element valid, dan BUKAN salah satu nilai input task.
  assert.ok(BigInt(s[0]) < BN128_FIELD_PRIME, "signal[0] harus < P");
  assert.notEqual(s[0], s[1]);
  assert.notEqual(s[0], s[12]);
  console.log(`   (proof VALID dengan encoding baru dibuat dalam ${proofMs}ms)`);
});

test("16. buildPublicSignals == sinyal proof asli [1..12] (fallback jujur)", async () => {
  // Sinyal fallback harus sama persis dengan sinyal dari proof Groth16 yang
  // berhasil dibuat untuk task + keputusan yang sama — kecuali [0]
  // (evaluationCommitment, hanya bisa dihitung circuit; platform melewatinya).
  const task = baseTask({ task_id: "gk_test_valid_proof", input: { max_transfer: "2000" } });
  const generated = await generateDecisionProof(task, "APPROVE", 60_000);
  const fallback = buildPublicSignals(task, "APPROVE");
  assert.equal(fallback.length, 13);
  assert.equal(fallback[0], "0", "index 0 placeholder — platform melewati evaluationCommitment");
  for (let i = 1; i < 13; i++) {
    assert.equal(fallback[i], generated.publicSignals[i], `signal[${i}] fallback harus sama dengan proof asli`);
  }
  // Dan untuk REJECT: [11] harus "0", sisanya sama dengan task.
  const rej = buildPublicSignals(task, "REJECT");
  assert.equal(rej[11], "0");
  assert.equal(rej[12], taskIdToField(task.task_id));
  assert.equal(rej[1], vkHashToField(task.input.registered_vk));
});
