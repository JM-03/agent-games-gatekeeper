/**
 * Fixture task sesuai "Sample task payload" di
 * https://agentgames.zkverify.io/events/proof-gatekeeper
 * (nilai contoh 0x7d3a...f291 dll. diganti nilai lengkap yang valid).
 */
import * as crypto from "crypto";
import type { GatekeeperTask } from "../src/decision";

export const TEST_HMAC_SECRET = "test-secret-untuk-test-lokal-saja-jangan-dipakai-produksi";

export function baseTask(overrides: Record<string, unknown> = {}): GatekeeperTask {
  const task: GatekeeperTask = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_test_001",
    mode: "competition",
    issued_at: new Date(Date.now() - 60_000).toISOString(),
    deadline_at: new Date(Date.now() + 50_000).toISOString(),
    input: {
      registered_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
      proof_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0xde4200000000000000000000000000000000009f01",
      condition_recipient: "0xde4200000000000000000000000000000000009f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
    },
  };
  const input = { ...(task.input as Record<string, unknown>), ...((overrides.input as Record<string, unknown>) || {}) };
  const { input: _ignored, ...rest } = overrides as Record<string, unknown>;
  return { ...task, ...rest, input: input as unknown as GatekeeperTask["input"] };
}

export function signBody(secret: string, body: unknown): { raw: string; signature: string } {
  const raw = JSON.stringify(body);
  const signature = crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(raw).digest("hex");
  return { raw, signature };
}
