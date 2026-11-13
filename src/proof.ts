/**
 * Pembuatan proof Groth16 lokal (snarkjs) + info circuit.
 * Sumber: https://agentgames.zkverify.io/build
 * "Download the proving key (.zkey) and WASM file for the event you are
 *  entering, generate proofs locally with snarkjs, and include the proof
 *  in your response."
 */

import * as fs from "fs";
import { CIRCUIT_WASM_PATH, CIRCUIT_ZKEY_PATH, CIRCUIT_INFO } from "./config";
import {
  buildCircuitInputs,
  CIRCUIT_INPUTS_CONFIGURED,
  CircuitInputMappingNotConfigured,
} from "./circuit-inputs";
import type { GatekeeperTask, Decision } from "./decision";

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
}

export interface CircuitInfo {
  protocol: string;
  curve: string;
  nPublic: number;
  vkHash: string;
  wasmPresent: boolean;
  zkeyPresent: boolean;
}

export function getCircuitInfo(): CircuitInfo {
  return {
    protocol: CIRCUIT_INFO.protocol,
    curve: CIRCUIT_INFO.curve,
    nPublic: CIRCUIT_INFO.nPublic,
    vkHash: CIRCUIT_INFO.vkHash,
    wasmPresent: fs.existsSync(CIRCUIT_WASM_PATH),
    zkeyPresent: fs.existsSync(CIRCUIT_ZKEY_PATH),
  };
}

/** Ekstrak verification key dari .zkey dan cek konsistensinya dengan
 *  fakta publik (groth16 / bn128 / nPublic 13). Dipakai di /health dan test. */
export async function verifyCircuitArtifacts(): Promise<{
  ok: boolean;
  protocol: string;
  curve: string;
  nPublic: number;
  detail: string;
}> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const snarkjs = require("snarkjs");
  const vk = await snarkjs.zKey.exportVerificationKey(CIRCUIT_ZKEY_PATH);
  const ok =
    vk.protocol === CIRCUIT_INFO.protocol &&
    vk.curve === CIRCUIT_INFO.curve &&
    vk.nPublic === CIRCUIT_INFO.nPublic;
  return {
    ok,
    protocol: String(vk.protocol),
    curve: String(vk.curve),
    nPublic: Number(vk.nPublic),
    detail: ok
      ? "VK cocok dengan fakta publik (groth16/bn128/nPublic=13)"
      : `VK TIDAK COCOK: ${vk.protocol}/${vk.curve}/nPublic=${vk.nPublic}`,
  };
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<T>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timeout setelah ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * Buat proof untuk satu keputusan.
 * - Kalau pemetaan input belum diisi -> throw CircuitInputMappingNotConfigured
 *   (pemanggil HARUS menangkap ini dan tetap mengirim keputusan tanpa proof).
 * - fullProve dibatasi PROOF_TIMEOUT_MS supaya tidak melewati deadline 60 detik.
 */
export async function generateDecisionProof(
  task: GatekeeperTask,
  decision: Decision,
  proofTimeoutMs: number
): Promise<GeneratedProof> {
  if (!CIRCUIT_INPUTS_CONFIGURED) {
    throw new CircuitInputMappingNotConfigured();
  }
  if (!fs.existsSync(CIRCUIT_WASM_PATH) || !fs.existsSync(CIRCUIT_ZKEY_PATH)) {
    throw new Error("File circuit tidak ditemukan di circuits/ (wasm/zkey).");
  }
  const input = buildCircuitInputs(task, decision);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const snarkjs = require("snarkjs");
  const result = (await withTimeout(
    snarkjs.groth16.fullProve(input, CIRCUIT_WASM_PATH, CIRCUIT_ZKEY_PATH),
    proofTimeoutMs,
    "snarkjs fullProve"
  )) as { proof: unknown; publicSignals: unknown[] };
  const { proof, publicSignals } = result;
  return { proof, publicSignals: publicSignals.map(String) };
}
