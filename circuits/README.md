# Circuit Gatekeeper — file asli dari zkVerify

Diunduh 2026-11-13 dari URL publik di halaman resmi:

- WASM: https://agentgames.zkverify.io/circuits/gatekeeper.wasm
- ZKey: https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
- Info JSON: https://agentgames.zkverify.io/api/circuit-info

## Verifikasi

| File | Ukuran | SHA-256 |
|---|---|---|
| `gatekeeper.wasm` | 1.755.820 byte | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | 309.750 byte | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

Cek ulang dengan: `sha256sum circuits/*`

## Fakta circuit (dari file .zkey asli, via `snarkjs zkey export verificationkey`)

- Protocol: **Groth16**
- Curve: **bn128**
- nPublic: **13** (13 public signal)
- vkHash (mainnet, dari `/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Template di dalam circuit memakai Poseidon (Ark/Mix/PoseidonEx).

## Yang TIDAK ada di sini

Nama sinyal input circuit (file `.sym`) **tidak dipublikasikan** di halaman
resmi. Karena itu pemetaan input -> sinyal circuit belum bisa diisi
(lihat `src/circuit-inputs.ts`). Jangan mengarang nama sinyal — proof yang
dihasilkan dari tebakan tidak akan terverifikasi platform.

Untuk mengunduh ulang (kalau file hilang):

```bash
curl -L -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -L -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
```
