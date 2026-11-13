# Agent Gatekeeper — zkVerify Agent Games

Agent untuk track **Proof Gatekeeper**. Agent ini menerima task dari platform,
memutuskan **APPROVE / REJECT** dengan 7 cek deterministik, dan mengembalikan
keputusan yang ditandatangani HMAC — dalam batas 60 detik, dan kalau ragu
sedikit pun: **REJECT** (fail-closed).

> Project ini terpisah dari project-project lain. Isinya hanya Agent Games.

Sumber resmi yang dipakai (dibaca 2026-11-13):

- https://agentgames.zkverify.io/build
- https://agentgames.zkverify.io/guide
- https://agentgames.zkverify.io/rules
- https://agentgames.zkverify.io/events/proof-gatekeeper
- https://agentgames.zkverify.io/api/circuit-info
- https://docs.zkverify.io/handbook/quickstart (Kurier)

## Jadwal yang perlu diingat

- Ronde: **13–21 Nov 2026**, 1 ronde per hari, **8 task per agent per ronde**,
  jam **16:00–02:00 IST = 17:30–03:30 WIB**, skor kumulatif.
- Round 01 (13 Nov) sudah LIVE saat agent ini dibuat — ronde 02–08 masih
  tersisa (14–20 Nov). Skor kumulatif, jadi start telat = ketinggalan poin.
- Hadiah per track: 100.000 VFY (juara 1: 50.000, 2: 30.000, 3: 20.000).
- Skor per keputusan: APPROVE benar +12, REJECT benar +12, APPROVE salah -6,
  REJECT salah -3, timeout -2, proof tidak valid -2, plus reliability bonus
  +0 s.d. +5 per ronde.

## Yang sudah jadi (di repo ini)

| Bagian | Status |
|---|---|
| `POST /agent` — terima task Gatekeeper + preflight | ✅ jadi |
| `GET /health` — cek hidup + info circuit | ✅ jadi |
| Verifikasi HMAC (`x-agent-games-signature`) atas raw body, sebelum parse JSON | ✅ jadi |
| Tanda tangan HMAC untuk semua respons | ✅ jadi |
| Logika keputusan 7 cek (lihat bawah) — deterministik | ✅ jadi |
| Idempotency: task_id yang sama -> respons yang sama | ✅ jadi |
| Anti-reuse: proof yang sudah DITERIMA tidak bisa dipakai lagi | ✅ jadi |
| Fail-closed: task rusak / deadline lewat / ragu -> REJECT | ✅ jadi |
| Batas waktu internal 55 detik (di bawah deadline platform 60 detik) | ✅ jadi |
| Circuit asli diunduh (`circuits/gatekeeper.wasm` + `gatekeeper_final.zkey`, vkHash terverifikasi) | ✅ jadi |
| Wiring snarkjs `fullProve` + cek artefak circuit (test no. 9) | ✅ jadi |
| Client Kurier: `register-vk`, `submit-proof`, `job-status` sampai Finalized | ✅ jadi (kode) |
| Dockerfile + `railway.json` (deploy Railway) | ✅ jadi |
| Test lokal: 10 test, semua lolos (lihat bawah) | ✅ jadi |

### 7 cek keputusan (Trap Encyclopedia, halaman event)

1. `VALID_CONDITION` — semua lolos -> **APPROVE**
2. `VK_SUBSTITUTION` — proof_vk beda dengan registered_vk -> REJECT
3. `THRESHOLD_MISMATCH` — public_balance < minimum -> REJECT
4. `PROOF_REUSED` — proof_tx sudah pernah DITERIMA -> REJECT
5. `EXPIRED_CONDITION` — current_block > expiry_block -> REJECT
6. `RECIPIENT_MISMATCH` — recipient beda dengan condition_recipient -> REJECT
7. `AMOUNT_OVERFLOW` — amount > max_transfer -> REJECT

Plus: task yang strukturnya rusak / timestamp tidak valid -> REJECT
`INVALID_TASK`.

## Yang BELUM selesai — baca ini dulu

### 1. Pemetaan input circuit (TODO paling penting)

File circuit asli sudah ada dan terverifikasi (Groth16/bn128, nPublic=13),
tapi **nama sinyal input circuit tidak dipublikasikan** di halaman resmi
yang saya baca (file `.sym` tidak disediakan). Karena itu fungsi
`buildCircuitInputs()` di `src/circuit-inputs.ts` masih melempar error
yang jelas, dan agent mengirim keputusan **tanpa field proof**.

Akibatnya (jujur, sesuai halaman event): keputusan benar tetap +12, tapi
ada penalti **-2 per task** ("Missing / invalid proof") dan **tidak ada
reliability bonus**.

Cara mengisi TODO ini:

1. Jalankan satu **practice task** dari dashboard — practice formatnya sama
   dengan scored task. Perhatikan apakah platform menampilkan
   `public_signals` yang diharapkan.
2. Atau tanya di Discord resmi zkVerify: https://discord.gg/zkverify —
   tanyakan: *"What are the input signal names and public input layout of
   the gatekeeper circuit (gatekeeper.wasm / gatekeeper_final.zkey,
   nPublic=13)?"*
3. Atau cek "protocol documentation" yang dirujuk halaman `/build`.

Setelah dapat jawabannya: isi `buildCircuitInputs()` di
`src/circuit-inputs.ts`, ubah `CIRCUIT_INPUTS_CONFIGURED` menjadi `true`,
lalu jalankan `npm test`.

### 2. Yang harus dilakukan Elgi sendiri (tidak bisa diwakilkan)

- [ ] Buat repo di GitHub **JM-03** dan upload isi folder ini
      (jangan upload file `.env` — hanya `.env.example`).
- [ ] Minta **Kurier API key (mainnet)** di https://kurier.xyz
      (tanpa ini, submit Kurier dilewati — agent tetap menjawab task).
- [ ] Deploy ke **Railway** (langkah di bawah) dan isi env var di Railway:
      `AGENT_GAMES_HMAC_SECRET` dan `KURIER_API_KEY`.
- [ ] Di dashboard Agent Games, daftarkan agent: isi **Agent Name**,
      pilih track **Proof Gatekeeper**, isi **Repository URL** (repo JM-03),
      isi **Agent Endpoint** (URL Railway, contoh:
      `https://namamu.up.railway.app/agent`).
      Saat registrasi, platform membuat **HMAC secret 32-byte yang
      ditampilkan SEKALI** — salin secret itu ke env var Railway
      `AGENT_GAMES_HMAC_SECRET`. Kalau hilang, pakai "Rotate Secret" di
      dashboard dan update env var-nya.
- [ ] Jalankan **preflight + minimal 1 practice task** dari dashboard,
      cek log Railway: harus muncul `preflight -> ok` dan keputusan
      APPROVE/REJECT yang benar.
- [ ] Kalau pemetaan circuit sudah didapat (TODO no. 1), isi dan deploy ulang.
- [ ] Catatan: tidak ada kolom wallet di dashboard (dicek 2026-11-13) —
      situsnya bilang detail payout dikumpulkan langsung dari pemenang
      setelah kompetisi tutup.

## Cara jalanin lokal (test)

```bash
cd agent-games-gatekeeper
npm install
npm test        # 10 test lokal
npm run build   # compile TypeScript -> dist/
npm start       # jalan di http://localhost:3000
```

Test butuh `AGENT_GAMES_HMAC_SECRET` — file test memakai secret khusus
test di `tests/fixtures.ts`, bukan secret asli.

## Cara deploy ke Railway (langkah demi langkah)

1. Di https://railway.app — login pakai GitHub JM-03, buat project baru,
   pilih **Deploy from GitHub repo**, pilih repo agent ini.
   (Railway akan memakai `Dockerfile` di repo ini.)
2. Setelah deploy pertama selesai, buka tab **Variables** di Railway,
   isi:
   - `AGENT_GAMES_HMAC_SECRET` = secret dari dashboard Agent Games
   - `KURIER_API_KEY` = API key dari https://kurier.xyz
   - (yang lain sudah punya default yang benar — lihat `.env.example`)
3. Buka tab **Settings** -> **Networking** -> **Generate Domain**,
   catat URL publiknya, contoh `https://xxx.up.railway.app`.
4. Cek `https://xxx.up.railway.app/health` di browser — harus tampil
   `{"ok":true, ...}`.
5. Daftarkan endpoint di dashboard Agent Games:
   `https://xxx.up.railway.app/agent`
6. Jalankan preflight + practice task dari dashboard. Cek log Railway
   (tab **Deployments** -> **View Logs**).

**Peringatan uptime (Rules 1.4):** kalau agent offline saat task datang,
task itu hangus (-2). Jangan pakai hosting gratis yang "tidur" kalau
tidak ada traffic — Railway free tier bisa sleep; kalau ronde terlewat
karena sleep, itu risikonya.

## File di repo ini

```
agent-games-gatekeeper/
├── src/
│   ├── index.ts            # entry point
│   ├── server.ts           # Express: POST /agent, GET /health, preflight
│   ├── config.ts           # env var + konstanta publik (vkHash, URL Kurier)
│   ├── hmac.ts             # verifikasi + tanda tangan HMAC-SHA256
│   ├── decision.ts         # logika 7 cek (deterministik)
│   ├── store.ts            # idempotency + anti-reuse (file JSON)
│   ├── proof.ts            # snarkjs fullProve + cek artefak circuit
│   ├── circuit-inputs.ts   # *** TODO: pemetaan input circuit ***
│   └── kurier.ts           # client Kurier (register-vk/submit/job-status)
├── tests/
│   ├── agent.test.ts       # 10 test
│   └── fixtures.ts         # contoh task per trap (dari halaman event)
├── circuits/
│   ├── gatekeeper.wasm     # asli, dari agentgames.zkverify.io
│   ├── gatekeeper_final.zkey
│   └── README.md           # sha256 + cara unduh ulang
├── Dockerfile
├── railway.json
├── .env.example            # daftar env var (KOSONG — isi sendiri)
├── .gitignore
├── package.json
├── tsconfig.json
└── README.md               # file ini
```

## Keputusan desain yang perlu diketahui

- **Kurier di-background, bukan sebelum respons.** Polling sampai
  `Finalized` bisa lebih lama dari deadline 60 detik, jadi proof disubmit
  ke Kurier SETELAH respons terkirim. Platform memverifikasi ulang proof
  dengan VK-nya sendiri.
- **Format signature HMAC:** hex HMAC-SHA256 dari raw body. Saat verifikasi,
  format `sha256=<hex>` juga diterima. Kalau practice run menolak signature,
  ini hal pertama yang dicek.
- **Seen-set disimpan di file `data/seen.json`.** Kalau deployment Railway
  dibuat ulang tanpa volume, file ini hilang dan proteksi PROOF_REUSED
  mulai dari nol. Untuk produksi idealnya Redis/Postgres.
- **Tidak ada secret apa pun di repo ini.** Semua secret hanya dari env var.

## Yang TIDAK dilakukan di sini

- Tidak deploy / register / submit apa pun atas nama Elgi.
- Tidak meminta, memakai, atau menyimpan seed phrase, private key,
  API key, atau HMAC secret asli.
- Tidak ada klaim agent sudah live, sudah terdaftar, atau akan menang.
- Tidak ada nilai yang dikarang: vkHash, URL Kurier, dan artefak circuit
  semuanya dari halaman resmi (lihat `circuits/README.md`).
