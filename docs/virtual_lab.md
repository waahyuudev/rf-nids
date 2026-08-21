# Experiment C — Controlled Virtual Laboratory Validation

Experiment C memvalidasi alur end-to-end `capture → CICFlowMeter → feature adapter → FastAPI
→ PostgreSQL → Streamlit`. Eksperimen ini bukan pengganti benchmark Experiment A/B dan tidak
boleh dipakai untuk mengklaim performa produksi.

## Topologi contoh

Gunakan host-only/internal network yang terisolasi. Alamat berikut hanya konfigurasi contoh
development dan boleh diganti dengan alamat private lain:

```text
192.168.56.0/24
├── Ubuntu Target  192.168.56.10
├── Kali Linux     192.168.56.20
└── RF-NIDS        192.168.56.30
```

Jangan hubungkan skenario pembangkitan beban ke bridged/public network. Target yang diizinkan
adalah loopback atau private range `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, dan
`192.168.0.0/16`, pada mesin milik sendiri atau dengan izin tertulis.

## Target Ubuntu sederhana

Di VM target, endpoint statis ringan dapat dibuat dengan `python3 -m http.server 8000
--bind 192.168.56.10`. SSH bersifat opsional dan hanya untuk akun sendiri. Batasi firewall
agar service hanya dapat diakses dari subnet lab.

## Skenario aman

1. **Normal:** ping terbatas, HTTP request/file kecil dari server lokal, serta login SSH akun
   sendiri.
2. **Port Scan:** gunakan pemindai umum hanya ke `192.168.56.10`, pada port/rentang kecil dan
   tanpa opsi stealth, evasion, atau spoofing.
3. **Controlled DDoS-like load:** gunakan load generator HTTP biasa menuju endpoint statis
   lokal. Tetapkan durasi singkat dan concurrency rendah yang telah diuji kemampuan VM-nya;
   hentikan bila target tidak responsif. Ini satu sumber beban terkontrol, bukan distributed
   denial-of-service.

Project sengaja tidak menyediakan otomasi ofensif atau menerima target publik.

## Menjalankan pipeline

CICFlowMeter yang kompatibel harus tersedia sebagai executable. Karena implementasi dan versi
CICFlowMeter berbeda, jalankan audit schema terlebih dahulu pada output CSV nyata:

```bash
python scripts/check_live_feature_compatibility.py --extractor-csv flows.csv
python -m src.ingestion.runner --flow-csv flows.csv --api-url http://localhost:8000
python -m src.ingestion.runner --pcap data/lab/sample.pcap --api-url http://localhost:8000
python -m src.ingestion.runner --interface enp0s8 --api-url http://localhost:8000
```

Mode interface memerlukan izin packet capture. `--flow-csv` adalah jalur paling reproducible.
Runner tidak melakukan inferensi lokal. Kedua fitur `fwd_header_length` dan
`fwd_header_length.1` wajib hadir sendiri-sendiri; adaptor tidak menyalin nilainya. Bila schema
tidak lengkap, klasifikasi dihentikan dan laporan menyebutkan fitur yang hilang.

## Pencatatan hasil

Salin template `reports/metrics/virtual_lab_experiment.json` per run dan isi hanya pengukuran
aktual: jumlah flow, ringkasan prediksi API, latency API/end-to-end, false alert, serta missed
attack. Ground truth per-flow hanya boleh dicatat jika generator menyediakan pemetaan flow
yang dapat diverifikasi. Capture campuran tanpa pemetaan dinyatakan sebagai limitation.

Fingerprint deduplikasi prototype berasal dari metadata waktu/5-tuple dan beberapa counter;
ia bukan fitur ML dan hanya berlaku selama satu proses. Collision serta duplikasi lintas
restart masih merupakan limitation. Dashboard tetap membaca FastAPI/PostgreSQL dan akan
memperbarui total, distribusi, timeline, recent prediction, serta alert sesuai refresh interval.
