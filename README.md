# RF-NIDS

RF-NIDS adalah prototipe penelitian *Network Intrusion Detection System* berbasis Random
Forest untuk mengklasifikasikan flow jaringan sebagai `Normal`, `DDoS`, atau `PortScan`.

Project ini mencakup pipeline eksperimen, inference tervalidasi, ingestion PCAP/live capture,
FastAPI, PostgreSQL, alert, ekspor evidence, dan dashboard Streamlit. Implementasi aplikasi
tesis dibekukan pada 2 September 2026; artefak ilmiah yang telah dibekukan tidak boleh
dilatih ulang atau diubah tanpa membuka kembali protokol eksperimen.

> **Peringatan penelitian:** evaluasi eksternal menunjukkan keterbatasan generalisasi yang
> serius, terutama untuk DDoS. Project ini adalah prototipe laboratorium/tesis, bukan IDS
> production-ready dan bukan sistem pencegahan intrusi.

## Fitur utama

- Training Random Forest baseline dan hyperparameter tuning pada CICIDS2017.
- Validasi skenario dan evaluasi eksternal tanpa refit.
- Model RF-v2 hasil adaptation experiment dengan artefak dan hash yang dibekukan.
- Inference 78 fitur dengan validasi schema, urutan fitur, dan hash model.
- Ingestion offline PCAP dan live traffic macOS melalui CICFlowMeter V3.
- Penyimpanan flow, prediction, dan alert secara transaksional di PostgreSQL.
- Alert deterministik: `DDoS` → `HIGH`, `PortScan` → `MEDIUM`, `Normal` → tanpa alert.
- Login administrator, sesi Bearer, dan audit acknowledgement alert.
- Dashboard dataset, model, evaluation, monitoring, predictions, alerts, dan export.
- Evidence sync read-only yang memverifikasi hash laporan eksperimen.

## Arsitektur

Runtime detection:

```text
PCAP / macOS interface
  → CICFlowMeter V3 (84 kolom mentah)
  → closed feature adapter (78 fitur terurut)
  → FastAPI → frozen preprocessing + Random Forest
  → PostgreSQL (flow + prediction + optional alert)
  → Streamlit dashboard
```

Historical evaluation dipisahkan dari runtime detection:

```text
Frozen report A/B/C/D → hash-verifying evidence sync
  → PostgreSQL presentation records → authenticated API/export → Streamlit
```

Experiment C tidak dimasukkan sebagai runtime traffic. Dashboard tidak membaca model,
report, atau database secara langsung; seluruh data disediakan oleh FastAPI.

## Technology stack

- Python 3.11+ (image aplikasi menggunakan Python 3.12)
- scikit-learn, pandas, NumPy, Joblib
- FastAPI, Uvicorn, Streamlit
- SQLAlchemy, Alembic, PostgreSQL 16
- Docker Compose dan CICFlowMeter V3

## Quick start — Ubuntu NIDS

FastAPI dan PostgreSQL tetap berjalan di Docker Compose. Streamlit berjalan di
host Ubuntu dan mengakses API pada port 8000. Ikuti
[panduan Docker runtime monitoring](docs/docker_runtime_monitoring.md) untuk
setup satu kali: direktori runtime milik UID 10001, `RUNTIME_MONITORING_HOST_ROOT`,
`DOCKER_SOCKET_GID`, dan verifikasi image CICFlowMeter V3 yang sudah dipin.
Simpan konfigurasi tersebut dalam `.env` yang ada; jangan menimpa atau commit `.env`.

Setelah setup, jalankan dari direktori repository yang sama:

```bash
docker compose build
docker compose up -d
```

Migration tetap menggunakan `postgres:5432`; API dengan Linux host networking
menggunakan `127.0.0.1:5432`. Volume PostgreSQL yang ada tetap dipakai.
Jangan menjalankan `docker compose down -v`.

Gunakan instalasi Streamlit host yang ada:

```bash
FASTAPI_BASE_URL=http://127.0.0.1:8000 .venv/bin/streamlit run dashboard/app.py
```

Virtual environment hanya diperlukan untuk Streamlit/tools host, bukan untuk
menjalankan FastAPI. Login dengan administrator yang sudah ada. Untuk instalasi
baru saja, administrator pertama dapat dibuat melalui `scripts/bootstrap_admin.py`.

- API: <http://localhost:8000>
- OpenAPI: <http://localhost:8000/docs>
- Dashboard: <http://localhost:8501>

Pada Monitoring, pilih target `10.10.20.2` dan interface `enp0s3`, lalu klik
**START MONITORING**. Panduan deployment memuat perintah validasi traffic, PCAP,
ekstraksi, prediksi, alert, Stop, dan Runtime Validation. Capture jaringan host
Ubuntu tidak dapat dibuktikan lewat Docker Desktop/macOS.

## Konfigurasi penting

| Variable | Default | Fungsi |
|---|---|---|
| `DATABASE_URL` | PostgreSQL localhost | Koneksi API/Alembic |
| `MODEL_PATH` | RF-v2 Experiment D | Model runtime aktif |
| `MODEL_METADATA_PATH` | metadata runtime RF-v2 | Schema, versi, dan hash model |
| `MAX_BATCH_SIZE` | `1000` | Batas batch inference |
| `MAX_PAGE_SIZE` | `100` | Batas pagination API |
| `AUTH_SESSION_HOURS` | `8` | Masa berlaku sesi administrator |
| `FASTAPI_BASE_URL` | `http://localhost:8000` | URL API dashboard/ingestion |
| `DASHBOARD_REFRESH_SECONDS` | `5` | Interval auto-refresh dashboard |
| `RUNTIME_MONITORING_ROOT` | `data/runtime/monitoring` | Tree khusus evidence runtime; tidak boleh diarahkan ke evidence ilmiah |
| `RUNTIME_MONITORING_HOST_ROOT` | wajib di Compose | Path absolut host untuk bind PCAP/CSV oleh Docker daemon |
| `DOCKER_SOCKET_GID` | wajib di Compose | GID socket Docker host untuk API UID 10001 |
| `CICFLOWMETER_V3_IMAGE_DIGEST` | digest V3 teraudit | Identitas image yang wajib cocok saat preflight |
| `EXTRACTION_TIMEOUT_SECONDS` | `120` | Batas waktu ekstraksi setiap window |
| `RF_NIDS_CAPTURE_INTERFACE` | `en0` | Interface default capture macOS |
| `LIVE_FEATURE_COMPATIBILITY_POLICY` | artifact reproduction | Policy adapter 78 fitur |

Lihat [.env.example](.env.example) untuk daftar lengkap.

## Dashboard dan autentikasi

Pengguna yang belum login hanya melihat Login. Administrator memiliki tujuh halaman:

1. **Dashboard** — ringkasan dan timeline runtime.
2. **Dataset** — metadata dataset, provenance, dan export.
3. **Models** — model aktif, parameter, dan informasi training.
4. **Evaluation** — evidence Experiment A/B/C dan confusion matrix.
5. **Monitoring** — agregasi dan filter traffic flow runtime.
6. **Predictions** — daftar, detail, filter, dan export prediction.
7. **Alerts** — daftar, detail, acknowledge, dan export alert.

Sesi disimpan di memory proses API. Restart API membatalkan seluruh sesi; desain ini cocok
untuk prototipe lokal, bukan deployment multi-worker.

## API

Endpoint publik/trusted-local:

- `GET /health`
- `POST /api/auth/login`
- `POST /api/predict`
- `POST /api/predict/batch`

Endpoint lain membutuhkan Bearer token administrator, termasuk dataset, model, experiment,
evaluation, monitoring, predictions, alerts, dashboard summary, acknowledgement, dan export.
Daftar dan schema lengkap tersedia di `/docs`.

Endpoint inference sengaja tidak diautentikasi karena digunakan collector pada boundary
laboratorium lokal tepercaya. Tambahkan machine authentication dan network isolation sebelum
mengekspos service ke jaringan lain.

Objek `features` pada request inference wajib memuat tepat 78 fitur sesuai metadata runtime.
Fitur kurang atau asing ditolak dengan status `422`; IP, port, protocol, session, dan waktu
capture disimpan sebagai metadata terpisah dan tidak menjadi input model.

## Dataset dan training RF-v1

Letakkan CSV berlabel di `data/raw/`, kemudian inspeksi dataset:

```bash
python -m src.data.inspect_dataset \
  --input data/raw/dataset.csv \
  --label-column label
```

Untuk beberapa file dengan schema sama:

```bash
python -m src.data.inspect_dataset \
  --input data/raw/cicids2017/file-ddos.csv \
          data/raw/cicids2017/file-portscan.csv \
  --label-column label
```

Label dipetakan case-insensitive: `BENIGN`/`Normal` → `Normal`, label yang mengandung
`ddos` → `DDoS`, dan `portscan`/`port scan` → `PortScan`. Kelas lain dikeluarkan dan dicatat.

Jalankan baseline, tuning, validasi skenario, lalu pemilihan model:

```bash
python -m src.training.train_baseline
python -m src.training.train_tuned --iterations 20 --cv 5 --tuning-sample-size 50000
python -m src.evaluation.scenario_validation
python -m src.evaluation.compare_models
```

Preprocessing mengganti infinity menjadi `NaN`, menghapus duplicate dan kandidat leakage,
serta memilih fitur numerik. Median imputer berada di dalam scikit-learn Pipeline dan hanya
di-fit pada training split. Jangan menilai model dari accuracy saja; tinjau macro F1, recall
tiap serangan, dan false-positive terhadap traffic normal.

## Ringkasan eksperimen

- **Experiment A:** stratified random split 80/20 untuk baseline utama.
- **Experiment B:** holdout blok kontigu per `source_file × class` sebagai scenario stress test.
- **Experiment C:** evaluasi eksternal tanpa refit; model gagal menggeneralisasi terhadap
  traffic serangan baru (Normal 61/61, DDoS 0/10.226, PortScan 0/1.000).
- **Experiment D:** adaptation experiment yang membandingkan RF-v1 dan RF-v2 pada final test
  satu kali, tanpa resampling atau threshold selection.

Pada final test Experiment D (15.949 flow), RF-v2 meningkatkan macro F1 dari `0.0028` menjadi
`0.3768` dan recall PortScan menjadi `0.9680`, tetapi recall DDoS tetap rendah (`0.0769`).
Distribusi final test sangat tidak seimbang (15.482 DDoS, 437 PortScan, 30 Normal), sehingga
hasil harus dibaca bersama confusion matrix dan batasan desain eksperimen.

Detail tersedia di [protokol Experiment D](docs/experiment_d_protocol.md) dan
`reports/experiment_d/`.

## Offline PCAP validation

```bash
docker compose build cicflowmeter
docker compose up -d --build
python scripts/run_offline_pcap_validation.py \
  --pcap data/lab/pcap/sample.pcap
```

Untuk memakai CSV hasil ekstraksi tanpa menjalankan extractor lagi:

```bash
python scripts/run_offline_pcap_validation.py \
  --flow-csv data/lab/flows/sample.csv
```

Report ditulis ke `reports/metrics/offline_pcap_validation.json`. Ini memvalidasi fungsi
pipeline, bukan mengukur akurasi ilmiah.

## Live normal traffic validation (macOS)

```bash
python scripts/run_live_capture.py --list-interfaces
sudo -v
docker compose up -d --build
python scripts/run_live_capture.py \
  --interface <interface> \
  --segment-seconds 15 \
  --max-segments 4
```

`tcpdump` berjalan pada host macOS, sedangkan ekstraksi flow berjalan di Docker. Evidence
lokal disimpan di `data/lab/live/<session-id>/`; report gate disimpan di
`reports/metrics/live_normal_validation.json`. Tanpa `--max-segments`, capture berjalan hingga
`Ctrl+C`.

Gunakan hanya traffic normal pada jaringan milik sendiri atau yang memiliki izin. Jangan
menjalankan scanning, flooding, atau simulasi serangan pada jaringan publik.

## Pengujian

```bash
pytest
```

Test API menggunakan SQLite temporer dan model deterministik sehingga tidak memerlukan
CICIDS2017 atau PostgreSQL aktif. Catatan freeze terakhir mendokumentasikan 156 test otomatis
dan 24 black-box case yang lulus; jumlah test dapat berubah jika suite dikembangkan.

## Struktur repository

```text
config/                  konfigurasi leakage dan experiment
dashboard/               aplikasi dan halaman Streamlit
data/                    raw, processed, external, dan lab evidence
docs/                    protokol, phase record, dan evidence tesis
migrations/              migration Alembic
models/                  model RF-v1/RF-v2 dan metadata
reports/                 metrics, tables, audit, dan comparison
scripts/                 entry point eksperimen, capture, audit, dan sync
src/api/                 FastAPI, auth, persistence, alert, dan export
src/application/         evidence synchronization
src/data/                loading dan inspeksi dataset
src/experiment_{c,d}/    protokol dan tooling Experiment C/D
src/inference/           model loading dan strict feature validation
src/ingestion/           capture, adapter, extractor, dan API sender
src/preprocessing/       column/label normalization dan dataset preparation
src/training/            baseline dan tuned training
src/evaluation/          metrics, comparison, dan scenario validation
tests/                   unit dan integration tests
```

## Batasan

- Experiment C dan D menunjukkan generalisasi lintas environment masih lemah, khususnya DDoS.
- CICFlowMeter V3 tidak identik dengan Java CICFlowMeter pembuat CICIDS2017; kompatibilitas
  78 fitur tidak menjamin numerical parity.
- Dua artifact dataset yang diaudit direproduksi untuk kompatibilitas model lama; nilainya
  tidak diklaim sebagai pengukuran jaringan independen.
- Live capture bersifat *near-real-time* berbasis segmen PCAP, bukan packet inspection inline.
- Sesi autentikasi hanya berada di memory; belum ada rate limiting, account recovery,
  generalized RBAC, atau machine authentication untuk ingestion.
- Export dibatasi hingga 10.000 record.
- Project belum di-hardening atau divalidasi untuk production deployment.

Dokumentasi implementasi final dan batas integritas ilmiah dijelaskan di
[phase 8 final integration and thesis freeze](docs/phase_8_final_integration_and_thesis_freeze.md).
