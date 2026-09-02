# RF-NIDS

RF-NIDS adalah prototipe penelitian *Random Forest Network Intrusion Detection System* untuk klasifikasi trafik `Normal`, `DDoS`, dan `PortScan`. Implementasi saat ini mencakup pipeline eksperimen, inference tervalidasi, backend FastAPI, persistence PostgreSQL, alert, dan dashboard monitoring Streamlit.

## Status implementasi

| Komponen | Status |
|---|---|
| Data pipeline | ✅ |
| Random Forest training | ✅ |
| Hyperparameter tuning | ✅ |
| Scenario validation | ✅ |
| Inference engine | ✅ |
| FastAPI backend | ✅ |
| PostgreSQL persistence | ✅ |
| Alert management | ✅ |
| Streamlit dashboard | ✅ |
| Offline PCAP ingestion | ⚠️ adapter ready; extractor compatibility must be audited |
| Live flow ingestion | ⚠️ optional; extractor compatibility and capture privilege required |
| Virtual laboratory | 📋 documented; Experiment C not yet run |

## Kebutuhan dan instalasi

- Python 3.11
- Dataset CSV berlabel

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Jangan commit `.env`. Ubah `LEAKAGE_COLUMNS_CONFIG` bila lokasi konfigurasi berbeda. Daftar kandidat leakage dan alasannya dapat disesuaikan di `config/leakage_columns.json` setelah struktur dataset nyata diperiksa.

## Struktur utama

```text
config/                 konfigurasi kandidat leakage
data/{raw,processed,external}/
src/common/             konfigurasi dan logging
src/preprocessing/      normalisasi kolom dan pemetaan label
src/data/               inspeksi dataset
src/training/           training Random Forest baseline
src/evaluation/         metrik dan visualisasi evaluasi
src/inference/          validasi fitur dan prediksi model aktif
src/api/                FastAPI, schema, persistence, dan alert
src/ingestion/          capture wrapper, strict feature adapter, batching, dan API sender
dashboard/              client API dan halaman monitoring Streamlit
migrations/             migrasi skema PostgreSQL (Alembic)
reports/{figures,metrics,experiments}/
tests/{unit,integration}/
```

## Persiapan dan inspeksi dataset

Letakkan CSV di `data/raw/`. Nama kolom tidak diasumsikan; berikan kolom target secara eksplisit jika bukan `label`:

```bash
python -m src.data.inspect_dataset \
  --input data/raw/dataset.csv \
  --label-column label
```

Beberapa CSV dengan skema yang sama dapat diperiksa sebagai satu dataset:

```bash
python -m src.data.inspect_dataset \
  --input data/raw/cicids2017/file-ddos.csv data/raw/cicids2017/file-portscan.csv \
  --label-column label
```

Daftar dan ukuran file sumber dicatat di laporan JSON. Untuk CICIDS2017 pada penelitian tiga kelas ini, gunakan file DDoS dan PortScan; file serangan lain berada di luar ruang lingkup label penelitian.

Perintah menghasilkan:

- `reports/metrics/data_understanding.json`: ukuran data, tipe kolom, distribusi kelas mentah dan hasil pemetaan, kelas yang dikeluarkan, missing/infinity, duplikat, statistik, kolom konstan/variasi rendah, korelasi, dan kandidat leakage.
- `reports/figures/class_distribution.png`: distribusi tiga kelas target menggunakan Matplotlib.

Pemetaan bersifat case-insensitive: `BENIGN`/`Normal` menjadi `Normal`, label yang mengandung `ddos` menjadi `DDoS`, dan `portscan`/`port scan` menjadi `PortScan`. Label lain dikeluarkan dan jumlahnya dicatat. Inspeksi tidak mengimputasi atau mentransformasi fitur sehingga tidak menyebabkan leakage sebelum train-test split.

## Preprocessing dan training baseline

Jalankan data understanding terlebih dahulu. Training tanpa `--input` membaca daftar CSV dan nama label dari laporan tersebut:

```bash
python -m src.training.train_baseline
```

Input juga dapat disebutkan eksplisit, tetapi harus sama persis dengan `source_files` pada laporan:

```bash
python -m src.training.train_baseline \
  --input data/raw/cicids2017/file-1.csv data/raw/cicids2017/file-2.csv \
  --label-column label
```

Preprocessing melakukan filtering tiga kelas, pencatatan kelas di luar ruang lingkup, deduplikasi, penggantian infinity menjadi `NaN`, pemisahan metadata, penghapusan kandidat leakage, dan pemilihan fitur numerik. Split dilakukan secara stratified dengan `test_size=0.2` dan `random_state=42`. Median imputer berada di dalam Scikit-learn Pipeline; `fit` hanya menerima training set sehingga statistik test set tidak bocor ke model.

Random Forest baseline menggunakan `n_estimators=100`, `random_state=42`, `n_jobs=-1`, dan `class_weight="balanced"`. Tidak ada tuning pada tahap ini.

Artefak yang dihasilkan:

- `models/random_forest_baseline.joblib`
- `reports/metrics/baseline_metrics.json`
- `reports/metrics/feature_importance.csv`
- `reports/figures/baseline_confusion_matrix.png`
- `reports/figures/baseline_feature_importance.png`

Metrik mencakup accuracy, macro dan weighted precision/recall/F1, classification report, confusion matrix, FPR one-vs-rest, kesalahan IDS penting, waktu training, dan waktu inferensi. Jangan menilai model hanya dari accuracy; tinjau recall DDoS, recall PortScan, macro F1, false positive terhadap trafik Normal, serta risiko bias capture/file.

## Experiment A dan Experiment B

**Experiment A — Stratified Random Split** adalah baseline utama untuk mengukur performa
klasifikasi dengan pembagian acak terstratifikasi 80/20. Artefak baseline, tuned model,
perbandingan model, dan active model tetap dipertahankan dan tidak dipilih ulang oleh
validasi tambahan.

**Experiment B — Unseen/Scenario Validation** mengurangi risiko estimasi yang terlalu
optimistis ketika flow dari capture atau bagian capture yang sama tersebar antara training
dan testing. Pada distribusi CICIDS2017 ini, DDoS dan PortScan masing-masing terkonsentrasi
pada satu source file. Full source-file holdout tidak valid karena akan menghilangkan kelas
tersebut dari training. Karena CSV juga tidak menyediakan session identifier yang tervalidasi,
Experiment B memakai holdout blok kontigu berurutan: di setiap pasangan `source_file × class`,
seluruh blok paling akhir menjadi testing dan blok sebelumnya menjadi training. Tidak ada
grup blok yang muncul pada kedua split, `source_file` hanya metadata, dan median imputer tetap
di-fit hanya pada training.

Jalankan validasi tambahan setelah artefak Experiment A tersedia:

```bash
python -m src.evaluation.scenario_validation
```

Perintah menghasilkan distribusi per source file, feature audit, metrik scenario, perbandingan
Experiment A/B, dan confusion matrix di `reports/metrics/` serta `reports/figures/`. Strategi
ini adalah stress test tambahan berbasis urutan baris capture, bukan representasi sempurna
production traffic atau pengganti evaluasi lintas jaringan/waktu yang benar-benar independen.

## Hyperparameter tuning

Tuning default mempertahankan `n_iter=20`, stratified `cv=5`, scoring `f1_macro`, dan ruang parameter penelitian. Agar eksperimen praktis, CV menggunakan stratified sample 50.000 baris dari training set. Parameter terbaik kemudian di-fit ulang pada seluruh training set dan dievaluasi pada test set baseline yang sama.

```bash
python -m src.training.train_tuned \
  --iterations 20 \
  --cv 5 \
  --tuning-sample-size 50000
```

Jumlah sample dapat disesuaikan secara eksplisit. Laporan metrik selalu mencatat ukuran dan distribusi sample serta jumlah baris full-training untuk refit. Test set tidak pernah digunakan selama pencarian parameter.

Artefak tuning:

- `models/random_forest_tuned.joblib`
- `reports/metrics/tuned_metrics.json`
- `reports/metrics/tuned_best_parameters.json`
- `reports/metrics/tuning_results.csv`
- `reports/metrics/tuned_feature_importance.csv`
- `reports/figures/tuned_confusion_matrix.png`
- `reports/figures/tuned_feature_importance.png`

Pilih model aktif hanya setelah baseline dan tuned tersedia:

```bash
python -m src.evaluation.compare_models
```

Comparator memprioritaskan macro F1, recall DDoS, recall PortScan, false-positive rate trafik Normal, lalu inference time. Tuned model tidak dipilih otomatis. Hasilnya disimpan sebagai `models/random_forest_active.joblib`, `models/model_metadata.json`, dan `reports/metrics/model_comparison.json`.

## Inference

`InferenceEngine` memuat model satu kali, memverifikasi hash model, menormalisasi dan mengurutkan fitur sesuai metadata, menolak fitur kurang, serta secara default menolak fitur tambahan. Hasil prediksi memuat label, confidence, probability seluruh kelas, dan versi model.

```python
from pathlib import Path
from src.inference import InferenceEngine

engine = InferenceEngine(
    Path("models/random_forest_active.joblib"),
    Path("models/model_metadata.json"),
)
result = engine.predict_one(feature_values)
```

## Pengujian

```bash
pytest
```

## Detection backend

Alur backend adalah `FastAPI request → InferenceEngine → active Random Forest Pipeline →
traffic flow + prediction transaction → conditional alert`. Model aktif dimuat dan hash-nya
diverifikasi satu kali pada application startup. Urutan fitur selalu berasal dari metadata;
metadata capture seperti IP, port, protocol, dan waktu tidak dimasukkan ke model secara
otomatis.

### PostgreSQL

Jalankan PostgreSQL development lokal (credential ini hanya untuk local development):

```bash
docker compose up -d postgres
```

### Migration

Development dan production wajib membuat atau memperbarui schema dengan Alembic:

```bash
alembic upgrade head
```

Runtime PostgreSQL tidak menjalankan `Base.metadata.create_all()`. Fasilitas tersebut hanya
tersedia melalui factory aplikasi untuk integration test SQLite temporer.

### FastAPI

```bash
uvicorn src.api.main:app --reload
```

### API docs

```text
http://localhost:8000/docs
```

### Test

```bash
pytest
```

Sebagai alternatif, seluruh stack dapat dijalankan dengan `docker compose up -d --build`.
Compose menunggu PostgreSQL sehat, menjalankan `alembic upgrade head` melalui service
`migration`, lalu memulai API.

## macOS Flow Extraction

Development compatibility workflow (this is not the Experiment C virtual lab):

```text
macOS -> Docker CICFlowMeter-compatible extractor -> Flow CSV -> Compatibility Check
```

The tools-profile image pins the Python/Scapy implementation
[`hieulw/cicflowmeter` 0.4.2](https://github.com/hieulw/cicflowmeter). It is maintained
and uses Scapy plus Debian's native `libpcap`. It runs natively in Docker on both Apple Silicon (`linux/arm64`) and Intel
(`linux/amd64`); Compose therefore does not force amd64 emulation. It is not identical
to the original Java CICFlowMeter used for CICIDS2017. The original's Java 8-era
jNetPcap and native Linux x86_64 dependencies are unsuitable for a clean,
reproducible modern arm64 setup, so schema compatibility is checked strictly rather
than assumed.

Create a benign sample capture without hard-coding the network interface:

```bash
ifconfig
sudo tcpdump -i <interface> -w data/lab/pcap/sample.pcap
```

While capture is active, generate normal traffic (for example `ping -c 5 8.8.8.8`
and `curl https://example.com`), then stop `tcpdump` with Ctrl-C. No attack traffic is
needed. Alternatively, copy an existing benign PCAP into `data/lab/pcap/`.

Build and extract one offline CSV:

```bash
docker compose build cicflowmeter
docker compose --profile tools run --rm cicflowmeter \
  /input/sample.pcap /output/sample.csv
```

Run the strict 78-feature audit and inspect the generated report:

```bash
python scripts/check_live_feature_compatibility.py \
  --input data/lab/flows/sample.csv
cat reports/metrics/live_feature_compatibility.json
```

The checker reuses the training column normalizer and never uses fuzzy mapping,
zero-fill, or a generic missing-feature fallback. Unknown missing features always
make the selected policy incompatible.

For `hieulw/cicflowmeter` 0.4.2, the adapter additionally applies the reviewed,
explicit aliases in `src/ingestion/cicflowmeter_mapping.py`; it never performs fuzzy
matching. The mapping audit is written to
`reports/metrics/live_feature_mapping_audit.json`.

The active model was trained using the released CICIDS2017 MachineLearningCSV
schema. Provenance auditing identified two released-dataset artifacts. For
compatibility with the existing trained model, the prototype explicitly reproduces
these audited artifacts at inference time. These values are not presented as
independent network measurements.

Two explicit policies are supported:

- `STRICT_SEMANTIC` resolves 76/78 and requires independent semantic sources.
- `CICIDS2017_DATASET_ARTIFACT_REPRODUCTION` additionally reproduces only the two
  audited allowlisted artifacts: `fwd_header_length.1` from
  `fwd_header_length`, and `cwe_flag_count` from `fwd_urg_flags`. The latter is
  dataset-value reproduction and is not claimed to be genuine TCP CWR.

The artifact policy is the thesis-prototype runtime default and is logged by the
ingestion runner. Select strict mode explicitly when required:

```bash
python scripts/check_live_feature_compatibility.py \
  --input data/lab/flows/sample.csv \
  --policy STRICT_SEMANTIC
```

Di dalam jaringan Compose, API memakai hostname database `postgres`. Dari aplikasi desktop
lokal seperti DBeaver/TablePlus, gunakan host `localhost`, port `5432`, database `rf_nids`,
user `postgres`, dan password `postgres`. `DATABASE_URL` tetap menjadi satu-satunya sumber
konfigurasi koneksi backend dan credential production tidak boleh disimpan di repository.

Setelah server aktif, dokumentasi interaktif tersedia di
[`/docs`](http://localhost:8000/docs) dan [`/redoc`](http://localhost:8000/redoc).

Operasi Docker yang umum:

```bash
# Melihat status dan log
docker compose ps
docker compose logs -f api

# Restart API
docker compose restart api

# Hentikan stack tanpa menghapus database
docker compose down

# Reset total termasuk data PostgreSQL (destruktif)
docker compose down -v
```

Menjalankan API langsung dari virtual environment masih memungkinkan untuk debugging, tetapi
ubah `DATABASE_URL` menjadi host `localhost` khusus pada shell tersebut. Konfigurasi default
project ditujukan untuk full Docker Compose.

Endpoint backend:

- `GET /health`
- `GET /api/model`
- `POST /api/predict` dan `POST /api/predict/batch`
- `GET /api/predictions` dan `GET /api/predictions/{id}`
- `GET /api/alerts`, `GET /api/alerts/{id}`, dan `PATCH /api/alerts/{id}/acknowledge`
- `GET /api/dashboard/summary`
- `GET /api/dashboard/timeline` (agregasi per menit; parameter `minutes`, default 60)

Contoh request prediksi (objek `features` harus memuat seluruh 78 fitur sesuai
`models/model_metadata.json`):

```bash
curl -X POST http://localhost:8000/api/predict \
  -H 'Content-Type: application/json' \
  -d '{
    "features": {"destination_port": 80, "flow_duration": 1250},
    "metadata": {"source_ip": "10.0.0.10", "destination_ip": "10.0.0.20"}
  }'
```

Contoh ringkas di atas sengaja tidak memuat semua fitur dan akan menghasilkan validasi
`422`; gunakan daftar feature lengkap dari `models/model_metadata.json` saat
membangun collector. Batch dibatasi `MAX_BATCH_SIZE`, sedangkan pagination dibatasi
`MAX_PAGE_SIZE`.

Prediction selalu disimpan. Alert mengikuti aturan aplikasi deterministik: `Normal` tidak
membuat alert, `DDoS` selalu membuat alert `HIGH`, dan `PortScan` selalu membuat alert
`MEDIUM`. Confidence tetap disimpan dan ditampilkan sebagai informasi prediction, tetapi
tidak menentukan pembuatan alert. Konfigurasi lama `ALERT_CONFIDENCE_THRESHOLD` telah
dihapus karena tidak lagi memiliki efek aplikasi.

Endpoint acknowledge memerlukan sesi administrator Bearer yang diperoleh melalui
`POST /api/auth/login`. Streamlit menyediakan Login interaktif, menyimpan token opaque
di session state, menambahkan Bearer token ke request terproteksi, dan menyediakan Logout.
Seluruh halaman aplikasi hanya muncul setelah sesi ADMIN diverifikasi.

Batch prediction disimpan dalam satu transaction: seluruh flow, prediction, dan alert di-flush
lalu di-commit sekali; kegagalan apa pun memicu rollback seluruh batch. Relasi data mengikuti
ownership berikut: menghapus traffic flow di level database menghapus prediction dan alert
turunannya (`ON DELETE CASCADE`), dan menghapus prediction menghapus alert. Model yang sudah
direferensikan prediction tidak boleh dihapus (`ON DELETE RESTRICT`) agar versi model pada
audit history tidak hilang. Backend belum menyediakan delete endpoint.

Pada PostgreSQL, `traffic_flows.raw_features` dan
`predictions.class_probabilities` menggunakan `JSONB`. Model memakai variant SQLAlchemy
`JSON` untuk SQLite agar integration test tetap ringan dan portable.

Test API memakai model deterministik kecil dan SQLite temporer sehingga tidak memerlukan
dataset CICIDS2017 maupun PostgreSQL yang sedang berjalan:

```bash
pytest
```

## Batasan dan troubleshooting

- Jika kolom label tidak ditemukan, periksa nama aktual lalu gunakan `--label-column`.
- Jika normalisasi membuat dua nama kolom sama, ganti nama kolom sumber agar tidak ambigu.
- CSV rusak atau encoding yang tidak didukung akan dihentikan dengan pesan error dan tidak menghasilkan laporan parsial.
- Simulasi trafik keamanan hanya boleh dilakukan pada jaringan laboratorium milik sendiri atau sistem yang telah memiliki izin resmi.

## Monitoring Dashboard

Dashboard menyediakan halaman **Overview**, **Predictions**, **Alerts**, dan **Model** untuk
demo penelitian dan pemantauan hasil klasifikasi. Arsitekturnya adalah
`Streamlit → FastAPI → PostgreSQL`: Streamlit tidak mengakses database, memuat model, atau
melakukan inference. Semua runtime monitoring data berasal dari API backend.

Setelah menyalin `.env.example` ke `.env`, jalankan komponen secara berurutan:

```bash
docker compose up -d postgres
alembic upgrade head
uvicorn src.api.main:app --reload
streamlit run dashboard/app.py
```

Dashboard tersedia di `http://localhost:8501`. URL backend, interval refresh, dan timeout
diatur dengan `FASTAPI_BASE_URL`, `DASHBOARD_REFRESH_SECONDS`, dan
`DASHBOARD_REQUEST_TIMEOUT`. Saat backend offline atau database kosong, UI tetap terbuka dan
menampilkan pesan informatif. Acknowledgement alert selalu dikirim melalui FastAPI.

Dashboard ini masih prototipe development/laboratory: belum memiliki authentication atau
production-grade authentication.

## Offline PCAP Validation

Validasi offline menjalankan batas arsitektur produksi secara utuh:

```text
PCAP -> CICFlowMeter -> Feature Adapter -> FastAPI
     -> Random Forest -> PostgreSQL -> Streamlit
```

Jalankan service aplikasi, lalu validasi PCAP normal yang sudah tersedia:

```bash
docker compose up -d --build
python scripts/run_offline_pcap_validation.py \
  --pcap data/lab/pcap/sample.pcap
```

Extractor dijalankan melalui service Docker `cicflowmeter` pada profile `tools`.
Hasil aktual—termasuk kegagalan parsial—ditulis ke
`reports/metrics/offline_pcap_validation.json`. URL API dan lokasi laporan dapat
diubah tanpa melewati FastAPI:

```bash
python scripts/run_offline_pcap_validation.py \
  --pcap data/lab/pcap/sample.pcap \
  --api-url http://localhost:8000 \
  --output reports/metrics/offline_pcap_validation.json
```

Untuk mengulang validasi API dari CSV yang telah diekstrak tanpa menjalankan
extractor lagi, gunakan `--flow-csv data/lab/flows/sample.csv`.

Runner menerapkan policy
`CICIDS2017_DATASET_ARTIFACT_REPRODUCTION`, menghasilkan tepat 78 fitur dalam
urutan model, mempertahankan metadata flow secara terpisah, mengirim batch
terbatas ke `POST /api/predict/batch`, lalu memverifikasi ID prediksi dan kenaikan
counter melalui API. Tidak ada traffic serangan yang dibuat oleh proses ini.

Validasi dashboard secara manual setelah run:

```bash
streamlit run dashboard/app.py
```

Periksa halaman Overview, Predictions, Alerts, dan Model. Data baru tersedia
melalui endpoint yang sama dengan yang dikonsumsi dashboard.

Ini adalah validasi fungsi pipeline, bukan Experiment C dan bukan pengukuran
akurasi deteksi. Kompatibilitas schema tidak membuktikan ekuivalensi numerik;
`hieulw/cicflowmeter` juga bukan implementasi Java CICFlowMeter historis.

## Live Normal Traffic Validation

Arsitektur khusus macOS mempertahankan FastAPI sebagai satu-satunya boundary inferensi:

```text
macOS Interface -> tcpdump -> Rotating/Short PCAP -> CICFlowMeter Docker
                -> Feature Adapter -> FastAPI -> Random Forest
                -> PostgreSQL -> Streamlit
```

Prototipe ini melakukan deteksi berbasis flow secara *near-real-time* menggunakan segmen
packet capture pendek. Ini bukan inspeksi packet inline dan bukan sistem prevention. Docker
Desktop tidak diasumsikan dapat menangkap interface host macOS; hanya ekstraksi flow yang
berjalan di Docker, sedangkan `tcpdump` berjalan pada host.

Temukan interface, lalu pilih secara eksplisit (nama interface tidak di-hardcode):

```bash
python scripts/run_live_capture.py --list-interfaces
# Alternatif dengan keterangan hardware port:
networksetup -listallhardwareports
```

Siapkan izin capture tanpa menyimpan password, hidupkan backend, lalu jalankan smoke test
normal selama 30–60 detik. Contoh berikut memakai empat segmen 15 detik; durasi ini hanya
smoke test dan bukan durasi evaluasi ilmiah:

```bash
sudo -v
docker compose up -d --build
python scripts/run_live_capture.py \
  --interface <interface> \
  --segment-seconds 15 \
  --max-segments 4
```

Tanpa `--max-segments`, runner berlanjut sampai `Ctrl+C`. Shutdown menghentikan `tcpdump`
dengan aman, memproses segmen yang sudah ditutup, dan selalu menulis report. Selama capture,
lakukan aktivitas normal saja, misalnya membuka situs biasa atau:

```bash
ping -c 5 8.8.8.8
curl https://example.com
curl https://github.com
```

Jangan menjalankan nmap, hping3, flood, stress traffic, atau skenario ofensif pada tahap ini.
Prediksi DDoS/PortScan dari traffic yang diketahui normal tidak disembunyikan atau diubah;
hasil tersebut dicatat sebagai kandidat false positive.

Evidence lokal disimpan di `data/lab/live/<session-id>/{pcap,flows,logs}` dan report gate di
`reports/metrics/live_normal_validation.json`. Keduanya diabaikan Git. PCAP tidak diunggah,
payload tidak dicatat ke log atau PostgreSQL, dan hanya metadata flow/prediksi yang dipersist.
Hapus session secara manual hanya setelah evidence tidak diperlukan; report tidak pernah
dihapus otomatis.

Preflight memeriksa interface, `tcpdump`, API/model 78 fitur, PostgreSQL melalui health API,
dan service extractor. Adapter tetap memakai policy
`CICIDS2017_DATASET_ARTIFACT_REPRODUCTION`; hanya dua artifact yang telah diaudit
(`fwd_header_length.1` dan `cwe_flag_count`) yang direproduksi. Flow dengan fitur asing yang
hilang gagal tanpa zero-fill. Metadata session/interface/segmen/5-tuple/timestamp disimpan
terpisah dan tidak menjadi input RF. Pengiriman memakai batch terbatas, timeout, retry
terbatas, dan exponential backoff.

Verifikasi Streamlit dengan `streamlit run dashboard/app.py`: counter Overview dan Recent
Predictions harus berubah, alert harus muncul bila dibuat, dan detail prediksi menyediakan
metadata capture. Streamlit tetap membaca FastAPI/PostgreSQL, bukan PCAP.

Keterbatasan: `hieulw/cicflowmeter` berbeda dari Java CICFlowMeter historis; kompatibilitas
78/78 tidak membuktikan parity numerik sempurna; policy reproduksi artifact dataset tetap
aktif; dan observed candidate false-positive rate dari session normal ini bukan FPR final
model. Experiment C hanya boleh dimulai sebagai tahap terpisah setelah instruksi eksplisit.
