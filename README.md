# RF-NIDS

RF-NIDS adalah prototipe penelitian *Random Forest Network Intrusion Detection System* untuk klasifikasi trafik `Normal`, `DDoS`, dan `PortScan`. Implementasi saat ini mencakup pipeline eksperimen, inference tervalidasi, serta backend deteksi FastAPI dengan persistence PostgreSQL dan alert. Dashboard visual dan virtual lab belum diimplementasikan.

## Status implementasi

Sudah tersedia: data understanding, preprocessing, baseline RF, tuned RF, model selection,
scenario validation, inference engine, FastAPI backend, SQL persistence, dan alert mechanism.

Belum tersedia: Streamlit dashboard, live network flow ingestion, dan virtual laboratory
integration.

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

Prediction selalu disimpan. Alert hanya dibuat bila label bukan `Normal` dan confidence
mencapai `ALERT_CONFIDENCE_THRESHOLD` (default `0.70`): `DDoS` menjadi `HIGH`, sedangkan
`PortScan` menjadi `MEDIUM`. Confidence rendah tidak mengubah label hasil model.

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

Tahap berikutnya adalah membangun Streamlit monitoring dashboard yang membaca endpoint
summary, predictions, dan alerts tanpa mengulang inference atau mengakses tabel secara
langsung.
