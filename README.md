# RF-NIDS

RF-NIDS adalah prototipe penelitian *Random Forest Network Intrusion Detection System* untuk klasifikasi trafik `Normal`, `DDoS`, dan `PortScan`. Implementasi saat ini mencakup data understanding, preprocessing anti-leakage, baseline, hyperparameter tuning, pemilihan model aktif, dan inference tervalidasi. API, database, dashboard, dan virtual lab belum diimplementasikan.

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

## Batasan dan troubleshooting

- Jika kolom label tidak ditemukan, periksa nama aktual lalu gunakan `--label-column`.
- Jika normalisasi membuat dua nama kolom sama, ganti nama kolom sumber agar tidak ambigu.
- CSV rusak atau encoding yang tidak didukung akan dihentikan dengan pesan error dan tidak menghasilkan laporan parsial.
- Simulasi trafik keamanan hanya boleh dilakukan pada jaringan laboratorium milik sendiri atau sistem yang telah memiliki izin resmi.

Tahap berikutnya adalah membungkus inference aktif dalam FastAPI setelah hasil model ditinjau secara kritis.
