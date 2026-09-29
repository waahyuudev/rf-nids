# Audit Spesifikasi Basis Data RF-NIDS untuk BAB III

## Ruang Lingkup dan Authority

Audit ini bersifat read-only. Tidak ada migration, DDL, DML, training, inference, atau perubahan aplikasi yang dijalankan. Schema target ditentukan dari rantai Alembic sampai head repository `20260917_10`, kemudian dicocokkan dengan ORM dan PostgreSQL live.

PostgreSQL berhasil diakses dengan `transaction_read_only=on`. Live DB berisi 12 application table, tetapi revision-nya masih `20260905_08`, tertinggal dari head `20260917_10`. Karena urutan authority yang diminta menempatkan Alembic head lebih tinggi, spesifikasi utama di bawah adalah **target final schema pada head `20260917_10`**. Perbedaan live dijelaskan eksplisit pada Cross-check Summary.

Konvensi tipe:

- `sa.Integer()` → PostgreSQL `INTEGER`; PK menggunakan sequence (`nextval(...)`) pada live DB.
- `sa.Float()` terintrospeksi sebagai PostgreSQL `DOUBLE PRECISION` dengan presisi biner 53.
- `sa.DateTime(timezone=True)` → `TIMESTAMP WITH TIME ZONE` (`TIMESTAMPTZ`).
- `PortableJSON = JSON().with_variant(JSONB(), "postgresql")` → `JSONB` pada target PostgreSQL (`src/api/models.py:27`; migration `20260820_01:12`, `20260902_03:17`).
- `runtime_validation_runs.evidence_json` dibuat sebagai `JSON`, bukan `JSONB` (`20260904_07_runtime_validation.py:41`).
- Tidak ada PostgreSQL `ENUM`; pembatasan nilai memakai `CHECK` atas `VARCHAR`.
- “Default ORM” adalah client-side SQLAlchemy dan dibedakan dari `server_default` database.

Sumber utama: `migrations/versions/20260820_01_detection_backend.py:15-30`, `20260820_02_live_capture_metadata.py:13-21`, `20260902_03_application_foundation.py:20-155`, `20260902_04_evidence_ingestion.py:17-42`, `20260904_05_runtime_monitoring.py:16-57`, `20260904_06_runtime_pipeline_metadata.py:16-20`, `20260904_07_runtime_validation.py:15-50`, `20260905_08_runtime_artifact_provenance.py:15-54`, `20260917_09_runtime_model_selection.py:16-33`, `20260917_10_expand_monitoring_selection_mode.py:16-24`; ORM `src/api/models.py:34-443`.

## 1. `users`

**Fungsi:** menyimpan akun administrator dan identitas aktor audit. **PK:** `id`. **FK:** tidak ada. **Unique:** `email` melalui unique index `ix_users_email`. **Index penting:** `ix_users_email` (unique), `ix_users_is_active`. **Check:** `ck_users_role: role IN ('ADMIN')`. Sumber: `20260902_03:21-34`; ORM `models.py:34-55`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID pengguna |
| 2 | `name` | VARCHAR(200) | 200 | NOT NULL | — | — | — | Nama administrator |
| 3 | `email` | VARCHAR(320) | 320 | NOT NULL | UNIQUE | — | — | Email login |
| 4 | `password_hash` | VARCHAR(512) | 512 | NOT NULL | — | — | — | Hash kata sandi |
| 5 | `role` | VARCHAR(30) | 30 | NOT NULL | — | ORM: `ADMIN` | — | Peran; dibatasi `ADMIN` |
| 6 | `is_active` | BOOLEAN | — | NOT NULL | — | ORM: `true` | — | Status akun |
| 7 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 8 | `updated_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now/on update | — | Waktu diperbarui |

## 2. `datasets`

**Fungsi:** metadata dataset ilmiah yang diimpor. **PK:** `id`. **FK:** `created_by_user_id → users.id ON DELETE SET NULL`. **Unique:** tidak ada. **Index:** `ix_datasets_source_sha256`, `ix_datasets_created_by_user_id`. Sumber: `20260902_03:36-55`; ORM `models.py:58-76`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID dataset |
| 2 | `name` | VARCHAR(255) | 255 | NOT NULL | — | — | — | Nama dataset |
| 3 | `source_path` | VARCHAR(1000) | 1000 | NULL | — | — | — | Path sumber |
| 4 | `source_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | SHA-256 sumber |
| 5 | `total_rows` | INTEGER | 32-bit | NULL | — | — | — | Jumlah baris |
| 6 | `total_features` | INTEGER | 32-bit | NULL | — | — | — | Jumlah fitur |
| 7 | `label_column` | VARCHAR(255) | 255 | NULL | — | — | — | Nama kolom label |
| 8 | `class_distribution` | JSONB | — | NULL | — | — | — | Distribusi kelas |
| 9 | `created_by_user_id` | INTEGER | 32-bit | NULL | FK | — | `users.id`, SET NULL | Pembuat metadata |
| 10 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 11 | `updated_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now/on update | — | Waktu diperbarui |

## 3. `experiments`

**Fungsi:** metadata eksperimen/evaluasi ilmiah. **PK:** `id`. **FK:** `dataset_id → datasets.id ON DELETE SET NULL`. **Unique:** `experiment_code` melalui `ix_experiments_experiment_code`. **Index:** unique code, `ix_experiments_dataset_id`, `ix_experiments_source_sha256`. Sumber: `20260902_03:57-81`; ORM `models.py:79-103`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID eksperimen |
| 2 | `experiment_code` | VARCHAR(100) | 100 | NOT NULL | UNIQUE | — | — | Kode eksperimen |
| 3 | `experiment_name` | VARCHAR(255) | 255 | NOT NULL | — | — | — | Nama eksperimen |
| 4 | `experiment_type` | VARCHAR(100) | 100 | NOT NULL | — | — | — | Jenis eksperimen |
| 5 | `dataset_id` | INTEGER | 32-bit | NULL | FK | — | `datasets.id`, SET NULL | Dataset terkait |
| 6 | `description` | TEXT | — | NULL | — | — | — | Deskripsi |
| 7 | `status` | VARCHAR(50) | 50 | NOT NULL | — | — | — | Status eksperimen |
| 8 | `source_path` | VARCHAR(1000) | 1000 | NULL | — | — | — | Path evidence |
| 9 | `source_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | SHA-256 evidence |
| 10 | `schema_version` | VARCHAR(100) | 100 | NULL | — | — | — | Versi schema evidence |
| 11 | `imported_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu impor |
| 12 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 13 | `updated_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now/on update | — | Waktu diperbarui |

## 4. `evaluation_results`

**Fungsi:** metrik evaluasi keseluruhan dan per kelas. **PK:** `id`. **FK:** `experiment_id → experiments.id ON DELETE CASCADE`. **Unique:** `uq_evaluation_metric_key (experiment_id, metric_key)`. **Index:** `ix_evaluation_results_experiment_id` dan unique index constraint. Sumber: `20260902_03:83-113`, `20260902_04:35-39`; ORM `models.py:106-134`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID hasil |
| 2 | `experiment_id` | INTEGER | 32-bit | NOT NULL | FK, UNIQUE(composite) | — | `experiments.id`, CASCADE | Eksperimen induk |
| 3 | `class_name` | VARCHAR(100) | 100 | NULL | — | — | — | Nama kelas |
| 4 | `accuracy` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Akurasi |
| 5 | `precision_score` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Precision |
| 6 | `recall_score` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Recall |
| 7 | `f1_score` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | F1-score |
| 8 | `macro_precision` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Macro precision |
| 9 | `macro_recall` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Macro recall |
| 10 | `macro_f1` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Macro F1 |
| 11 | `false_positive_rate` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | False-positive rate |
| 12 | `true_positive` | INTEGER | 32-bit | NULL | — | — | — | True positive |
| 13 | `true_negative` | INTEGER | 32-bit | NULL | — | — | — | True negative |
| 14 | `false_positive` | INTEGER | 32-bit | NULL | — | — | — | False positive |
| 15 | `false_negative` | INTEGER | 32-bit | NULL | — | — | — | False negative |
| 16 | `confusion_matrix` | JSONB | — | NULL | — | — | — | Matriks konfusi |
| 17 | `notes` | TEXT | — | NULL | — | — | — | Catatan |
| 18 | `source_path` | VARCHAR(1000) | 1000 | NULL | — | — | — | Path sumber |
| 19 | `source_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | SHA-256 sumber |
| 20 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 21 | `metric_key` | VARCHAR(150) | 150 | NULL | UNIQUE(composite) | — | — | Kunci metrik |

## 5. `evidence_sources`

**Fungsi:** provenance file evidence ilmiah. **PK:** `id`. **FK:** tidak ada; `owner_type` dan `owner_key` bukan physical FK. **Unique:** `uq_evidence_owner_role (owner_type, owner_key, evidence_role)` dan `uq_evidence_source_path (source_path)`. **Index:** `ix_evidence_sources_owner_type`, `ix_evidence_sources_owner_key`, serta index unique constraint. Sumber: `20260902_04:18-34`; ORM `models.py:137-152`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID evidence |
| 2 | `owner_type` | VARCHAR(50) | 50 | NOT NULL | UNIQUE(composite) | — | — | Tipe pemilik logis; bukan FK |
| 3 | `owner_key` | VARCHAR(150) | 150 | NOT NULL | UNIQUE(composite) | — | — | Kunci pemilik logis; bukan FK |
| 4 | `evidence_role` | VARCHAR(100) | 100 | NOT NULL | UNIQUE(composite) | — | — | Peran evidence |
| 5 | `source_path` | VARCHAR(1000) | 1000 | NOT NULL | UNIQUE | — | — | Path sumber unik |
| 6 | `source_sha256` | VARCHAR(64) | 64 | NOT NULL | — | — | — | SHA-256 sumber |
| 7 | `schema_version` | VARCHAR(100) | 100 | NULL | — | — | — | Versi schema |
| 8 | `imported_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu impor |

## 6. `models`

**Fungsi:** registry metadata versi model dan artifact. **PK:** `id`. **FK:** `experiment_id → experiments.id ON DELETE SET NULL`. **Unique:** `model_version` melalui `ix_models_model_version`. **Index:** unique model version, `ix_models_is_active`, `ix_models_experiment_id`. Sumber: `20260820_01:16-18`, `20260902_03:115-127`, `20260902_04:40-42`; ORM `models.py:155-181`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID model |
| 2 | `model_name` | VARCHAR(200) | 200 | NOT NULL | — | — | — | Nama model |
| 3 | `model_version` | VARCHAR(100) | 100 | NOT NULL | UNIQUE | — | — | Versi model |
| 4 | `algorithm` | VARCHAR(100) | 100 | NOT NULL | — | — | — | Algoritma |
| 5 | `accuracy` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Akurasi |
| 6 | `macro_f1` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Macro F1 |
| 7 | `ddos_recall` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Recall DDoS |
| 8 | `portscan_recall` | DOUBLE PRECISION | 53-bit | NULL | — | — | — | Recall PortScan |
| 9 | `is_active` | BOOLEAN | — | NOT NULL | — | ORM: `true` | — | Status aktif |
| 10 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu registrasi |
| 11 | `experiment_id` | INTEGER | 32-bit | NULL | FK | — | `experiments.id`, SET NULL | Eksperimen sumber |
| 12 | `artifact_path` | VARCHAR(1000) | 1000 | NULL | — | — | — | Path artifact |
| 13 | `artifact_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | SHA-256 artifact |
| 14 | `parameters` | JSONB | — | NULL | — | — | — | Parameter model |
| 15 | `feature_count` | INTEGER | 32-bit | NULL | — | — | — | Jumlah fitur |

## 7. `monitoring_sessions`

**Fungsi:** lifecycle sesi monitoring dan snapshot model runtime. **PK:** `id`. **FK:** `model_id → models.id ON DELETE RESTRICT`; `created_by_user_id → users.id ON DELETE SET NULL`. **Unique:** `uq_monitoring_sessions_artifact_key`; partial unique index `uq_monitoring_sessions_single_active` pada status aktif. **Index:** `ix_monitoring_sessions_model_id`, `ix_monitoring_sessions_status`, `ix_monitoring_sessions_created_by_user_id`, `ix_monitoring_sessions_status_created`, dua unique index tersebut. **Check:** status valid dan tiga counter `>= 0`. Sumber: `20260904_05:17-50`, `06:17-20`, `08:16-21`, `09:17-33`, `10:17-24`; ORM `models.py:184-245`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID sesi |
| 2 | `target_ip` | VARCHAR(45) | 45 | NOT NULL | — | — | — | IP target |
| 3 | `interface_name` | VARCHAR(100) | 100 | NOT NULL | — | — | — | Interface capture |
| 4 | `model_id` | INTEGER | 32-bit | NOT NULL | FK | — | `models.id`, RESTRICT | Model runtime |
| 5 | `status` | VARCHAR(20) | 20 | NOT NULL | — | — | — | Status lifecycle |
| 6 | `started_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu mulai |
| 7 | `stopped_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu berhenti |
| 8 | `created_by_user_id` | INTEGER | 32-bit | NULL | FK | — | `users.id`, SET NULL | Administrator pembuat |
| 9 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 10 | `updated_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now/on update | — | Waktu diperbarui |
| 11 | `last_error` | TEXT | — | NULL | — | — | — | Error terakhir |
| 12 | `runtime_handle` | VARCHAR(100) | 100 | NULL | — | — | — | Handle runtime |
| 13 | `flow_count` | INTEGER | 32-bit | NOT NULL | — | server: `0`; ORM: `0` | — | Jumlah flow |
| 14 | `prediction_count` | INTEGER | 32-bit | NOT NULL | — | server: `0`; ORM: `0` | — | Jumlah prediksi |
| 15 | `alert_count` | INTEGER | 32-bit | NOT NULL | — | server: `0`; ORM: `0` | — | Jumlah alert |
| 16 | `extractor_name` | VARCHAR(150) | 150 | NULL | — | — | — | Nama extractor |
| 17 | `extractor_version` | VARCHAR(100) | 100 | NULL | — | — | — | Versi extractor |
| 18 | `latest_processing_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Proses terakhir |
| 19 | `extractor_identity` | VARCHAR(300) | 300 | NULL | — | — | — | Identitas extractor |
| 20 | `artifact_key` | VARCHAR(36) | 36 | NULL | UNIQUE | — | — | Kunci artifact sesi |
| 21 | `artifact_root` | VARCHAR(1000) | 1000 | NULL | — | — | — | Root artifact |
| 22 | `processing_state` | VARCHAR(30) | 30 | NULL | — | — | — | State pemrosesan |
| 23 | `selection_mode` | VARCHAR(64) | 64 | NOT NULL | — | server: `DEFAULT`; ORM: `DEFAULT` | — | Mode pemilihan model |
| 24 | `selected_model_version` | VARCHAR(100) | 100 | NULL | — | — | — | Snapshot versi model |
| 25 | `selected_model_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | Snapshot hash model |

**Live difference:** PostgreSQL revision `20260905_08` hanya memiliki kolom 1–22; kolom 23–25 belum ada (`NOT PRESENT IN LIVE DB`).

## 8. `traffic_flows`

**Fungsi:** metadata flow jaringan dan payload fitur. **PK:** `id`. **FK:** tidak ada; khususnya tidak ada `monitoring_session_id`. **Unique:** tidak ada. **Index:** `ix_traffic_flows_capture_time`, `ix_traffic_flows_source_ip`, `ix_traffic_flows_destination_ip`, `ix_traffic_flows_capture_session_id`. Sumber: `20260820_01:19-22`, `20260820_02:13-21`; ORM `models.py:346-366`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID flow |
| 2 | `capture_time` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu capture |
| 3 | `source_ip` | VARCHAR(45) | 45 | NULL | — | — | — | IP sumber |
| 4 | `source_port` | INTEGER | 32-bit | NULL | — | — | — | Port sumber |
| 5 | `destination_ip` | VARCHAR(45) | 45 | NULL | — | — | — | IP tujuan |
| 6 | `destination_port` | INTEGER | 32-bit | NULL | — | — | — | Port tujuan |
| 7 | `protocol` | VARCHAR(30) | 30 | NULL | — | — | — | Protokol |
| 8 | `raw_features` | JSONB | — | NOT NULL | — | — | — | Fitur hasil adaptasi |
| 9 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 10 | `capture_session_id` | VARCHAR(80) | 80 | NULL | — | — | — | Identitas capture |
| 11 | `capture_interface` | VARCHAR(100) | 100 | NULL | — | — | — | Interface capture |
| 12 | `pcap_segment` | VARCHAR(255) | 255 | NULL | — | — | — | Segmen PCAP |

**Live difference:** `raw_features` bertipe `JSON`, sedangkan migration source/head menargetkan `JSONB`.

## 9. `predictions`

**Fungsi:** hasil klasifikasi beserta model dan provenance runtime. **PK:** `id`. **FK:** `traffic_flow_id → traffic_flows.id ON DELETE CASCADE`; `model_id → models.id ON DELETE RESTRICT`; `experiment_id → experiments.id ON DELETE SET NULL`; `monitoring_session_id → monitoring_sessions.id ON DELETE SET NULL`; `runtime_artifact_id → runtime_capture_artifacts.id ON DELETE SET NULL`. **Unique:** `traffic_flow_id`; `uq_predictions_source_external_key (source_type, external_key)`. **Index:** `ix_predictions_model_id`, `ix_predictions_predicted_label`, `ix_predictions_label_time`, `ix_predictions_experiment_id`, `ix_predictions_source_type`, `ix_predictions_monitoring_session_id`, `ix_predictions_runtime_artifact_id`, serta index unique constraints. Sumber: `20260820_01:23-26`, `20260902_03:129-144`, `20260904_05:51-57`, `20260905_08:51-54`; ORM `models.py:369-415`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID prediksi |
| 2 | `traffic_flow_id` | INTEGER | 32-bit | NOT NULL | FK, UNIQUE | — | `traffic_flows.id`, CASCADE | Flow yang diprediksi |
| 3 | `model_id` | INTEGER | 32-bit | NOT NULL | FK | — | `models.id`, RESTRICT | Model yang digunakan |
| 4 | `predicted_label` | VARCHAR(50) | 50 | NOT NULL | — | — | — | Label prediksi |
| 5 | `confidence_score` | DOUBLE PRECISION | 53-bit | NOT NULL | — | — | — | Confidence |
| 6 | `class_probabilities` | JSONB | — | NOT NULL | — | — | — | Probabilitas kelas |
| 7 | `prediction_time` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu prediksi |
| 8 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 9 | `experiment_id` | INTEGER | 32-bit | NULL | FK | — | `experiments.id`, SET NULL | Eksperimen opsional |
| 10 | `source_type` | VARCHAR(50) | 50 | NULL | UNIQUE(composite) | — | — | Tipe sumber |
| 11 | `external_key` | VARCHAR(255) | 255 | NULL | UNIQUE(composite) | — | — | Kunci idempotensi eksternal |
| 12 | `monitoring_session_id` | INTEGER | 32-bit | NULL | FK | — | `monitoring_sessions.id`, SET NULL | Sesi monitoring |
| 13 | `runtime_artifact_id` | INTEGER | 32-bit | NULL | FK | — | `runtime_capture_artifacts.id`, SET NULL | Artifact capture runtime |

**Check:** `ck_predictions_predicted_label` membatasi `Normal`, `DDoS`, `PortScan`. **Live differences:** `class_probabilities` adalah `JSON`, bukan target `JSONB`; live FK `traffic_flow_id` dan `model_id` terintrospeksi dengan default `NO ACTION` (klausa CASCADE/RESTRICT tidak tampil), berbeda dari migration source.

## 10. `alerts`

**Fungsi:** alert serangan dan audit acknowledgement. **PK:** `id`. **FK:** `prediction_id → predictions.id ON DELETE CASCADE`; `acknowledged_by_user_id → users.id ON DELETE SET NULL`. **Unique:** `prediction_id`. **Index:** `ix_alerts_severity`, `ix_alerts_status`, `ix_alerts_status_severity`, `ix_alerts_acknowledged_by_user_id`, serta unique index prediction. **Check:** severity `HIGH|MEDIUM`; status `ACTIVE|ACKNOWLEDGED`. Sumber: `20260820_01:27-30`, `20260902_03:146-155`; ORM `models.py:418-443`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID alert |
| 2 | `prediction_id` | INTEGER | 32-bit | NOT NULL | FK, UNIQUE | — | `predictions.id`, CASCADE | Prediksi pemicu |
| 3 | `severity` | VARCHAR(20) | 20 | NOT NULL | — | — | — | Severity |
| 4 | `title` | VARCHAR(200) | 200 | NOT NULL | — | — | — | Judul alert |
| 5 | `description` | TEXT | — | NOT NULL | — | — | — | Deskripsi alert |
| 6 | `status` | VARCHAR(30) | 30 | NOT NULL | — | ORM: `ACTIVE` | — | Status alert |
| 7 | `acknowledged_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu acknowledgement |
| 8 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |
| 9 | `acknowledged_by_user_id` | INTEGER | 32-bit | NULL | FK | — | `users.id`, SET NULL | Administrator acknowledgement |

**Live difference:** FK `prediction_id` terintrospeksi dengan default `NO ACTION`, bukan `ON DELETE CASCADE` seperti migration source.

## 11. `runtime_capture_artifacts`

**Fungsi:** provenance persisten setiap window PCAP/CSV runtime. **PK:** `id`. **FK:** `monitoring_session_id → monitoring_sessions.id ON DELETE CASCADE`. **Unique:** `uq_runtime_artifact_session_window (monitoring_session_id, window_number)`; `uq_runtime_capture_artifact_key (artifact_key)`. **Index:** `ix_runtime_capture_artifacts_monitoring_session_id`, `ix_runtime_artifact_session_state`, serta index unique constraints. **Check:** state valid. Sumber: `20260905_08:22-50`; ORM `models.py:248-289`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID artifact |
| 2 | `monitoring_session_id` | INTEGER | 32-bit | NOT NULL | FK, UNIQUE(composite) | — | `monitoring_sessions.id`, CASCADE | Sesi pemilik |
| 3 | `artifact_key` | VARCHAR(36) | 36 | NOT NULL | UNIQUE | — | — | Kunci artifact |
| 4 | `window_number` | INTEGER | 32-bit | NOT NULL | UNIQUE(composite) | — | — | Nomor window |
| 5 | `state` | VARCHAR(20) | 20 | NOT NULL | — | — | — | State artifact |
| 6 | `pcap_relative_path` | VARCHAR(1000) | 1000 | NULL | — | — | — | Path relatif PCAP |
| 7 | `pcap_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | SHA-256 PCAP |
| 8 | `pcap_size` | INTEGER | 32-bit | NULL | — | — | — | Ukuran PCAP |
| 9 | `csv_relative_path` | VARCHAR(1000) | 1000 | NULL | — | — | — | Path relatif CSV |
| 10 | `csv_sha256` | VARCHAR(64) | 64 | NULL | — | — | — | SHA-256 CSV |
| 11 | `csv_size` | INTEGER | 32-bit | NULL | — | — | — | Ukuran CSV |
| 12 | `extractor_identity` | VARCHAR(300) | 300 | NULL | — | — | — | Identitas extractor |
| 13 | `extracted_row_count` | INTEGER | 32-bit | NOT NULL | — | server: `0`; ORM: `0` | — | Baris hasil ekstraksi |
| 14 | `adapted_row_count` | INTEGER | 32-bit | NOT NULL | — | server: `0`; ORM: `0` | — | Baris hasil adaptasi |
| 15 | `error_stage` | VARCHAR(50) | 50 | NULL | — | — | — | Tahap error |
| 16 | `error_message` | TEXT | — | NULL | — | — | — | Pesan error |
| 17 | `capture_started_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Capture mulai |
| 18 | `capture_finished_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Capture selesai |
| 19 | `extraction_finished_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Ekstraksi selesai |
| 20 | `committed_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu commit |
| 21 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |

## 12. `runtime_validation_runs`

**Fungsi:** evidence dan hasil validasi runtime yang diturunkan server. **PK:** `id`. **FK:** `monitoring_session_id → monitoring_sessions.id ON DELETE CASCADE`; `model_id → models.id ON DELETE RESTRICT`. **Unique:** tidak ada. **Index:** `ix_runtime_validation_runs_monitoring_session_id`, `ix_runtime_validation_session_created`; tidak ada index khusus `model_id`. **Check:** scenario, status, pipeline_result, detection_result. Sumber: `20260904_07:16-50`; ORM `models.py:292-343`.

| No | Column | Exact SQL Type | Length/Precision | Nullable | Key | Default | References | Description |
|---:|---|---|---|---|---|---|---|---|
| 1 | `id` | INTEGER | 32-bit | NOT NULL | PK | sequence/identity implicit | — | ID validasi |
| 2 | `monitoring_session_id` | INTEGER | 32-bit | NOT NULL | FK | — | `monitoring_sessions.id`, CASCADE | Sesi tervalidasi |
| 3 | `scenario` | VARCHAR(30) | 30 | NOT NULL | — | — | — | Skenario validasi |
| 4 | `status` | VARCHAR(20) | 20 | NOT NULL | — | ORM: `RUNNING` | — | Status validasi |
| 5 | `target_ip` | VARCHAR(45) | 45 | NOT NULL | — | — | — | IP target |
| 6 | `interface_name` | VARCHAR(100) | 100 | NOT NULL | — | — | — | Interface |
| 7 | `started_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu mulai |
| 8 | `finished_at` | TIMESTAMP WITH TIME ZONE | — | NULL | — | — | — | Waktu selesai |
| 9 | `pcap_files_processed` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | File PCAP diproses |
| 10 | `pcap_bytes_processed` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Byte PCAP diproses |
| 11 | `flows_extracted` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Flow diekstrak |
| 12 | `flows_adapter_valid` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Flow valid adapter |
| 13 | `predictions_committed` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Prediksi tersimpan |
| 14 | `alerts_committed` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Alert tersimpan |
| 15 | `normal_predictions` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Prediksi Normal |
| 16 | `portscan_predictions` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Prediksi PortScan |
| 17 | `ddos_predictions` | INTEGER | 32-bit | NOT NULL | — | server/ORM: `0` | — | Prediksi DDoS |
| 18 | `pipeline_result` | VARCHAR(20) | 20 | NOT NULL | — | server/ORM: `NOT_EVALUATED` | — | Hasil pipeline |
| 19 | `detection_result` | VARCHAR(20) | 20 | NOT NULL | — | server/ORM: `NOT_EVALUATED` | — | Hasil deteksi |
| 20 | `extractor_identity` | VARCHAR(300) | 300 | NULL | — | — | — | Identitas extractor |
| 21 | `adapter_identity` | VARCHAR(300) | 300 | NULL | — | — | — | Identitas adapter |
| 22 | `model_id` | INTEGER | 32-bit | NOT NULL | FK | — | `models.id`, RESTRICT | Model tervalidasi |
| 23 | `model_version` | VARCHAR(100) | 100 | NOT NULL | — | — | — | Snapshot versi model |
| 24 | `evidence_json` | JSON | — | NOT NULL | — | ORM: `{}` | — | Payload evidence |
| 25 | `notes` | TEXT | — | NULL | — | — | — | Catatan |
| 26 | `created_at` | TIMESTAMP WITH TIME ZONE | — | NOT NULL | — | ORM: UTC now | — | Waktu dibuat |

## Cross-check Summary

### 1. Total application tables

**12**. `alembic_version` diabaikan sebagai tabel internal Alembic.

### 2. Total columns per table

| Table | Alembic Head | Live DB |
|---|---:|---:|
| `users` | 8 | 8 |
| `datasets` | 11 | 11 |
| `experiments` | 13 | 13 |
| `evaluation_results` | 21 | 21 |
| `evidence_sources` | 8 | 8 |
| `models` | 15 | 15 |
| `monitoring_sessions` | 25 | 22 |
| `traffic_flows` | 12 | 12 |
| `predictions` | 13 | 13 |
| `alerts` | 9 | 9 |
| `runtime_capture_artifacts` | 21 | 21 |
| `runtime_validation_runs` | 26 | 26 |

### 3. Seluruh primary key

Semua tabel memakai PK tunggal `id`: `users.id`, `datasets.id`, `experiments.id`, `evaluation_results.id`, `evidence_sources.id`, `models.id`, `monitoring_sessions.id`, `traffic_flows.id`, `predictions.id`, `alerts.id`, `runtime_capture_artifacts.id`, `runtime_validation_runs.id`.

### 4. Seluruh foreign key

1. `datasets.created_by_user_id → users.id` SET NULL.
2. `experiments.dataset_id → datasets.id` SET NULL.
3. `evaluation_results.experiment_id → experiments.id` CASCADE.
4. `models.experiment_id → experiments.id` SET NULL.
5. `monitoring_sessions.model_id → models.id` RESTRICT.
6. `monitoring_sessions.created_by_user_id → users.id` SET NULL.
7. `predictions.traffic_flow_id → traffic_flows.id` CASCADE.
8. `predictions.model_id → models.id` RESTRICT.
9. `predictions.experiment_id → experiments.id` SET NULL.
10. `predictions.monitoring_session_id → monitoring_sessions.id` SET NULL.
11. `predictions.runtime_artifact_id → runtime_capture_artifacts.id` SET NULL.
12. `alerts.prediction_id → predictions.id` CASCADE.
13. `alerts.acknowledged_by_user_id → users.id` SET NULL.
14. `runtime_capture_artifacts.monitoring_session_id → monitoring_sessions.id` CASCADE.
15. `runtime_validation_runs.monitoring_session_id → monitoring_sessions.id` CASCADE.
16. `runtime_validation_runs.model_id → models.id` RESTRICT.

### 5. Unique constraints

- `users.email`; `experiments.experiment_code`; `models.model_version` (dinyatakan sebagai unique indexes).
- `evaluation_results`: `(experiment_id, metric_key)`.
- `evidence_sources`: `(owner_type, owner_key, evidence_role)` dan `source_path`.
- `monitoring_sessions`: `artifact_key`; partial unique active status.
- `predictions`: `traffic_flow_id`; `(source_type, external_key)`.
- `alerts`: `prediction_id`.
- `runtime_capture_artifacts`: `(monitoring_session_id, window_number)` dan `artifact_key`.

### 6. Seluruh index non-PK penting

- `users`: `ix_users_email` (UQ), `ix_users_is_active`.
- `datasets`: `ix_datasets_source_sha256`, `ix_datasets_created_by_user_id`.
- `experiments`: `ix_experiments_experiment_code` (UQ), `ix_experiments_dataset_id`, `ix_experiments_source_sha256`.
- `evaluation_results`: `ix_evaluation_results_experiment_id`, `uq_evaluation_metric_key` (UQ).
- `evidence_sources`: `ix_evidence_sources_owner_type`, `ix_evidence_sources_owner_key`, dua index UQ constraint.
- `models`: `ix_models_model_version` (UQ), `ix_models_is_active`, `ix_models_experiment_id`.
- `monitoring_sessions`: `ix_monitoring_sessions_model_id`, `ix_monitoring_sessions_status`, `ix_monitoring_sessions_created_by_user_id`, `ix_monitoring_sessions_status_created`, `uq_monitoring_sessions_artifact_key` (UQ), `uq_monitoring_sessions_single_active` (partial UQ).
- `traffic_flows`: `ix_traffic_flows_capture_time`, `ix_traffic_flows_source_ip`, `ix_traffic_flows_destination_ip`, `ix_traffic_flows_capture_session_id`.
- `predictions`: `ix_predictions_model_id`, `ix_predictions_predicted_label`, `ix_predictions_label_time`, `ix_predictions_experiment_id`, `ix_predictions_source_type`, `ix_predictions_monitoring_session_id`, `ix_predictions_runtime_artifact_id`, serta dua UQ indexes.
- `alerts`: `ix_alerts_severity`, `ix_alerts_status`, `ix_alerts_status_severity`, `ix_alerts_acknowledged_by_user_id`, UQ prediction index.
- `runtime_capture_artifacts`: `ix_runtime_capture_artifacts_monitoring_session_id`, `ix_runtime_artifact_session_state`, dua UQ indexes.
- `runtime_validation_runs`: `ix_runtime_validation_runs_monitoring_session_id`, `ix_runtime_validation_session_created`. Tidak ada index `model_id`.

### 7. ORM vs Alembic mismatches

1. Table dan column set pada ORM sesuai target head, termasuk tiga kolom pemilihan model.
2. `runtime_validation_runs.evidence_json`: migration membuat `JSON`; ORM `PortableJSON` menargetkan `JSONB` (`models.py:340`). Ini mismatch tipe nyata.
3. `monitoring_sessions.selection_mode`: migration mempunyai server default `DEFAULT`; ORM hanya mendefinisikan client default.
4. Beberapa counter mempunyai server default di migration dan client default di ORM; timestamp/status lain umumnya hanya client default ORM.
5. `runtime_validation_runs.model_id` dan `predictions.monitoring_session_id` adalah FK fisik tetapi tidak mempunyai `relationship()` ORM eksplisit.
6. ORM tidak mendefinisikan index untuk `runtime_validation_runs.model_id`; migration juga tidak.
7. Urutan deklarasi ORM berbeda dari urutan fisik migration pada `models`, `monitoring_sessions`, `traffic_flows`, `predictions`, `alerts`, dan `evaluation_results`; spesifikasi ini memakai urutan migration.

### 8. Live PostgreSQL verification

**BERHASIL**, read-only. `transaction_read_only=on`; live revision `20260905_08`; 12 application tables hadir. Perbedaan live terhadap head/source:

- Belum menerapkan `20260917_09` dan `20260917_10`: `monitoring_sessions.selection_mode`, `selected_model_version`, `selected_model_sha256` belum ada.
- Live `traffic_flows.raw_features` dan `predictions.class_probabilities` adalah `JSON`, sementara source migration portable type menargetkan PostgreSQL `JSONB`.
- Live FK `predictions.traffic_flow_id`, `predictions.model_id`, dan `alerts.prediction_id` menampilkan default `NO ACTION`, sementara migration source menyatakan masing-masing `CASCADE`, `RESTRICT`, dan `CASCADE`.
- Perbedaan tersebut adalah schema drift/revision lag yang dilaporkan, bukan diperbaiki.

### 9. Confidence level

**HIGH** untuk Alembic head, ORM, dan live schema yang berhasil diintrospeksi. Spesifikasi target mengikuti authority yang diminta (Alembic head); kolom bertanda live difference tidak diklaim sudah ada pada live DB.

## Thesis-Ready Database Specification

Bagian berikut adalah ringkasan siap salin. Detail default, references, constraints, dan indexes tetap mengacu pada tabel audit lengkap di atas.

### Nama Tabel: `users`

**Fungsi:** Menyimpan akun administrator dan identitas aktor audit.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID pengguna |
| 2 | name | VARCHAR | 200 | — | Tidak | Nama administrator |
| 3 | email | VARCHAR | 320 | UNIQUE | Tidak | Email login |
| 4 | password_hash | VARCHAR | 512 | — | Tidak | Hash kata sandi |
| 5 | role | VARCHAR | 30 | — | Tidak | Peran ADMIN |
| 6 | is_active | BOOLEAN | — | — | Tidak | Status akun |
| 7 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 8 | updated_at | TIMESTAMPTZ | — | — | Tidak | Waktu diperbarui |

### Nama Tabel: `datasets`

**Fungsi:** Menyimpan metadata dataset ilmiah.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID dataset |
| 2 | name | VARCHAR | 255 | — | Tidak | Nama dataset |
| 3 | source_path | VARCHAR | 1000 | — | Ya | Path sumber |
| 4 | source_sha256 | VARCHAR | 64 | — | Ya | Hash sumber |
| 5 | total_rows | INTEGER | 32-bit | — | Ya | Jumlah baris |
| 6 | total_features | INTEGER | 32-bit | — | Ya | Jumlah fitur |
| 7 | label_column | VARCHAR | 255 | — | Ya | Kolom label |
| 8 | class_distribution | JSONB | — | — | Ya | Distribusi kelas |
| 9 | created_by_user_id | INTEGER | 32-bit | FK | Ya | → users.id, SET NULL |
| 10 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 11 | updated_at | TIMESTAMPTZ | — | — | Tidak | Waktu diperbarui |

### Nama Tabel: `experiments`

**Fungsi:** Menyimpan metadata eksperimen ilmiah.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID eksperimen |
| 2 | experiment_code | VARCHAR | 100 | UNIQUE | Tidak | Kode eksperimen |
| 3 | experiment_name | VARCHAR | 255 | — | Tidak | Nama eksperimen |
| 4 | experiment_type | VARCHAR | 100 | — | Tidak | Jenis eksperimen |
| 5 | dataset_id | INTEGER | 32-bit | FK | Ya | → datasets.id, SET NULL |
| 6 | description | TEXT | — | — | Ya | Deskripsi |
| 7 | status | VARCHAR | 50 | — | Tidak | Status |
| 8 | source_path | VARCHAR | 1000 | — | Ya | Path sumber |
| 9 | source_sha256 | VARCHAR | 64 | — | Ya | Hash sumber |
| 10 | schema_version | VARCHAR | 100 | — | Ya | Versi schema |
| 11 | imported_at | TIMESTAMPTZ | — | — | Ya | Waktu impor |
| 12 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 13 | updated_at | TIMESTAMPTZ | — | — | Tidak | Waktu diperbarui |

### Nama Tabel: `evaluation_results`

**Fungsi:** Menyimpan metrik evaluasi model.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID hasil |
| 2 | experiment_id | INTEGER | 32-bit | FK, UQ gabungan | Tidak | → experiments.id, CASCADE |
| 3 | class_name | VARCHAR | 100 | — | Ya | Nama kelas |
| 4 | accuracy | DOUBLE PRECISION | 53-bit | — | Ya | Akurasi |
| 5 | precision_score | DOUBLE PRECISION | 53-bit | — | Ya | Precision |
| 6 | recall_score | DOUBLE PRECISION | 53-bit | — | Ya | Recall |
| 7 | f1_score | DOUBLE PRECISION | 53-bit | — | Ya | F1-score |
| 8 | macro_precision | DOUBLE PRECISION | 53-bit | — | Ya | Macro precision |
| 9 | macro_recall | DOUBLE PRECISION | 53-bit | — | Ya | Macro recall |
| 10 | macro_f1 | DOUBLE PRECISION | 53-bit | — | Ya | Macro F1 |
| 11 | false_positive_rate | DOUBLE PRECISION | 53-bit | — | Ya | False-positive rate |
| 12 | true_positive | INTEGER | 32-bit | — | Ya | True positive |
| 13 | true_negative | INTEGER | 32-bit | — | Ya | True negative |
| 14 | false_positive | INTEGER | 32-bit | — | Ya | False positive |
| 15 | false_negative | INTEGER | 32-bit | — | Ya | False negative |
| 16 | confusion_matrix | JSONB | — | — | Ya | Matriks konfusi |
| 17 | notes | TEXT | — | — | Ya | Catatan |
| 18 | source_path | VARCHAR | 1000 | — | Ya | Path sumber |
| 19 | source_sha256 | VARCHAR | 64 | — | Ya | Hash sumber |
| 20 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 21 | metric_key | VARCHAR | 150 | UQ gabungan | Ya | Kunci metrik |

### Nama Tabel: `evidence_sources`

**Fungsi:** Menyimpan provenance file evidence.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID evidence |
| 2 | owner_type | VARCHAR | 50 | UQ gabungan | Tidak | Pemilik logis, bukan FK |
| 3 | owner_key | VARCHAR | 150 | UQ gabungan | Tidak | Kunci logis, bukan FK |
| 4 | evidence_role | VARCHAR | 100 | UQ gabungan | Tidak | Peran evidence |
| 5 | source_path | VARCHAR | 1000 | UNIQUE | Tidak | Path sumber |
| 6 | source_sha256 | VARCHAR | 64 | — | Tidak | Hash sumber |
| 7 | schema_version | VARCHAR | 100 | — | Ya | Versi schema |
| 8 | imported_at | TIMESTAMPTZ | — | — | Tidak | Waktu impor |

### Nama Tabel: `models`

**Fungsi:** Menyimpan registry metadata model.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID model |
| 2 | model_name | VARCHAR | 200 | — | Tidak | Nama model |
| 3 | model_version | VARCHAR | 100 | UNIQUE | Tidak | Versi model |
| 4 | algorithm | VARCHAR | 100 | — | Tidak | Algoritma |
| 5 | accuracy | DOUBLE PRECISION | 53-bit | — | Ya | Akurasi |
| 6 | macro_f1 | DOUBLE PRECISION | 53-bit | — | Ya | Macro F1 |
| 7 | ddos_recall | DOUBLE PRECISION | 53-bit | — | Ya | Recall DDoS |
| 8 | portscan_recall | DOUBLE PRECISION | 53-bit | — | Ya | Recall PortScan |
| 9 | is_active | BOOLEAN | — | — | Tidak | Status aktif |
| 10 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 11 | experiment_id | INTEGER | 32-bit | FK | Ya | → experiments.id, SET NULL |
| 12 | artifact_path | VARCHAR | 1000 | — | Ya | Path artifact |
| 13 | artifact_sha256 | VARCHAR | 64 | — | Ya | Hash artifact |
| 14 | parameters | JSONB | — | — | Ya | Parameter model |
| 15 | feature_count | INTEGER | 32-bit | — | Ya | Jumlah fitur |

### Nama Tabel: `monitoring_sessions`

**Fungsi:** Menyimpan lifecycle monitoring dan snapshot model.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID sesi |
| 2 | target_ip | VARCHAR | 45 | — | Tidak | IP target |
| 3 | interface_name | VARCHAR | 100 | — | Tidak | Interface |
| 4 | model_id | INTEGER | 32-bit | FK | Tidak | → models.id, RESTRICT |
| 5 | status | VARCHAR | 20 | — | Tidak | Status lifecycle |
| 6 | started_at | TIMESTAMPTZ | — | — | Ya | Waktu mulai |
| 7 | stopped_at | TIMESTAMPTZ | — | — | Ya | Waktu berhenti |
| 8 | created_by_user_id | INTEGER | 32-bit | FK | Ya | → users.id, SET NULL |
| 9 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 10 | updated_at | TIMESTAMPTZ | — | — | Tidak | Waktu diperbarui |
| 11 | last_error | TEXT | — | — | Ya | Error terakhir |
| 12 | runtime_handle | VARCHAR | 100 | — | Ya | Handle runtime |
| 13 | flow_count | INTEGER | 32-bit | — | Tidak | Jumlah flow |
| 14 | prediction_count | INTEGER | 32-bit | — | Tidak | Jumlah prediksi |
| 15 | alert_count | INTEGER | 32-bit | — | Tidak | Jumlah alert |
| 16 | extractor_name | VARCHAR | 150 | — | Ya | Nama extractor |
| 17 | extractor_version | VARCHAR | 100 | — | Ya | Versi extractor |
| 18 | latest_processing_at | TIMESTAMPTZ | — | — | Ya | Proses terakhir |
| 19 | extractor_identity | VARCHAR | 300 | — | Ya | Identitas extractor |
| 20 | artifact_key | VARCHAR | 36 | UNIQUE | Ya | Kunci artifact |
| 21 | artifact_root | VARCHAR | 1000 | — | Ya | Root artifact |
| 22 | processing_state | VARCHAR | 30 | — | Ya | State pemrosesan |
| 23 | selection_mode | VARCHAR | 64 | — | Tidak | Target head; live belum ada |
| 24 | selected_model_version | VARCHAR | 100 | — | Ya | Target head; live belum ada |
| 25 | selected_model_sha256 | VARCHAR | 64 | — | Ya | Target head; live belum ada |

### Nama Tabel: `traffic_flows`

**Fungsi:** Menyimpan metadata flow dan fitur.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID flow |
| 2 | capture_time | TIMESTAMPTZ | — | — | Ya | Waktu capture |
| 3 | source_ip | VARCHAR | 45 | — | Ya | IP sumber |
| 4 | source_port | INTEGER | 32-bit | — | Ya | Port sumber |
| 5 | destination_ip | VARCHAR | 45 | — | Ya | IP tujuan |
| 6 | destination_port | INTEGER | 32-bit | — | Ya | Port tujuan |
| 7 | protocol | VARCHAR | 30 | — | Ya | Protokol |
| 8 | raw_features | JSONB | — | — | Tidak | Target head; live JSON |
| 9 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 10 | capture_session_id | VARCHAR | 80 | — | Ya | Identitas capture |
| 11 | capture_interface | VARCHAR | 100 | — | Ya | Interface capture |
| 12 | pcap_segment | VARCHAR | 255 | — | Ya | Segmen PCAP |

### Nama Tabel: `predictions`

**Fungsi:** Menyimpan hasil klasifikasi dan provenance.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID prediksi |
| 2 | traffic_flow_id | INTEGER | 32-bit | FK, UNIQUE | Tidak | → traffic_flows.id, CASCADE target |
| 3 | model_id | INTEGER | 32-bit | FK | Tidak | → models.id, RESTRICT target |
| 4 | predicted_label | VARCHAR | 50 | — | Tidak | Label prediksi |
| 5 | confidence_score | DOUBLE PRECISION | 53-bit | — | Tidak | Confidence |
| 6 | class_probabilities | JSONB | — | — | Tidak | Target head; live JSON |
| 7 | prediction_time | TIMESTAMPTZ | — | — | Tidak | Waktu prediksi |
| 8 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 9 | experiment_id | INTEGER | 32-bit | FK | Ya | → experiments.id, SET NULL |
| 10 | source_type | VARCHAR | 50 | UQ gabungan | Ya | Tipe sumber |
| 11 | external_key | VARCHAR | 255 | UQ gabungan | Ya | Kunci eksternal |
| 12 | monitoring_session_id | INTEGER | 32-bit | FK | Ya | → monitoring_sessions.id, SET NULL |
| 13 | runtime_artifact_id | INTEGER | 32-bit | FK | Ya | → runtime_capture_artifacts.id, SET NULL |

### Nama Tabel: `alerts`

**Fungsi:** Menyimpan alert dan acknowledgement.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID alert |
| 2 | prediction_id | INTEGER | 32-bit | FK, UNIQUE | Tidak | → predictions.id, CASCADE target |
| 3 | severity | VARCHAR | 20 | — | Tidak | Severity |
| 4 | title | VARCHAR | 200 | — | Tidak | Judul |
| 5 | description | TEXT | — | — | Tidak | Deskripsi |
| 6 | status | VARCHAR | 30 | — | Tidak | Status |
| 7 | acknowledged_at | TIMESTAMPTZ | — | — | Ya | Waktu acknowledgement |
| 8 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
| 9 | acknowledged_by_user_id | INTEGER | 32-bit | FK | Ya | → users.id, SET NULL |

### Nama Tabel: `runtime_capture_artifacts`

**Fungsi:** Menyimpan provenance window PCAP/CSV runtime.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID artifact |
| 2 | monitoring_session_id | INTEGER | 32-bit | FK, UQ gabungan | Tidak | → monitoring_sessions.id, CASCADE |
| 3 | artifact_key | VARCHAR | 36 | UNIQUE | Tidak | Kunci artifact |
| 4 | window_number | INTEGER | 32-bit | UQ gabungan | Tidak | Nomor window |
| 5 | state | VARCHAR | 20 | — | Tidak | State artifact |
| 6 | pcap_relative_path | VARCHAR | 1000 | — | Ya | Path PCAP |
| 7 | pcap_sha256 | VARCHAR | 64 | — | Ya | Hash PCAP |
| 8 | pcap_size | INTEGER | 32-bit | — | Ya | Ukuran PCAP |
| 9 | csv_relative_path | VARCHAR | 1000 | — | Ya | Path CSV |
| 10 | csv_sha256 | VARCHAR | 64 | — | Ya | Hash CSV |
| 11 | csv_size | INTEGER | 32-bit | — | Ya | Ukuran CSV |
| 12 | extractor_identity | VARCHAR | 300 | — | Ya | Identitas extractor |
| 13 | extracted_row_count | INTEGER | 32-bit | — | Tidak | Baris ekstraksi |
| 14 | adapted_row_count | INTEGER | 32-bit | — | Tidak | Baris adaptasi |
| 15 | error_stage | VARCHAR | 50 | — | Ya | Tahap error |
| 16 | error_message | TEXT | — | — | Ya | Pesan error |
| 17 | capture_started_at | TIMESTAMPTZ | — | — | Ya | Capture mulai |
| 18 | capture_finished_at | TIMESTAMPTZ | — | — | Ya | Capture selesai |
| 19 | extraction_finished_at | TIMESTAMPTZ | — | — | Ya | Ekstraksi selesai |
| 20 | committed_at | TIMESTAMPTZ | — | — | Ya | Waktu commit |
| 21 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |

### Nama Tabel: `runtime_validation_runs`

**Fungsi:** Menyimpan evidence dan hasil validasi runtime.  
**Primary Key:** `id`

| No. | Field | Tipe Data | Panjang | Key | Null | Keterangan |
|---:|---|---|---|---|---|---|
| 1 | id | INTEGER | 32-bit | PK | Tidak | ID validasi |
| 2 | monitoring_session_id | INTEGER | 32-bit | FK | Tidak | → monitoring_sessions.id, CASCADE |
| 3 | scenario | VARCHAR | 30 | — | Tidak | Skenario |
| 4 | status | VARCHAR | 20 | — | Tidak | Status |
| 5 | target_ip | VARCHAR | 45 | — | Tidak | IP target |
| 6 | interface_name | VARCHAR | 100 | — | Tidak | Interface |
| 7 | started_at | TIMESTAMPTZ | — | — | Tidak | Waktu mulai |
| 8 | finished_at | TIMESTAMPTZ | — | — | Ya | Waktu selesai |
| 9 | pcap_files_processed | INTEGER | 32-bit | — | Tidak | File PCAP |
| 10 | pcap_bytes_processed | INTEGER | 32-bit | — | Tidak | Byte PCAP |
| 11 | flows_extracted | INTEGER | 32-bit | — | Tidak | Flow diekstrak |
| 12 | flows_adapter_valid | INTEGER | 32-bit | — | Tidak | Flow valid |
| 13 | predictions_committed | INTEGER | 32-bit | — | Tidak | Prediksi tersimpan |
| 14 | alerts_committed | INTEGER | 32-bit | — | Tidak | Alert tersimpan |
| 15 | normal_predictions | INTEGER | 32-bit | — | Tidak | Prediksi Normal |
| 16 | portscan_predictions | INTEGER | 32-bit | — | Tidak | Prediksi PortScan |
| 17 | ddos_predictions | INTEGER | 32-bit | — | Tidak | Prediksi DDoS |
| 18 | pipeline_result | VARCHAR | 20 | — | Tidak | Hasil pipeline |
| 19 | detection_result | VARCHAR | 20 | — | Tidak | Hasil deteksi |
| 20 | extractor_identity | VARCHAR | 300 | — | Ya | Identitas extractor |
| 21 | adapter_identity | VARCHAR | 300 | — | Ya | Identitas adapter |
| 22 | model_id | INTEGER | 32-bit | FK | Tidak | → models.id, RESTRICT |
| 23 | model_version | VARCHAR | 100 | — | Tidak | Snapshot versi |
| 24 | evidence_json | JSON | — | — | Tidak | Evidence JSON |
| 25 | notes | TEXT | — | — | Ya | Catatan |
| 26 | created_at | TIMESTAMPTZ | — | — | Tidak | Waktu dibuat |
