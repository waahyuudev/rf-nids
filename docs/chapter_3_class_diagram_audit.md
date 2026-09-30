# Audit Class Diagram BAB III RF-NIDS

## 1. Ruang Lingkup dan Metode

Status audit: **VERIFIED** melalui inspeksi statis source code. Audit ini tidak menjalankan migrasi, database, training, inference, monitoring, atau perubahan konfigurasi/dataset/model artifact. Satu-satunya file yang dibuat adalah laporan ini.

Konvensi:

- **DATABASE COLUMN**: atribut hasil `mapped_column(...)`.
- **ORM RELATIONSHIP**: atribut hasil `relationship(...)`.
- **CLASS METHOD**: fungsi yang benar-benar didefinisikan dalam body class.
- **FK-only**: foreign key fisik ada, tetapi atribut `relationship(...)` tidak didefinisikan.
- Kardinalitas memakai `0..1`, `1`, dan `0..*`; nullability FK dan constraint `unique=True` menjadi dasar batas bawah/atas.
- Semua path bersifat relatif terhadap root repository.

Temuan utama:

1. Dua belas entity ORM memang ada di satu file, tetapi nama Python aktual untuk entity `Model` adalah **`ModelRecord`**, bukan `Model` (`src/api/models.py:155-181`).
2. Semua 12 entity ORM tidak mendefinisikan method, property, atau hybrid property: **NO EXPLICIT METHODS**.
3. `EvidenceSource` menggunakan pemilik logis `owner_type`/`owner_key`; tidak mempunyai FK atau ORM relationship (`src/api/models.py:137-152`).
4. `MonitoringSession -> TrafficFlow` **NOT PRESENT**. `TrafficFlow.capture_session_id` hanyalah string, bukan FK (`src/api/models.py:346-366`). Hubungan runtime yang fisik adalah `MonitoringSession <- Prediction.monitoring_session_id` (`src/api/models.py:391-392`).
5. `RuntimeValidationRun.model_id` adalah FK fisik ke `models.id`, tetapi tidak ada ORM relationship ke `ModelRecord` (`src/api/models.py:338-343`). Hal serupa berlaku untuk `Prediction.monitoring_session_id`: FK ada, relationship ORM tidak ada (`src/api/models.py:391-410`).

## 2. Audit Persistence / ORM

Seluruh class berikut berada di `src/api/models.py` dan mewarisi `Base` dari `src/api/database.py:12`.

### 2.1 `User` — VERIFIED

- Evidence class/table: `src/api/models.py:34-55`; `__tablename__ = "users"` pada baris 35.
- DATABASE COLUMNS: `id: int` PK (39); `name: str` (40); `email: str` unique/index (41); `password_hash: str` (42); `role: str` (43); `is_active: bool` (44); `created_at: datetime` (45); `updated_at: datetime` (46-48).
- FOREIGN KEYS: tidak ada.
- ORM RELATIONSHIPS: `datasets: list[Dataset]` (49); `acknowledged_alerts: list[Alert]` (50-52); `monitoring_sessions: list[MonitoringSession]` (53-55).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.2 `Dataset` — VERIFIED

- Evidence class/table: `src/api/models.py:58-76`; table `datasets` (59).
- DATABASE COLUMNS: `id: int` PK (60); `name: str` (61); `source_path: str | None` (62); `source_sha256: str | None` (63); `total_rows: int | None` (64); `total_features: int | None` (65); `label_column: str | None` (66); `class_distribution: dict | None` (67); `created_by_user_id: int | None` (68-70); `created_at: datetime` (71); `updated_at: datetime` (72-74).
- FOREIGN KEY: `created_by_user_id -> users.id`, nullable, `ON DELETE SET NULL` (68-70).
- ORM RELATIONSHIPS: `created_by_user: User | None` (75); `experiments: list[Experiment]` (76).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.3 `Experiment` — VERIFIED

- Evidence class/table: `src/api/models.py:79-103`; table `experiments` (80).
- DATABASE COLUMNS: `id: int` PK (81); `experiment_code: str` unique/index (82); `experiment_name: str` (83); `experiment_type: str` (84); `dataset_id: int | None` (85-87); `description: str | None` (88); `status: str` (89); `source_path: str | None` (90); `source_sha256: str | None` (91); `schema_version: str | None` (92); `imported_at: datetime | None` (93); `created_at: datetime` (94); `updated_at: datetime` (95-97).
- FOREIGN KEY: `dataset_id -> datasets.id`, nullable, `ON DELETE SET NULL` (85-87).
- ORM RELATIONSHIPS: `dataset: Dataset | None` (98); `evaluation_results: list[EvaluationResult]` with delete-orphan composition semantics (99-101); `models: list[ModelRecord]` (102); `predictions: list[Prediction]` (103).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.4 `EvaluationResult` — VERIFIED

- Evidence class/table: `src/api/models.py:106-134`; table `evaluation_results` (107).
- DATABASE COLUMNS: `id: int` PK (111); `experiment_id: int` (112-114); `class_name: str | None` (115); `metric_key: str | None` (116); `accuracy`, `precision_score`, `recall_score`, `f1_score`, `macro_precision`, `macro_recall`, `macro_f1`, `false_positive_rate: float | None` (117-124); `true_positive`, `true_negative`, `false_positive`, `false_negative: int | None` (125-128); `confusion_matrix: dict | list | None` (129); `notes: str | None` (130); `source_path: str | None` (131); `source_sha256: str | None` (132); `created_at: datetime` (133).
- PRIMARY/FOREIGN KEY: PK `id`; `experiment_id -> experiments.id`, non-null, `ON DELETE CASCADE` (112-114).
- ORM RELATIONSHIP: `experiment: Experiment` (134).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.5 `EvidenceSource` — VERIFIED

- Evidence class/table: `src/api/models.py:137-152`; table `evidence_sources` (138).
- DATABASE COLUMNS: `id: int` PK (145); `owner_type: str` (146); `owner_key: str` (147); `evidence_role: str` (148); `source_path: str` (149); `source_sha256: str` (150); `schema_version: str | None` (151); `imported_at: datetime` (152).
- FOREIGN KEYS: **NONE**.
- ORM RELATIONSHIPS: **NONE**.
- Ownership is logical/polymorphic by string only. Penggunaan query juga membandingkan `owner_type` dan `owner_key`, bukan join/FK (`src/application/evidence_sync.py:272-292`; `src/api/main.py:1000-1003`).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.6 `ModelRecord` (bukan `Model`) — VERIFIED

- Evidence class/table: `src/api/models.py:155-181`; table `models` (156).
- DATABASE COLUMNS: `id: int` PK (157); `model_name: str` (158); `model_version: str` unique/index (159); `algorithm: str` (160); `accuracy`, `macro_f1`, `ddos_recall`, `portscan_recall: float | None` (161-164); `feature_count: int | None` (165); `is_active: bool` (166); `experiment_id: int | None` (167-169); `artifact_path: str | None` (170); `artifact_sha256: str | None` (171); `parameters: dict | None` (172); `created_at: datetime` (173).
- FOREIGN KEY: `experiment_id -> experiments.id`, nullable, `ON DELETE SET NULL` (167-169).
- ORM RELATIONSHIPS: `predictions: list[Prediction]` (175-177); `experiment: Experiment | None` (178); `monitoring_sessions: list[MonitoringSession]` (179-181).
- Tidak ada relationship ke `RuntimeValidationRun`, walaupun tabel tersebut menyimpan `model_id` FK.
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.7 `MonitoringSession` — VERIFIED

- Evidence class/table: `src/api/models.py:184-245`; table `monitoring_sessions` (187).
- DATABASE COLUMNS: `id: int` PK (205); `target_ip: str` (206); `interface_name: str` (207); `model_id: int` (208-210); `selection_mode: str` (211); `selected_model_version: str | None` (212); `selected_model_sha256: str | None` (213); `status: str` (214); `started_at`, `stopped_at: datetime | None` (215-216); `created_by_user_id: int | None` (217-219); `created_at: datetime` (220); `updated_at: datetime` (221-223); `last_error: str | None` (224); `runtime_handle: str | None` (225); `extractor_name`, `extractor_version`, `extractor_identity: str | None` (226-228); `artifact_key: str | None` unique (229); `artifact_root: str | None` (230); `processing_state: str | None` (231); `latest_processing_at: datetime | None` (232); `flow_count`, `prediction_count`, `alert_count: int` (233-235).
- FOREIGN KEYS: `model_id -> models.id`, non-null, RESTRICT (208-210); `created_by_user_id -> users.id`, nullable, SET NULL (217-219).
- ORM RELATIONSHIPS: `model: ModelRecord` (236); `created_by_user: User | None` (237-239); `validation_runs: list[RuntimeValidationRun]` delete-orphan (240-242); `runtime_artifacts: list[RuntimeCaptureArtifact]` delete-orphan (243-245).
- Tidak ada `traffic_flows` atau `predictions` relationship attribute.
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.8 `RuntimeCaptureArtifact` — VERIFIED

- Evidence class/table: `src/api/models.py:248-289`; table `runtime_capture_artifacts` (251).
- DATABASE COLUMNS: `id: int` PK (263); `monitoring_session_id: int` (264-266); `artifact_key: str` (267); `window_number: int` (268); `state: str` (269); `pcap_relative_path: str | None` (270); `pcap_sha256: str | None` (271); `pcap_size: int | None` (272); `csv_relative_path: str | None` (273); `csv_sha256: str | None` (274); `csv_size: int | None` (275); `extractor_identity: str | None` (276); `extracted_row_count`, `adapted_row_count: int` (277-278); `error_stage`, `error_message: str | None` (279-280); `capture_started_at`, `capture_finished_at`, `extraction_finished_at`, `committed_at: datetime | None` (281-284); `created_at: datetime` (285).
- FOREIGN KEY: `monitoring_session_id -> monitoring_sessions.id`, non-null, CASCADE (264-266).
- ORM RELATIONSHIPS: `monitoring_session: MonitoringSession` (286-288); `predictions: list[Prediction]` (289).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.9 `RuntimeValidationRun` — VERIFIED

- Evidence class/table: `src/api/models.py:292-343`; table `runtime_validation_runs` (295).
- DATABASE COLUMNS: `id: int` PK (315); `monitoring_session_id: int` (316-318); `scenario: str` (319); `status: str` (320); `target_ip: str` (321); `interface_name: str` (322); `started_at: datetime` (323); `finished_at: datetime | None` (324); counters `pcap_files_processed`, `pcap_bytes_processed`, `flows_extracted`, `flows_adapter_valid`, `predictions_committed`, `alerts_committed`, `normal_predictions`, `portscan_predictions`, `ddos_predictions: int` (325-333); `pipeline_result`, `detection_result: str` (334-335); `extractor_identity`, `adapter_identity: str | None` (336-337); `model_id: int` (338); `model_version: str` (339); `evidence_json: dict` (340); `notes: str | None` (341); `created_at: datetime` (342).
- FOREIGN KEYS: `monitoring_session_id -> monitoring_sessions.id`, non-null, CASCADE (316-318); `model_id -> models.id`, non-null, RESTRICT (338).
- ORM RELATIONSHIP: hanya `monitoring_session: MonitoringSession` (343). Relasi model adalah **FK-only**.
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.10 `TrafficFlow` — VERIFIED

- Evidence class/table: `src/api/models.py:346-366`; table `traffic_flows` (347).
- DATABASE COLUMNS: `id: int` PK (348); `capture_session_id: str | None` (349); `capture_interface: str | None` (350); `pcap_segment: str | None` (351); `capture_time: datetime | None` (352); `source_ip: str | None` (353); `source_port: int | None` (354); `destination_ip: str | None` (355); `destination_port: int | None` (356); `protocol: str | None` (357); `raw_features: dict` (358); `created_at: datetime` (359).
- FOREIGN KEYS: **NONE**.
- ORM RELATIONSHIP: `prediction: Prediction | None` (361-366).
- `capture_session_id` bukan FK dan bertipe string; jangan gambar association fisik ke `MonitoringSession`.
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.11 `Prediction` — VERIFIED

- Evidence class/table: `src/api/models.py:369-415`; table `predictions` (370).
- DATABASE COLUMNS: `id: int` PK (381); `traffic_flow_id: int` unique (382-384); `model_id: int` (385-387); `experiment_id: int | None` (388-390); `monitoring_session_id: int | None` (391-393); `runtime_artifact_id: int | None` (394-396); `source_type: str | None` (397); `external_key: str | None` (398); `predicted_label: str` (399); `confidence_score: float` (400); `class_probabilities: dict` (401); `prediction_time: datetime` (402); `created_at: datetime` (403).
- FOREIGN KEYS: `traffic_flow_id -> traffic_flows.id`, non-null, CASCADE, unique (382-384); `model_id -> models.id`, non-null, RESTRICT (385-387); `experiment_id -> experiments.id`, nullable, SET NULL (388-390); `monitoring_session_id -> monitoring_sessions.id`, nullable, SET NULL (391-393); `runtime_artifact_id -> runtime_capture_artifacts.id`, nullable, SET NULL (394-396).
- ORM RELATIONSHIPS: `traffic_flow: TrafficFlow` (404); `model: ModelRecord` (405); `experiment: Experiment | None` (406); `runtime_artifact: RuntimeCaptureArtifact | None` (407-409); `alert: Alert | None` delete-orphan (410-415).
- `monitoring_session_id` adalah **FK-only**; tidak ada atribut `monitoring_session`.
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

### 2.12 `Alert` — VERIFIED

- Evidence class/table: `src/api/models.py:418-443`; table `alerts` (419).
- DATABASE COLUMNS: `id: int` PK (427); `prediction_id: int` unique (428-430); `severity: str` (431); `title: str` (432); `description: str` (433); `status: str` (434); `acknowledged_at: datetime | None` (435); `acknowledged_by_user_id: int | None` (436-438); `created_at: datetime` (439).
- FOREIGN KEYS: `prediction_id -> predictions.id`, non-null, CASCADE, unique (428-430); `acknowledged_by_user_id -> users.id`, nullable, SET NULL (436-438).
- ORM RELATIONSHIPS: `prediction: Prediction` (440); `acknowledged_by_user: User | None` (441-443).
- Methods/properties/hybrid properties: **NO EXPLICIT METHODS**.

## 3. Verifikasi Relationship Persistence

| Source | Target | Jenis | Kardinalitas | Status dan evidence |
|---|---|---|---|---|
| User | Dataset | ASSOCIATION, bidirectional ORM | User `0..1` — Dataset `0..*` | **VERIFIED**: nullable FK `Dataset.created_by_user_id` dan relationships (`src/api/models.py:49,68-76`) |
| User | MonitoringSession | ASSOCIATION, bidirectional ORM | User `0..1` — Session `0..*` | **VERIFIED** (`src/api/models.py:53-55,217-239`) |
| User | Alert | ASSOCIATION, bidirectional ORM | User `0..1` — Alert `0..*` | **VERIFIED**; makna khusus acknowledgment (`src/api/models.py:50-52,436-443`) |
| Dataset | Experiment | ASSOCIATION, bidirectional ORM | Dataset `0..1` — Experiment `0..*` | **VERIFIED** (`src/api/models.py:76,85-98`) |
| Experiment | EvaluationResult | COMPOSITION-like ORM (`delete-orphan`) | Experiment `1` — Result `0..*`; tiap Result tepat `1` Experiment | **VERIFIED** (`src/api/models.py:99-101,112-134`) |
| Experiment | ModelRecord | ASSOCIATION, bidirectional ORM | Experiment `0..1` — Model `0..*` | **VERIFIED** (`src/api/models.py:102,167-178`) |
| Experiment | Prediction | ASSOCIATION, bidirectional ORM | Experiment `0..1` — Prediction `0..*` | **VERIFIED** (`src/api/models.py:103,388-406`) |
| ModelRecord | MonitoringSession | ASSOCIATION, bidirectional ORM | Model `1` — Session `0..*`; tiap Session tepat `1` Model | **VERIFIED** (`src/api/models.py:179-181,208-210,236`) |
| ModelRecord | Prediction | ASSOCIATION, bidirectional ORM | Model `1` — Prediction `0..*`; tiap Prediction tepat `1` Model | **VERIFIED** (`src/api/models.py:175-177,385-405`) |
| ModelRecord | RuntimeValidationRun | ASSOCIATION at database level, FK-only | Model `1` — Run `0..*`; tiap Run tepat `1` Model | **VERIFIED FK / NOT PRESENT ORM** (`src/api/models.py:338-343`) |
| MonitoringSession | RuntimeCaptureArtifact | COMPOSITION-like ORM (`delete-orphan`, CASCADE FK) | Session `1` — Artifact `0..*` | **VERIFIED** (`src/api/models.py:240-245,264-289`) |
| MonitoringSession | RuntimeValidationRun | COMPOSITION-like ORM (`delete-orphan`, CASCADE FK) | Session `1` — Run `0..*` | **VERIFIED** (`src/api/models.py:240-242,316-343`) |
| MonitoringSession | Prediction | ASSOCIATION at database level, FK-only | Session `0..1` — Prediction `0..*` | **VERIFIED FK / NOT PRESENT ORM** (`src/api/models.py:391-393`); runtime query memakai FK (`src/api/runtime_monitoring.py:535-545`) |
| RuntimeCaptureArtifact | Prediction | ASSOCIATION, bidirectional ORM | Artifact `0..1` — Prediction `0..*` | **VERIFIED** (`src/api/models.py:289,394-409`) |
| TrafficFlow | Prediction | COMPOSITION-like ORM, one-to-zero-or-one | Flow `1` — Prediction `0..1`; tiap Prediction tepat `1` Flow | **VERIFIED**; unique FK (`src/api/models.py:361-366,382-404`) |
| Prediction | Alert | COMPOSITION-like ORM, one-to-zero-or-one | Prediction `1` — Alert `0..1`; tiap Alert tepat `1` Prediction | **VERIFIED**; unique FK (`src/api/models.py:410-415,428-440`) |
| MonitoringSession | TrafficFlow | tidak ada | — | **NOT PRESENT**: tidak ada FK/relationship; `capture_session_id` hanya string (`src/api/models.py:346-366`) |
| EvidenceSource | entity mana pun | logical reference only | — | **NOT PRESENT sebagai association fisik**: tidak ada FK/relationship (`src/api/models.py:137-152`) |

Catatan kardinalitas: list relationship SQLAlchemy tidak menjamin minimal satu child, sehingga sisi collection ditulis `0..*`. FK nullable menghasilkan `0..1` pada sisi parent; FK non-null menghasilkan `1`.

## 4. Audit Service / Application / Runtime

### 4.1 `RFNIDSClient` — VERIFIED

- File/class: `dashboard/api_client.py:25-226`.
- Responsibility: facade HTTP dashboard menuju FastAPI backend.
- Constructor: `__init__(base_url: str, timeout: float = 10, session=None, access_token: str | None=None, token_provider: Callable[[], str | None] | None=None)` (26-38).
- Public methods (return type tidak dideklarasikan): `health()` (99-100), `login(email: str, password: str)` (102-105), `current_user()` (107-108), `logout()` (110-111), `model_info()` (113-114), `active_model()` (116-117), `models()` (119-120), `datasets()` (122-123), `experiments()` (125-126), `experiment_evaluation(experiment_id: int)` (128-129), `evidence_sources(*, owner_type=None, owner_key=None)` (131-135), `summary()` (137-138), `timeline(minutes: int=60)` (140-141), `predictions(*, limit=20, offset=0, **filters)` (143-145), `prediction(prediction_id: int)` (147-148), `traffic_flows(*, limit=20, offset=0, **filters)` (150-156), `monitoring_summary()` (158-159), `monitoring_status()` (161-162), `monitoring_interfaces()` (164-165), `monitoring_models()` (167-168), `monitoring_sessions(*, limit=20, offset=0)` (170-171), `monitoring_session_predictions(session_id: int, *, limit=5)` (173-177), `start_monitoring(target_ip: str, interface_name: str, selected_model_id: str | None=None)` (179-185), `stop_monitoring()` (187-188), `create_runtime_validation(session_id: int, scenario: str)` (190-191), `runtime_validations(session_id: int)` (193-194), `complete_runtime_validation(session_id: int, validation_id: int)` (196-197), `alerts(*, limit=20, offset=0, **filters)` (199-205), `alert(alert_id: int)` (207-208), `acknowledge_alert(alert_id: int)` (210-211), `export_dataset()` (213-214), `export_experiment(experiment_id: int, format: str="json")` (216-217), `export_confusion_matrix(experiment_id: int)` (219-220), `export_predictions(format: str="csv", **filters)` (222-223), `export_alerts(format: str="csv", **filters)` (225-226).
- Private methods: `_access_token() -> str | None` (40-41), `_request(method: str, path: str, **kwargs) -> Any` (43-73), `_download(path: str, **params) -> Download` (75-97).
- Dependencies: `requests.Session`, `APIError`, `Download`; komunikasi dengan service backend hanya lewat HTTP, bukan object association langsung.

### 4.2 `MonitoringService` — VERIFIED

- File/class: `src/api/monitoring.py:54-213`.
- Responsibility: validasi dan lifecycle persistence monitoring; mendelegasikan eksekusi collector.
- Constructor: `__init__(collector: CollectorController | None=None)` (55-56).
- Public methods: static `active(db: Session) -> MonitoringSession | None` (58-64); `reconcile_stale_sessions(db: Session) -> int` (66-84); `start(db: Session, *, target_ip: str, interface_name: str, user: User, model_id: int | None=None, inference=None, selection_mode: str="DEFAULT")` tanpa declared return (86-173); `shutdown(db: Session) -> None` (175-177); `stop(db: Session)` tanpa declared return (179-213).
- Dependencies: association ke collector melalui `self.collector` (55-56), serta dependencies `Session`, `MonitoringSession`, `ModelRecord`, `User`; pemanggilan `collector.start/stop` pada baris 146-149 dan 190.
- Production wiring membangun `MonitoringService(RuntimeCollectorController(...))` (`src/api/main.py:290-300`).

### 4.3 `RuntimeCollectorController` — VERIFIED

- File/class: `src/api/runtime_monitoring.py:554-645`.
- Responsibility: registry worker in-memory, pembuatan root artifact sesi, lifecycle start/stop/status/shutdown.
- Constructor: `__init__(*, session_factory, inference, settings, worker_factory=RuntimeWorker)` (557-567).
- Public methods: `start(*, session_id: int, target_ip: str, interface_name: str, inference=None) -> str` (569-596); `stop(runtime_handle: str | None) -> bool` (598-613); `status(runtime_handle: str | None) -> str` (615-618); `shutdown()` tanpa declared return (620-627).
- Private method: `_on_exit(session_id, failure)` (629-645).
- Dependencies: `MonitoringSession`, session factory, injected inference/settings; `worker_factory` default `RuntimeWorker` dan worker disimpan dalam `_workers` (557-563,586-595). Ini adalah **COMPOSITION** terhadap worker pada runtime.

### 4.4 `RuntimeWorker` — VERIFIED

- File/class: `src/api/runtime_monitoring.py:311-551`.
- Responsibility: loop capture → extraction → adaptation → inference → transactional persistence dan refresh counter.
- Constructor: `__init__(*, session_id, session_factory, inference, settings, on_exit)` (312-332).
- Public methods: `start()` tanpa declared return (334-340); `stop(timeout: float)` tanpa declared return (342-353).
- Private methods: `_set_processing_state(state: str | None) -> None` (355-360), `_fail_artifact(artifact_id: int, stage: str, exc: Exception) -> None` (362-369), `_run()` (371-533), `_refresh_counts(db)` (535-551).
- Dependencies: owns `RuntimePipeline` instance (320-329); owns `threading.Thread` (330-332); creates `CICFlowMeterV3ModelAdapter` (376); reads/writes `MonitoringSession`, `RuntimeCaptureArtifact`, `Prediction`, `Alert`; calls injected inference `predict_batch` (489); calls module-level `persist_predictions(...)` (506-513). `persist_predictions` is **not** a class method (`src/api/service.py:76-131`).

### 4.5 `RuntimePipeline` — VERIFIED

- File/class: `src/api/runtime_monitoring.py:87-308`.
- Responsibility: preflight capture/extractor, bounded packet capture, path mapping, dan CICFlowMeter Docker extraction.
- Constructor: `__init__(*, root: Path, image: str, window_seconds: float, host_root: Path | None=None, expected_image_digest: str=..., extraction_timeout_seconds: float=120.0, source_commit: str=..., extractor_registry: RuntimeExtractorRegistry | None=None, popen=subprocess.Popen, run=subprocess.run)` (90-116).
- Public methods: `preflight(interface: str) -> None` (118-178); `request_stop() -> None` (180-188); `force_stop() -> None` (212-216); `capture(interface: str, target_ip: str, output: Path, stop: threading.Event)` tanpa declared return (218-254); `host_artifact_path(path: Path) -> Path` (256-265); `extract(pcap: Path, output_dir: Path) -> Path` (267-308).
- Private method: `_terminate_process(process, *, interrupt_first: bool=True) -> None` (190-210).
- Dependencies: composes/defaults `RuntimeExtractorRegistry` (`src/api/runtime_monitoring.py:96-107`), depends on subprocess/Docker/tcpdump/filesystem, and module-level `list_capture_interfaces` / `validate_pcap`. Tidak bergantung langsung pada `InferenceEngine`.

### 4.6 `InferenceEngine` — VERIFIED

- File/class: `src/inference/predictor.py:24-161`.
- Responsibility: load/verify model dan metadata, feature ordering/validation, single/batch prediction.
- Constructor: `__init__(model_path: Path, metadata_path: Path, *, extra_feature_policy: Literal["reject", "ignore"] | None=None, verify_model_hash: bool=True) -> None` (27-74).
- Public methods: `predict_one(features: Mapping[str, Any]) -> dict[str, Any]` (139-155); `predict_batch(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]` (157-161).
- Private methods: static `_normalize_demo_metadata(metadata: dict[str, Any]) -> dict[str, Any]` (76-91); static `_load_metadata(path: Path) -> dict[str, Any]` (93-103); `_prepare_row(features: Mapping[str, Any]) -> tuple[pd.DataFrame, list[str]]` (105-137).
- Dependencies: `joblib`, sklearn `Pipeline`, pandas/numpy, metadata/model files, hashing and column normalization.

### 4.7 `RuntimeValidationService` — VERIFIED

- File/class: `src/api/runtime_validation.py:30-201`.
- Responsibility: membuat validation run dan menurunkan evidence/result dari sesi, artifacts, predictions, flows, dan alerts.
- Constructor: `__init__(artifact_root: Path, expected_feature_names: list[str])` (31-33).
- Public methods: `create(db: Session, session_id: int, scenario: str) -> RuntimeValidationRun` (35-55); `complete(db: Session, session_id: int, validation_id: int) -> RuntimeValidationRun` (57-75).
- Private method: `_derive(db: Session, row: RuntimeValidationRun) -> None` (77-201).
- Dependencies: `MonitoringSession`, `RuntimeValidationRun`, `RuntimeCaptureArtifact`, `Prediction`, `Alert`, dan melalui prediction mengakses `TrafficFlow` (`src/api/runtime_validation.py:78-91,123-159`). Model identity disalin dari `session.model`, bukan melalui relationship `RuntimeValidationRun.model` (`src/api/runtime_validation.py:41-50`).

## 5. Controller / Client / Helper Arsitektural Tambahan

Class berikut relevan karena berada langsung pada jalur runtime, tetapi sebaiknya menjadi pendukung, bukan fokus utama diagram BAB III.

### `CollectorController` — VERIFIED test/lifecycle adapter

- File: `src/api/monitoring.py:30-42`.
- Responsibility: deterministic lifecycle test double; docstring eksplisit menyebut production menggunakan `RuntimeCollectorController` (30-31).
- Public methods: `start(*, session_id: int, target_ip: str, interface_name: str, inference=None) -> str` (35-36), `stop(runtime_handle: str | None) -> None` (38-39), `status(runtime_handle: str | None) -> str` (41-42).
- Recommendation: jangan tampilkan dalam production diagram, atau beri stereotype `<<test double>>` bila kontrak collector perlu dijelaskan.

### `RuntimeModelRegistry` — VERIFIED

- File: `src/api/runtime_models.py:68-145`.
- Responsibility: allowlist, verification, loading, dan resolution model runtime.
- Constructor: `__init__(engine_factory=InferenceEngine)` (71-80).
- Public methods: `resolve(model_id: str)` (117-136), `available()` (138-145), keduanya tanpa declared return type.
- Private method: static `_verify_and_load(approved, engine_factory)` (82-115).
- Dependency: creates `InferenceEngine` via factory (71-78,112-115); uses value object `ApprovedRuntimeModel` (`src/api/runtime_models.py:19-27`).

### `RuntimeExtractorRegistry` — VERIFIED

- File: `src/api/runtime_extractors.py:71-122`.
- Responsibility: verify pinned extractor identity dan repository evidence.
- Public method: `verify(image_digest: str, *, source_commit: str, adapter_identity: str=..., adapter_version: str=..., crosswalk_sha256: str=...) -> ApprovedRuntimeExtractor` (77-98).
- Private method: static `_verify_repository_evidence(approved: ApprovedRuntimeExtractor) -> None` (101-122).
- Dependency: digunakan/di-create oleh `RuntimePipeline` (`src/api/runtime_monitoring.py:96-107,167-170`).

### Adapter/extractor helpers — VERIFIED, opsional

- `CICFlowMeterV3ModelAdapter` adalah adapter yang benar-benar dibuat worker (`src/api/runtime_monitoring.py:376`) dan method `adapt(...)` dipanggil pada baris 454. Definisi: `src/ingestion/cicflowmeter_v3_adapter.py:135`.
- `FeatureAdapter` (`src/ingestion/feature_adapter.py:52-199`) dan `FlowCsvExtractor` (`src/ingestion/flow_extractor.py:12-30`) penting untuk pipeline ingestion umum, tetapi worker runtime V3 memakai `CICFlowMeterV3ModelAdapter` secara langsung. Jangan campurkan ke diagram runtime inti kecuali alur ingestion offline juga dibahas.
- `persist_predictions` adalah **MODULE-LEVEL FUNCTION**, bukan method service (`src/api/service.py:76-131`). Fungsi ini membuat `TrafficFlow`, `Prediction`, dan opsional `Alert` (`src/api/service.py:85-113`).

## 6. Verifikasi Dependency Service / Runtime

| Source | Target | UML | Evidence |
|---|---|---|---|
| RFNIDSClient | FastAPI endpoints | DEPENDENCY (HTTP) | Semua public operation mendelegasikan ke `_request`/`_download` (`dashboard/api_client.py:43-97,99-226`) |
| MonitoringService | RuntimeCollectorController | ASSOCIATION | Production object diinjeksi pada construction (`src/api/main.py:290-300`), disimpan sebagai `self.collector` (`src/api/monitoring.py:55-56`) |
| MonitoringService | MonitoringSession / ModelRecord / User | DEPENDENCY | Query/create/update ORM (`src/api/monitoring.py:59-173`) |
| RuntimeCollectorController | RuntimeWorker | COMPOSITION | Default factory, creates worker, stores in `_workers`, owns shutdown (`src/api/runtime_monitoring.py:557-567,586-627`) |
| RuntimeWorker | RuntimePipeline | COMPOSITION | Dibuat dan disimpan sebagai `self.pipeline` (`src/api/runtime_monitoring.py:320-329`) |
| RuntimeWorker | InferenceEngine | ASSOCIATION/DEPENDENCY | Inference object diinjeksi (312-317) lalu `predict_batch` dipanggil (489); annotation konkret tidak dideklarasikan, sehingga paling aman label diagram: **DEPENDENCY** |
| RuntimeWorker | CICFlowMeterV3ModelAdapter | DEPENDENCY | Dibuat lokal dalam `_run` dan dipakai adaptasi (`src/api/runtime_monitoring.py:376,454`) |
| RuntimeWorker | persist_predictions | DEPENDENCY | Memanggil module-level function (`src/api/runtime_monitoring.py:506-513`; `src/api/service.py:76-131`) |
| RuntimePipeline | RuntimeExtractorRegistry | COMPOSITION | Registry injected atau dibuat default dan disimpan (`src/api/runtime_monitoring.py:96-107`) |
| RuntimeModelRegistry | InferenceEngine | COMPOSITION/DEPENDENCY | Factory default dan engine disimpan di `_models` (`src/api/runtime_models.py:71-78,112-115`) |
| RuntimeValidationService | MonitoringSession / RuntimeValidationRun / RuntimeCaptureArtifact / Prediction / Alert | DEPENDENCY | ORM reads/writes di `create`, `complete`, `_derive` (`src/api/runtime_validation.py:35-201`) |
| RuntimePipeline | InferenceEngine | — | **NOT PRESENT**; inference terjadi di worker, bukan pipeline |
| RuntimeCollectorController | RuntimePipeline | indirect only | **NOT VERIFIED sebagai direct dependency**; pipeline dibuat oleh worker |

Tidak ditemukan inheritance antarkelas service/runtime tersebut. Semua inheritance yang relevan hanya exception class atau framework/data-model inheritance, bukan rantai service.

## 7. Rekomendasi Struktur Diagram BAB III

Gunakan dua diagram. Satu diagram gabungan akan terlalu padat dan berisiko mencampurkan struktur data dengan orchestration runtime.

### Diagram A — Persistence Layer

- Tampilkan semua 12 entity aktual dan gunakan nama **ModelRecord**; bila istilah tesis harus “Model”, gunakan label `ModelRecord «table: models»`, bukan mengganti nama class.
- Tampilkan PK, seluruh FK, dan atribut domain/audit utama. Untuk reproduksi 1:1 penuh, gunakan spesifikasi pada bagian 8; untuk gambar utama skripsi, kolom timestamp/provenance berulang dapat dipadatkan dengan catatan bahwa versi lengkap ada di tabel spesifikasi.
- Jangan tampilkan method compartment karena semua ORM class mempunyai **NO EXPLICIT METHODS**.
- Garis solid ORM untuk relationship bidirectional. Untuk dua hubungan FK-only (`MonitoringSession–Prediction` dan `ModelRecord–RuntimeValidationRun`), gambar association bertanda `{FK-only; no ORM relationship}` agar implementasi fisik tetap terlihat tanpa klaim ORM palsu.
- Jangan gambar association `MonitoringSession–TrafficFlow` atau `EvidenceSource–Experiment`. Untuk `EvidenceSource`, beri note `{logical owner_type + owner_key; no FK}`.

### Diagram B — Service / Runtime Layer

- Fokus: `RFNIDSClient`, `MonitoringService`, `RuntimeCollectorController`, `RuntimeWorker`, `RuntimePipeline`, `InferenceEngine`, `RuntimeValidationService`.
- Tambahkan `RuntimeModelRegistry`, `RuntimeExtractorRegistry`, dan `CICFlowMeterV3ModelAdapter` hanya bila ruang cukup; ketiganya menjelaskan verification/adaptation boundary yang nyata.
- Hanya tampilkan public methods. Sembunyikan private methods dan seluruh module-level endpoint/helper agar diagram tetap terbaca.
- Tampilkan `persist_predictions(...)` sebagai `<<module function>>` bila persistence orchestration perlu divisualkan; jangan letakkan dalam compartment class.

## 8. Final Thesis-Ready Specification

### CLASS DIAGRAM A — PERSISTENCE LAYER

Semua atribut di bawah adalah **DATABASE COLUMN**. Marker: `{PK}`, `{FK -> table.column}`, `{UQ}`. Tidak ada method compartment pada seluruh class.

```text
User «users»
--------------------
+ id : int {PK}
+ name : str
+ email : str {UQ}
+ password_hash : str
+ role : str
+ is_active : bool
+ created_at : datetime
+ updated_at : datetime

Dataset «datasets»
--------------------
+ id : int {PK}
+ name : str
+ source_path : str?
+ source_sha256 : str?
+ total_rows : int?
+ total_features : int?
+ label_column : str?
+ class_distribution : dict?
+ created_by_user_id : int? {FK -> users.id}
+ created_at : datetime
+ updated_at : datetime

Experiment «experiments»
--------------------
+ id : int {PK}
+ experiment_code : str {UQ}
+ experiment_name : str
+ experiment_type : str
+ dataset_id : int? {FK -> datasets.id}
+ description : str?
+ status : str
+ source_path : str?
+ source_sha256 : str?
+ schema_version : str?
+ imported_at : datetime?
+ created_at : datetime
+ updated_at : datetime

EvaluationResult «evaluation_results»
--------------------
+ id : int {PK}
+ experiment_id : int {FK -> experiments.id}
+ class_name : str?
+ metric_key : str?
+ accuracy : float?
+ precision_score : float?
+ recall_score : float?
+ f1_score : float?
+ macro_precision : float?
+ macro_recall : float?
+ macro_f1 : float?
+ false_positive_rate : float?
+ true_positive : int?
+ true_negative : int?
+ false_positive : int?
+ false_negative : int?
+ confusion_matrix : dict|list?
+ notes : str?
+ source_path : str?
+ source_sha256 : str?
+ created_at : datetime

EvidenceSource «evidence_sources»
--------------------
+ id : int {PK}
+ owner_type : str
+ owner_key : str
+ evidence_role : str
+ source_path : str
+ source_sha256 : str
+ schema_version : str?
+ imported_at : datetime

ModelRecord «models»
--------------------
+ id : int {PK}
+ model_name : str
+ model_version : str {UQ}
+ algorithm : str
+ accuracy : float?
+ macro_f1 : float?
+ ddos_recall : float?
+ portscan_recall : float?
+ feature_count : int?
+ is_active : bool
+ experiment_id : int? {FK -> experiments.id}
+ artifact_path : str?
+ artifact_sha256 : str?
+ parameters : dict?
+ created_at : datetime

MonitoringSession «monitoring_sessions»
--------------------
+ id : int {PK}
+ target_ip : str
+ interface_name : str
+ model_id : int {FK -> models.id}
+ selection_mode : str
+ selected_model_version : str?
+ selected_model_sha256 : str?
+ status : str
+ started_at : datetime?
+ stopped_at : datetime?
+ created_by_user_id : int? {FK -> users.id}
+ created_at : datetime
+ updated_at : datetime
+ last_error : str?
+ runtime_handle : str?
+ extractor_name : str?
+ extractor_version : str?
+ extractor_identity : str?
+ artifact_key : str? {UQ}
+ artifact_root : str?
+ processing_state : str?
+ latest_processing_at : datetime?
+ flow_count : int
+ prediction_count : int
+ alert_count : int

RuntimeCaptureArtifact «runtime_capture_artifacts»
--------------------
+ id : int {PK}
+ monitoring_session_id : int {FK -> monitoring_sessions.id}
+ artifact_key : str {UQ}
+ window_number : int
+ state : str
+ pcap_relative_path : str?
+ pcap_sha256 : str?
+ pcap_size : int?
+ csv_relative_path : str?
+ csv_sha256 : str?
+ csv_size : int?
+ extractor_identity : str?
+ extracted_row_count : int
+ adapted_row_count : int
+ error_stage : str?
+ error_message : str?
+ capture_started_at : datetime?
+ capture_finished_at : datetime?
+ extraction_finished_at : datetime?
+ committed_at : datetime?
+ created_at : datetime

RuntimeValidationRun «runtime_validation_runs»
--------------------
+ id : int {PK}
+ monitoring_session_id : int {FK -> monitoring_sessions.id}
+ scenario : str
+ status : str
+ target_ip : str
+ interface_name : str
+ started_at : datetime
+ finished_at : datetime?
+ pcap_files_processed : int
+ pcap_bytes_processed : int
+ flows_extracted : int
+ flows_adapter_valid : int
+ predictions_committed : int
+ alerts_committed : int
+ normal_predictions : int
+ portscan_predictions : int
+ ddos_predictions : int
+ pipeline_result : str
+ detection_result : str
+ extractor_identity : str?
+ adapter_identity : str?
+ model_id : int {FK -> models.id}
+ model_version : str
+ evidence_json : dict
+ notes : str?
+ created_at : datetime

TrafficFlow «traffic_flows»
--------------------
+ id : int {PK}
+ capture_session_id : str?
+ capture_interface : str?
+ pcap_segment : str?
+ capture_time : datetime?
+ source_ip : str?
+ source_port : int?
+ destination_ip : str?
+ destination_port : int?
+ protocol : str?
+ raw_features : dict
+ created_at : datetime

Prediction «predictions»
--------------------
+ id : int {PK}
+ traffic_flow_id : int {FK -> traffic_flows.id, UQ}
+ model_id : int {FK -> models.id}
+ experiment_id : int? {FK -> experiments.id}
+ monitoring_session_id : int? {FK -> monitoring_sessions.id}
+ runtime_artifact_id : int? {FK -> runtime_capture_artifacts.id}
+ source_type : str?
+ external_key : str?
+ predicted_label : str
+ confidence_score : float
+ class_probabilities : dict
+ prediction_time : datetime
+ created_at : datetime

Alert «alerts»
--------------------
+ id : int {PK}
+ prediction_id : int {FK -> predictions.id, UQ}
+ severity : str
+ title : str
+ description : str
+ status : str
+ acknowledged_at : datetime?
+ acknowledged_by_user_id : int? {FK -> users.id}
+ created_at : datetime
```

Associations yang harus digambar:

```text
User "0..1" -- "0..*" Dataset : created_by / datasets
User "0..1" -- "0..*" MonitoringSession : created_by / monitoring_sessions
User "0..1" -- "0..*" Alert : acknowledged_by / acknowledged_alerts
Dataset "0..1" -- "0..*" Experiment : dataset / experiments
Experiment "1" *-- "0..*" EvaluationResult : evaluation_results
Experiment "0..1" -- "0..*" ModelRecord : experiment / models
Experiment "0..1" -- "0..*" Prediction : experiment / predictions
ModelRecord "1" -- "0..*" MonitoringSession : model / monitoring_sessions
ModelRecord "1" -- "0..*" Prediction : model / predictions
ModelRecord "1" .. "0..*" RuntimeValidationRun : {FK-only}
MonitoringSession "1" *-- "0..*" RuntimeCaptureArtifact : runtime_artifacts
MonitoringSession "1" *-- "0..*" RuntimeValidationRun : validation_runs
MonitoringSession "0..1" .. "0..*" Prediction : {FK-only}
RuntimeCaptureArtifact "0..1" -- "0..*" Prediction : runtime_artifact / predictions
TrafficFlow "1" *-- "0..1" Prediction : prediction / traffic_flow
Prediction "1" *-- "0..1" Alert : alert / prediction

EvidenceSource .. note : logical owner_type/owner_key only; no FK
MonitoringSession .. TrafficFlow : DO NOT DRAW — NOT PRESENT
```

### CLASS DIAGRAM B — SERVICE / RUNTIME LAYER

Return type `unspecified` berarti source tidak memberi return annotation; jangan menebaknya.

```text
RFNIDSClient
--------------------
- base_url : str
- timeout : float
- session
- access_token : str?
--------------------
+ health() : unspecified
+ login(email: str, password: str) : unspecified
+ current_user() : unspecified
+ logout() : unspecified
+ model_info() : unspecified
+ active_model() : unspecified
+ models() : unspecified
+ datasets() : unspecified
+ experiments() : unspecified
+ experiment_evaluation(experiment_id: int) : unspecified
+ evidence_sources(owner_type=None, owner_key=None) : unspecified
+ summary() : unspecified
+ timeline(minutes: int=60) : unspecified
+ predictions(limit=20, offset=0, **filters) : unspecified
+ prediction(prediction_id: int) : unspecified
+ traffic_flows(limit=20, offset=0, **filters) : unspecified
+ monitoring_summary() : unspecified
+ monitoring_status() : unspecified
+ monitoring_interfaces() : unspecified
+ monitoring_models() : unspecified
+ monitoring_sessions(limit=20, offset=0) : unspecified
+ monitoring_session_predictions(session_id: int, limit=5) : unspecified
+ start_monitoring(target_ip: str, interface_name: str, selected_model_id: str?=None) : unspecified
+ stop_monitoring() : unspecified
+ create_runtime_validation(session_id: int, scenario: str) : unspecified
+ runtime_validations(session_id: int) : unspecified
+ complete_runtime_validation(session_id: int, validation_id: int) : unspecified
+ alerts(limit=20, offset=0, **filters) : unspecified
+ alert(alert_id: int) : unspecified
+ acknowledge_alert(alert_id: int) : unspecified
+ export_dataset() : unspecified
+ export_experiment(experiment_id: int, format: str="json") : unspecified
+ export_confusion_matrix(experiment_id: int) : unspecified
+ export_predictions(format: str="csv", **filters) : unspecified
+ export_alerts(format: str="csv", **filters) : unspecified

MonitoringService
--------------------
- collector
--------------------
+ active(db: Session) : MonitoringSession?
+ reconcile_stale_sessions(db: Session) : int
+ start(db: Session, target_ip: str, interface_name: str, user: User, model_id: int?=None, inference=None, selection_mode: str="DEFAULT") : unspecified
+ shutdown(db: Session) : None
+ stop(db: Session) : unspecified

RuntimeCollectorController
--------------------
- session_factory
- inference
- settings
- worker_factory
--------------------
+ start(session_id: int, target_ip: str, interface_name: str, inference=None) : str
+ stop(runtime_handle: str?) : bool
+ status(runtime_handle: str?) : str
+ shutdown() : unspecified

RuntimeWorker
--------------------
- session_id
- session_factory
- inference
- settings
- pipeline : RuntimePipeline
--------------------
+ start() : unspecified
+ stop(timeout: float) : unspecified

RuntimePipeline
--------------------
- root : Path
- image : str
- window_seconds : float
- extractor_registry : RuntimeExtractorRegistry
--------------------
+ preflight(interface: str) : None
+ request_stop() : None
+ force_stop() : None
+ capture(interface: str, target_ip: str, output: Path, stop: Event) : unspecified
+ host_artifact_path(path: Path) : Path
+ extract(pcap: Path, output_dir: Path) : Path

InferenceEngine
--------------------
- metadata : dict
- feature_names : list[str]
- model
--------------------
+ predict_one(features: Mapping[str, Any]) : dict[str, Any]
+ predict_batch(rows: Sequence[Mapping[str, Any]]) : list[dict[str, Any]]

RuntimeValidationService
--------------------
- artifact_root : Path
- expected_feature_names : tuple
--------------------
+ create(db: Session, session_id: int, scenario: str) : RuntimeValidationRun
+ complete(db: Session, session_id: int, validation_id: int) : RuntimeValidationRun

RuntimeModelRegistry «optional supporting class»
--------------------
+ resolve(model_id: str) : unspecified
+ available() : unspecified

RuntimeExtractorRegistry «optional supporting class»
--------------------
+ verify(image_digest: str, source_commit: str, adapter_identity: str=..., adapter_version: str=..., crosswalk_sha256: str=...) : ApprovedRuntimeExtractor
```

Dependencies yang harus digambar:

```text
RFNIDSClient ..> FastAPI : HTTP dependency
MonitoringService --> RuntimeCollectorController : association (production injection)
MonitoringService ..> MonitoringSession
MonitoringService ..> ModelRecord
MonitoringService ..> User
RuntimeCollectorController *-- RuntimeWorker : composition
RuntimeWorker *-- RuntimePipeline : composition
RuntimeWorker ..> InferenceEngine : injected dependency
RuntimeWorker ..> CICFlowMeterV3ModelAdapter : creates/uses
RuntimeWorker ..> persist_predictions : <<module function>>
RuntimePipeline *-- RuntimeExtractorRegistry : owns/defaults
RuntimeModelRegistry *-- InferenceEngine : verifies/creates/stores
RuntimeValidationService ..> MonitoringSession
RuntimeValidationService ..> RuntimeValidationRun
RuntimeValidationService ..> RuntimeCaptureArtifact
RuntimeValidationService ..> Prediction
RuntimeValidationService ..> Alert
```

## 9. Status Nama yang Diminta

| Nama kandidat | Status | Nama/path aktual |
|---|---|---|
| RFNIDSClient | VERIFIED | `dashboard/api_client.py:25-226` |
| MonitoringService | VERIFIED | `src/api/monitoring.py:54-213` |
| RuntimeCollectorController | VERIFIED | `src/api/runtime_monitoring.py:554-645` |
| RuntimeWorker | VERIFIED | `src/api/runtime_monitoring.py:311-551` |
| RuntimePipeline | VERIFIED | `src/api/runtime_monitoring.py:87-308` |
| InferenceEngine | VERIFIED | `src/inference/predictor.py:24-161` |
| RuntimeValidationService | VERIFIED | `src/api/runtime_validation.py:30-201` |
| Model (ORM Python class) | NOT PRESENT | Nama aktual `ModelRecord`, `src/api/models.py:155-181`; table tetap `models` |
