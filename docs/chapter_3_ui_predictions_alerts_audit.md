# Audit Read-Only UI Predictions dan Alerts RF-NIDS

Tanggal audit: 29 September 2026  
Ruang lingkup utama: `dashboard/pages/predictions.py` dan `dashboard/pages/alerts.py`; penelusuran tambahan dilakukan pada komponen tabel, API client, route FastAPI, schema, export mapper, dan model persistence.  
Metode: audit statis terhadap implementasi yang tersedia di repository. Tidak ada source aplikasi, database, migration, model, atau konfigurasi yang diubah. Satu-satunya file yang dibuat adalah laporan audit ini.

## Definisi status

- **SUPPORTED**: tersedia dan benar-benar diekspos oleh UI sesuai komponen wireframe.
- **PARTIALLY SUPPORTED**: sebagian kebutuhan tersedia, tetapi field, perilaku, atau cara interaksinya tidak lengkap.
- **NOT SUPPORTED**: tidak tersedia pada UI dan tidak tersedia sebagai fitur backend yang ekuivalen.
- **BACKEND ONLY**: backend/API menyediakan kemampuan tersebut, tetapi halaman Streamlit tidak mengeksposnya.
- **NOT VERIFIED**: bukti implementasi yang tersedia tidak cukup untuk memastikan perilaku.

## 1. Predictions Page

### A. List Predictions

Halaman mengambil maksimum 20 record per halaman dengan `limit=20` dan `offset=(page-1)*20`, lalu menampilkan tabel melalui `predictions_table` ([dashboard/pages/predictions.py:9](../dashboard/pages/predictions.py#L9), [dashboard/pages/predictions.py:100](../dashboard/pages/predictions.py#L100), [dashboard/pages/predictions.py:109](../dashboard/pages/predictions.py#L109)).

Kolom yang benar-benar ditampilkan:

| UI column | Sumber data | Evidence |
|---|---|---|
| ID | `id` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Time | `prediction_time` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Source IP | `source_ip` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Destination IP | `destination_ip` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Class | `predicted_label` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Confidence | `confidence_score` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Model | `model_version` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |
| Alert | `alert_status` | [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9) |

Temuan perilaku list:

- Filter UI: Class (`All`, `Normal`, `DDoS`, `PortScan`), Source IP, dan Destination IP ([dashboard/pages/predictions.py:96](../dashboard/pages/predictions.py#L96)). Source/Destination adalah exact-match filter pada backend, bukan full-text/substring search ([src/api/main.py:151](../src/api/main.py#L151), [src/api/main.py:155](../src/api/main.py#L155)). API juga menerima filter protocol, tetapi halaman tidak mengeksposnya ([src/api/main.py:603](../src/api/main.py#L603)).
- Date Range filter: tidak ada di UI maupun endpoint list Predictions ([dashboard/pages/predictions.py:96](../dashboard/pages/predictions.py#L96), [src/api/main.py:603](../src/api/main.py#L603)).
- Search umum: tidak ada. Input Source IP dan Destination IP merupakan filter exact-match terpisah, sehingga tidak dihitung sebagai search umum.
- Pagination: ada secara manual melalui number input `Page`; tidak ada total count, last page, next/previous, atau pencegahan page kosong. Caption hanya menyebut jumlah record pada page saat ini ([dashboard/pages/predictions.py:100](../dashboard/pages/predictions.py#L100), [dashboard/pages/predictions.py:119](../dashboard/pages/predictions.py#L119)).
- Action per prediction: tidak ada tombol/action di setiap row tabel. Detail dipilih dari selectbox `Open prediction detail` yang berisi ID pada page saat ini, kemudian UI memanggil endpoint detail ([dashboard/pages/predictions.py:122](../dashboard/pages/predictions.py#L122), [dashboard/api_client.py:147](../dashboard/api_client.py#L147)).
- Export: UI menyediakan CSV untuk seluruh hasil filter sampai 10.000 record, bukan hanya 20 row page saat ini ([dashboard/pages/predictions.py:112](../dashboard/pages/predictions.py#L112), [src/api/main.py:1042](../src/api/main.py#L1042)). Backend juga mendukung JSON, tetapi UI mengunci `format="csv"`: **BACKEND ONLY — NOT EXPOSED IN UI** ([src/api/main.py:1045](../src/api/main.py#L1045), [dashboard/pages/predictions.py:112](../dashboard/pages/predictions.py#L112)).

### B. Detail Prediction

Detail prediction benar-benar ada. UI memanggil `GET /api/predictions/{prediction_id}` dan langsung merender hasilnya di bawah list ([dashboard/pages/predictions.py:122](../dashboard/pages/predictions.py#L122), [dashboard/pages/predictions.py:127](../dashboard/pages/predictions.py#L127), [src/api/main.py:943](../src/api/main.py#L943)).

| Field/section | Database Available | API Available | UI Displayed | Evidence / catatan |
|---|---:|---:|---:|---|
| Prediction ID | Ya | Ya | Ya | [src/api/models.py:381](../src/api/models.py#L381), [src/api/schemas.py:97](../src/api/schemas.py#L97), [dashboard/pages/predictions.py:33](../dashboard/pages/predictions.py#L33) |
| Timestamp | Ya | Ya (`prediction_time`) | Ya | [src/api/models.py:402](../src/api/models.py#L402), [src/api/schemas.py:102](../src/api/schemas.py#L102), [dashboard/pages/predictions.py:34](../dashboard/pages/predictions.py#L34) |
| Predicted class | Ya | Ya | Ya | [src/api/models.py:399](../src/api/models.py#L399), [src/api/schemas.py:99](../src/api/schemas.py#L99), [dashboard/pages/predictions.py:35](../dashboard/pages/predictions.py#L35) |
| Confidence | Ya | Ya | Ya | [src/api/models.py:400](../src/api/models.py#L400), [src/api/schemas.py:100](../src/api/schemas.py#L100), [dashboard/pages/predictions.py:36](../dashboard/pages/predictions.py#L36) |
| Source IP/port | Ya | Ya | Ya | [src/api/models.py:353](../src/api/models.py#L353), [src/api/schemas.py:107](../src/api/schemas.py#L107), [dashboard/pages/predictions.py:59](../dashboard/pages/predictions.py#L59) |
| Destination IP/port | Ya | Ya | Ya | [src/api/models.py:355](../src/api/models.py#L355), [src/api/schemas.py:109](../src/api/schemas.py#L109), [dashboard/pages/predictions.py:61](../dashboard/pages/predictions.py#L61) |
| Protocol | Ya | Ya | Ya | [src/api/models.py:357](../src/api/models.py#L357), [src/api/schemas.py:111](../src/api/schemas.py#L111), [dashboard/pages/predictions.py:63](../dashboard/pages/predictions.py#L63) |
| Traffic flow ID | Ya (`traffic_flow_id`) | Ya | Tidak | [src/api/models.py:382](../src/api/models.py#L382), [src/api/schemas.py:98](../src/api/schemas.py#L98); tidak dipakai oleh renderer [dashboard/pages/predictions.py:28](../dashboard/pages/predictions.py#L28) |
| Model name/version | Ya melalui FK model | Ya | Ya | [src/api/models.py:385](../src/api/models.py#L385), [src/api/main.py:136](../src/api/main.py#L136), [dashboard/pages/predictions.py:37](../dashboard/pages/predictions.py#L37) |
| Monitoring session | Ya (`monitoring_session_id`) | Tidak pada `PredictionDetail` | Tidak | [src/api/models.py:391](../src/api/models.py#L391) vs schema [src/api/schemas.py:95](../src/api/schemas.py#L95) |
| Interface | Ya pada flow (`capture_interface`) | Ya | Ya sebagai `Capture interface` | [src/api/models.py:350](../src/api/models.py#L350), [src/api/schemas.py:113](../src/api/schemas.py#L113), [dashboard/pages/predictions.py:66](../dashboard/pages/predictions.py#L66) |
| Target IP | Ya pada `monitoring_sessions`, bukan prediction/flow langsung | Tidak pada `PredictionDetail` | Tidak | [src/api/models.py:206](../src/api/models.py#L206), [src/api/schemas.py:95](../src/api/schemas.py#L95) |
| Class probabilities | Ya | Ya | Ya jika persisted; jika tidak, UI menyatakan tidak tersedia | [src/api/models.py:401](../src/api/models.py#L401), [src/api/schemas.py:101](../src/api/schemas.py#L101), [dashboard/pages/predictions.py:41](../dashboard/pages/predictions.py#L41) |
| Raw feature values | Ya (`raw_features`) | Ya sebagai `flow_features` | Ya, di expander JSON | [src/api/models.py:358](../src/api/models.py#L358), [src/api/main.py:139](../src/api/main.py#L139), [dashboard/pages/predictions.py:82](../dashboard/pages/predictions.py#L82) |
| Top feature values | Raw values saja | Tidak ada hasil ranking/top-N | Tidak | Renderer hanya menampilkan seluruh JSON mentah; tidak menghitung top feature ([dashboard/pages/predictions.py:82](../dashboard/pages/predictions.py#L82)) |
| Network flow information | Ya | Ya | Ya, tetapi diberi heading `Flow Information` | [dashboard/pages/predictions.py:57](../dashboard/pages/predictions.py#L57) |

Catatan struktur: `Prediction Information` ada, tetapi model berada di section yang sama; section wireframe terpisah `Model & Session Information` tidak ada. UI mempunyai section tambahan `Context / Provenance` dan `Alert Information` ([dashboard/pages/predictions.py:31](../dashboard/pages/predictions.py#L31), [dashboard/pages/predictions.py:70](../dashboard/pages/predictions.py#L70)).

## 2. Alerts Page

### A. List Alerts

Kolom yang benar-benar ditampilkan:

| UI column | Sumber data | Evidence |
|---|---|---|
| ID | `id` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Time | `created_at` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Attack Type | `predicted_label` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Severity | `severity` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Source IP | `source_ip` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Destination IP | `destination_ip` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Confidence | `confidence_score` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Status | `status` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Acknowledged By | `acknowledged_by_name` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |
| Acknowledged At | `acknowledged_at` | [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29) |

Temuan perilaku list:

- Filter UI: Attack type (`All`, `DDoS`, `PortScan`), Severity (`All`, `HIGH`, `MEDIUM`), Status (`All`, `ACTIVE`, `ACKNOWLEDGED`), Source IP, dan Destination IP ([dashboard/pages/alerts.py:103](../dashboard/pages/alerts.py#L103)). IP diterapkan sebagai exact-match ([src/api/main.py:164](../src/api/main.py#L164)).
- Date Range filter: tidak ada di UI maupun endpoint list Alerts ([dashboard/pages/alerts.py:103](../dashboard/pages/alerts.py#L103), [src/api/main.py:954](../src/api/main.py#L954)).
- Search umum: tidak ada; dua input IP adalah filter exact-match.
- Pagination: ada secara manual melalui number input dan offset, dengan page size 20; tidak ada total count/last page/next/previous ([dashboard/pages/alerts.py:9](../dashboard/pages/alerts.py#L9), [dashboard/pages/alerts.py:110](../dashboard/pages/alerts.py#L110), [dashboard/pages/alerts.py:118](../dashboard/pages/alerts.py#L118)).
- Action per row: tidak ada. User memilih ID dari selectbox `Open alert detail`; detail dirender di bawah list ([dashboard/pages/alerts.py:134](../dashboard/pages/alerts.py#L134)). Acknowledge muncul setelah detail, bukan di row tabel ([dashboard/pages/alerts.py:142](../dashboard/pages/alerts.py#L142)).
- Export: CSV tersedia dari UI dan mengikuti filter, maksimum 10.000 record ([dashboard/pages/alerts.py:123](../dashboard/pages/alerts.py#L123), [src/api/main.py:1061](../src/api/main.py#L1061)). JSON didukung backend tetapi hardcoded CSV oleh UI: **BACKEND ONLY — NOT EXPOSED IN UI** ([src/api/main.py:1064](../src/api/main.py#L1064), [dashboard/pages/alerts.py:123](../dashboard/pages/alerts.py#L123)).

### B. Detail Alert

Detail alert benar-benar ada melalui `GET /api/alerts/{alert_id}` dan dirender setelah pemilihan ID ([dashboard/api_client.py:207](../dashboard/api_client.py#L207), [src/api/main.py:1084](../src/api/main.py#L1084), [dashboard/pages/alerts.py:139](../dashboard/pages/alerts.py#L139)).

| Field/section | Database Available | API Available | UI Displayed | Evidence / catatan |
|---|---:|---:|---:|---|
| Alert ID | Ya | Ya | Ya | [src/api/models.py:427](../src/api/models.py#L427), [src/api/schemas.py:270](../src/api/schemas.py#L270), [dashboard/pages/alerts.py:31](../dashboard/pages/alerts.py#L31) |
| Timestamp | Ya (`created_at`) | Ya | Ya sebagai `Created at` | [src/api/models.py:439](../src/api/models.py#L439), [src/api/schemas.py:280](../src/api/schemas.py#L280), [dashboard/pages/alerts.py:34](../dashboard/pages/alerts.py#L34) |
| Alert type | Tidak sebagai field alert tersendiri; attack type berasal dari prediction | Ya sebagai `predicted_label` | Ya sebagai `Predicted class`, bukan label `Alert type` | [src/api/main.py:201](../src/api/main.py#L201), [dashboard/pages/alerts.py:42](../dashboard/pages/alerts.py#L42) |
| Severity | Ya | Ya | Ya | [src/api/models.py:431](../src/api/models.py#L431), [src/api/schemas.py:272](../src/api/schemas.py#L272), [dashboard/pages/alerts.py:32](../dashboard/pages/alerts.py#L32) |
| Status | Ya | Ya | Ya | [src/api/models.py:434](../src/api/models.py#L434), [src/api/schemas.py:275](../src/api/schemas.py#L275), [dashboard/pages/alerts.py:33](../dashboard/pages/alerts.py#L33) |
| Title | Ya | Ya | Tidak | [src/api/models.py:432](../src/api/models.py#L432), [src/api/schemas.py:273](../src/api/schemas.py#L273); renderer tidak memakainya [dashboard/pages/alerts.py:24](../dashboard/pages/alerts.py#L24) |
| Description | Ya | Ya | Tidak | [src/api/models.py:433](../src/api/models.py#L433), [src/api/schemas.py:274](../src/api/schemas.py#L274); renderer tidak memakainya [dashboard/pages/alerts.py:24](../dashboard/pages/alerts.py#L24) |
| Source/destination information | Ya | Ya | Ya, termasuk port | [src/api/main.py:204](../src/api/main.py#L204), [dashboard/pages/alerts.py:49](../dashboard/pages/alerts.py#L49) |
| Monitoring session | Tersedia pada related prediction di DB | Tidak pada `AlertDetail` | Tidak | [src/api/models.py:391](../src/api/models.py#L391), [src/api/schemas.py:268](../src/api/schemas.py#L268) |
| Related prediction | Ya | Ya (`prediction_id`, class, confidence, probabilities) | Ya untuk ID, class, confidence | [src/api/schemas.py:271](../src/api/schemas.py#L271), [dashboard/pages/alerts.py:39](../dashboard/pages/alerts.py#L39) |
| Prediction confidence | Ya | Ya | Ya | [src/api/schemas.py:282](../src/api/schemas.py#L282), [dashboard/pages/alerts.py:43](../dashboard/pages/alerts.py#L43) |
| Class probabilities | Ya pada prediction | Ya | Ya jika persisted | [src/api/schemas.py:283](../src/api/schemas.py#L283), [dashboard/pages/alerts.py:69](../dashboard/pages/alerts.py#L69) |
| Flow information | Ya | Ya (IP, ports, protocol, capture time) | Ya sebagai `Related Flow` | [src/api/main.py:204](../src/api/main.py#L204), [dashboard/pages/alerts.py:49](../dashboard/pages/alerts.py#L49) |
| Feature values | Ya pada related flow | Tidak pada `AlertDetail`; tersedia melalui endpoint prediction terpisah | Tidak | [src/api/models.py:358](../src/api/models.py#L358), [src/api/schemas.py:268](../src/api/schemas.py#L268), [src/api/schemas.py:120](../src/api/schemas.py#L120) |
| Top feature values | Tidak ada ranking/top-N | Tidak | Tidak | Tidak ditemukan implementasi top feature pada halaman/API detail terkait |
| `acknowledged_at` | Ya | Ya | Ya | [src/api/models.py:435](../src/api/models.py#L435), [src/api/schemas.py:276](../src/api/schemas.py#L276), [dashboard/pages/alerts.py:35](../dashboard/pages/alerts.py#L35) |
| `acknowledged_by_user_id` | Ya | Ya | Ya sebagai `Acknowledging user ID` | [src/api/models.py:436](../src/api/models.py#L436), [src/api/schemas.py:277](../src/api/schemas.py#L277), [dashboard/pages/alerts.py:37](../dashboard/pages/alerts.py#L37) |

## 3. Alert Action

| Action/status | UI | Backend | Kesimpulan | Evidence |
|---|---|---|---|---|
| Acknowledge Alert | Ada hanya untuk alert berstatus `ACTIVE` | `PATCH /api/alerts/{alert_id}/acknowledge` | **SUPPORTED** | [dashboard/pages/alerts.py:142](../dashboard/pages/alerts.py#L142), [dashboard/api_client.py:210](../dashboard/api_client.py#L210), [src/api/main.py:1093](../src/api/main.py#L1093) |
| Close Alert | Tidak ada | Tidak ditemukan endpoint/status `CLOSED` | **NOT SUPPORTED** | Status schema hanya dua nilai [src/api/schemas.py:21](../src/api/schemas.py#L21) |
| Mark as Resolved | Tidak ada | Tidak ditemukan endpoint/status `RESOLVED` | **NOT SUPPORTED** | Constraint DB hanya `ACTIVE` dan `ACKNOWLEDGED` [src/api/models.py:420](../src/api/models.py#L420) |

Status alert yang benar-benar didukung adalah `ACTIVE` dan `ACKNOWLEDGED` pada schema API dan constraint database ([src/api/schemas.py:21](../src/api/schemas.py#L21), [src/api/models.py:423](../src/api/models.py#L423)). Acknowledge mengubah status menjadi `ACKNOWLEDGED`, mengisi waktu, dan mencatat user yang melakukan aksi ([src/api/main.py:1098](../src/api/main.py#L1098)). Tidak ada kasus Close/Resolved yang dapat diberi label **BACKEND ONLY** karena endpoint maupun status backend ekuivalennya tidak ditemukan.

## 4. Model Semantics

Predictions menggunakan model yang terkait langsung dengan setiap prediction, bukan global active model. Database menyimpan `Prediction.model_id` sebagai foreign key ([src/api/models.py:385](../src/api/models.py#L385)); mapper detail mengambil `row.model.model_name` dan `row.model.model_version` ([src/api/main.py:136](../src/api/main.py#L136)); halaman menampilkan nilai dari response detail tersebut ([dashboard/pages/predictions.py:37](../dashboard/pages/predictions.py#L37)).

Halaman Predictions tidak memanggil `client.active_model()` dan tidak menampilkan teks/konsep "active model"; pemanggilan tersebut ada di halaman lain seperti Model Info, bukan Predictions ([dashboard/api_client.py:116](../dashboard/api_client.py#L116), [dashboard/pages/model_info.py:16](../dashboard/pages/model_info.py#L16)). Dengan demikian:

- Model per prediction: **SUPPORTED**.
- Global active model sebagai semantics halaman Predictions: **NOT USED**.
- Model terkait monitoring session: DB menyimpan baik `Prediction.model_id` maupun `Prediction.monitoring_session_id`, tetapi detail Predictions tidak mengembalikan session; model yang ditampilkan tetap relasi langsung `Prediction.model`.

## 5. Wireframe Verification

| Wireframe Component | Implementation Evidence | Status | Recommendation |
|---|---|---|---|
| Prediction List — Date Range filter | Filter UI hanya Class, Source IP, Destination IP; API juga tidak menerima rentang tanggal ([dashboard/pages/predictions.py:96](../dashboard/pages/predictions.py#L96), [src/api/main.py:603](../src/api/main.py#L603)) | **NOT SUPPORTED** | Revisi wireframe agar menghapus Date Range, atau implementasikan filter tanggal end-to-end. |
| Prediction List — Predicted Class filter | Selectbox Class mengirim `predicted_label` ([dashboard/pages/predictions.py:97](../dashboard/pages/predictions.py#L97)) | **SUPPORTED** | Pertahankan. |
| Prediction List — Source IP | Ada sebagai kolom dan exact-match filter ([dashboard/components/tables.py:9](../dashboard/components/tables.py#L9), [dashboard/pages/predictions.py:98](../dashboard/pages/predictions.py#L98)) | **SUPPORTED** | Jelaskan pada rancangan bahwa input adalah exact-match filter. |
| Prediction List — Destination IP | Ada sebagai kolom dan exact-match filter ([dashboard/components/tables.py:9](../dashboard/components/tables.py#L9), [dashboard/pages/predictions.py:99](../dashboard/pages/predictions.py#L99)) | **SUPPORTED** | Jelaskan pada rancangan bahwa input adalah exact-match filter. |
| Prediction List — Timestamp | Ditampilkan sebagai `Time` dari `prediction_time` ([dashboard/components/tables.py:9](../dashboard/components/tables.py#L9)) | **SUPPORTED** | Samakan label wireframe dengan `Time` atau UI dengan `Timestamp`. |
| Prediction List — Source Port | API mengembalikan field, tabel tidak menampilkannya ([src/api/schemas.py:108](../src/api/schemas.py#L108), [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9)) | **BACKEND ONLY** | Tambahkan kolom atau hapus dari wireframe. |
| Prediction List — Destination Port | API mengembalikan field, tabel tidak menampilkannya ([src/api/schemas.py:110](../src/api/schemas.py#L110), [dashboard/components/tables.py:9](../dashboard/components/tables.py#L9)) | **BACKEND ONLY** | Tambahkan kolom atau hapus dari wireframe. |
| Prediction List — Confidence | Ditampilkan sebagai progress column ([dashboard/components/tables.py:12](../dashboard/components/tables.py#L12)) | **SUPPORTED** | Pertahankan. |
| Prediction List — Monitoring Session | DB menyimpan session, tetapi schema/API list dan UI tidak mengeksposnya ([src/api/models.py:391](../src/api/models.py#L391), [src/api/schemas.py:95](../src/api/schemas.py#L95)) | **NOT SUPPORTED** | Tambahkan ke response API dan tabel, atau revisi wireframe. |
| Prediction List — detail action | Detail tersedia, tetapi melalui selectbox global, bukan action per row ([dashboard/pages/predictions.py:122](../dashboard/pages/predictions.py#L122)) | **PARTIALLY SUPPORTED** | Gambarkan selectbox aktual atau tambahkan action per row. |
| Prediction List — search | Tidak ada search umum; input IP adalah exact-match filter | **NOT SUPPORTED** | Hapus search dari wireframe atau implementasikan definisi search yang jelas. |
| Prediction List — pagination | Page number dan offset tersedia; tidak ada total/next/previous/last-page validation ([dashboard/pages/predictions.py:100](../dashboard/pages/predictions.py#L100)) | **PARTIALLY SUPPORTED** | Representasikan pagination manual aktual atau lengkapi kontrol navigasi/total. |
| Prediction List — export CSV | Download CSV tersedia ([dashboard/pages/predictions.py:112](../dashboard/pages/predictions.py#L112)) | **SUPPORTED** | Pertahankan. |
| Prediction List — export JSON | Endpoint menerima JSON, UI selalu meminta CSV ([src/api/main.py:1045](../src/api/main.py#L1045), [dashboard/pages/predictions.py:112](../dashboard/pages/predictions.py#L112)) | **BACKEND ONLY** | Tambahkan pilihan format atau jangan klaim JSON di UI. |
| Prediction Detail — Prediction Information | ID, time, class, confidence, model name/version ditampilkan ([dashboard/pages/predictions.py:31](../dashboard/pages/predictions.py#L31)) | **SUPPORTED** | Pertahankan; pertimbangkan memindahkan model ke section khusus. |
| Prediction Detail — Model & Session Information | Model tampil di Prediction Information; session tidak ada di API/UI ([dashboard/pages/predictions.py:37](../dashboard/pages/predictions.py#L37), [src/api/schemas.py:95](../src/api/schemas.py#L95)) | **PARTIALLY SUPPORTED** | Tambahkan section khusus dan session, atau revisi wireframe menjadi model-only. |
| Prediction Detail — Class Probabilities | Ditampilkan jika persisted; tidak direkonstruksi jika kosong ([dashboard/pages/predictions.py:41](../dashboard/pages/predictions.py#L41)) | **SUPPORTED** | Pertahankan perilaku transparan untuk data kosong. |
| Prediction Detail — Top Feature Values | Hanya raw feature JSON yang tersedia; tidak ada ranking/top-N ([dashboard/pages/predictions.py:82](../dashboard/pages/predictions.py#L82)) | **NOT SUPPORTED** | Ganti wireframe menjadi Raw Feature Values atau implementasikan definisi top feature yang valid. |
| Prediction Detail — Network Flow Information | IP, port, protocol dan capture metadata ditampilkan di `Flow Information` ([dashboard/pages/predictions.py:57](../dashboard/pages/predictions.py#L57)) | **SUPPORTED** | Samakan nama section bila konsistensi dokumen diperlukan. |
| Alert List — Date Range | Tidak ada di UI/API list ([dashboard/pages/alerts.py:103](../dashboard/pages/alerts.py#L103), [src/api/main.py:954](../src/api/main.py#L954)) | **NOT SUPPORTED** | Implementasikan end-to-end atau hapus dari wireframe. |
| Alert List — Severity | Selectbox All/HIGH/MEDIUM tersedia ([dashboard/pages/alerts.py:105](../dashboard/pages/alerts.py#L105)) | **SUPPORTED** | Pertahankan. |
| Alert List — Alert Type | UI menyebut `Attack type` dan memfilter predicted class DDoS/PortScan, bukan field alert type tersendiri ([dashboard/pages/alerts.py:104](../dashboard/pages/alerts.py#L104)) | **PARTIALLY SUPPORTED** | Ubah istilah wireframe menjadi Attack Type/Predicted Class atau tambahkan field alert type eksplisit. |
| Alert List — Status | All/ACTIVE/ACKNOWLEDGED tersedia ([dashboard/pages/alerts.py:106](../dashboard/pages/alerts.py#L106)) | **SUPPORTED** | Batasi rancangan pada dua status aktual. |
| Alert List — Timestamp | `created_at` ditampilkan sebagai `Time` ([dashboard/components/tables.py:29](../dashboard/components/tables.py#L29)) | **SUPPORTED** | Samakan label. |
| Alert List — Source IP | Kolom dan exact-match filter tersedia ([dashboard/pages/alerts.py:108](../dashboard/pages/alerts.py#L108), [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29)) | **SUPPORTED** | Pertahankan. |
| Alert List — Destination IP | Kolom dan exact-match filter tersedia ([dashboard/pages/alerts.py:109](../dashboard/pages/alerts.py#L109), [dashboard/components/tables.py:29](../dashboard/components/tables.py#L29)) | **SUPPORTED** | Pertahankan. |
| Alert List — Monitoring Session | Ada pada related prediction di DB tetapi tidak pada Alert API/UI ([src/api/models.py:391](../src/api/models.py#L391), [src/api/schemas.py:268](../src/api/schemas.py#L268)) | **NOT SUPPORTED** | Tambahkan relasi ke response dan tabel atau hapus dari wireframe. |
| Alert List — detail action | Detail tersedia melalui selectbox global, bukan action per row ([dashboard/pages/alerts.py:134](../dashboard/pages/alerts.py#L134)) | **PARTIALLY SUPPORTED** | Sesuaikan wireframe atau tambahkan action row. |
| Alert List — search | Tidak ada search umum | **NOT SUPPORTED** | Hapus atau implementasikan search dengan cakupan yang didefinisikan. |
| Alert List — pagination | Page input/offset tersedia tanpa total dan kontrol navigasi ([dashboard/pages/alerts.py:110](../dashboard/pages/alerts.py#L110)) | **PARTIALLY SUPPORTED** | Lengkapi atau gambarkan pagination manual aktual. |
| Alert List — export CSV | Tersedia dari UI ([dashboard/pages/alerts.py:123](../dashboard/pages/alerts.py#L123)) | **SUPPORTED** | Pertahankan. |
| Alert List — export JSON | Backend mendukung, UI tidak mengekspos ([src/api/main.py:1064](../src/api/main.py#L1064)) | **BACKEND ONLY** | Tambahkan selector format atau jangan klaim JSON pada UI. |
| Alert Detail — Alert Information | ID, severity, status, timestamps dan acknowledgement ditampilkan; title/description API tidak ditampilkan ([dashboard/pages/alerts.py:29](../dashboard/pages/alerts.py#L29), [src/api/schemas.py:273](../src/api/schemas.py#L273)) | **PARTIALLY SUPPORTED** | Tambahkan title/description atau keluarkan dari spesifikasi detail. |
| Alert Detail — Related Prediction | ID, predicted class, confidence ditampilkan ([dashboard/pages/alerts.py:39](../dashboard/pages/alerts.py#L39)) | **SUPPORTED** | Pertahankan. |
| Alert Detail — Class Probabilities | Ditampilkan dari related prediction jika persisted ([dashboard/pages/alerts.py:69](../dashboard/pages/alerts.py#L69)) | **SUPPORTED** | Pertahankan. |
| Alert Detail — Top Feature Values | Tidak ada di Alert API/UI | **NOT SUPPORTED** | Implementasikan secara eksplisit atau hapus dari wireframe. |
| Alert Detail — Network Flow Information | Ditampilkan sebagai `Related Flow` dengan IP, port, protocol, capture time ([dashboard/pages/alerts.py:49](../dashboard/pages/alerts.py#L49)) | **SUPPORTED** | Samakan nama section bila diperlukan. |
| Alert Detail — Acknowledge Alert | Tombol muncul untuk status ACTIVE dan memanggil PATCH acknowledge ([dashboard/pages/alerts.py:142](../dashboard/pages/alerts.py#L142)) | **SUPPORTED** | Pertahankan. |
| Alert Detail — Mark as Resolved | Tidak ada status, endpoint, client method, atau tombol resolved | **NOT SUPPORTED** | Hapus dari wireframe atau rancang status/transisi/backend/UI secara lengkap. |

## 6. Kesimpulan Akhir

| Area | Verdict | Alasan utama |
|---|---|---|
| Prediction List | **NEED REVISION** | Tidak ada Date Range, search umum, Source/Destination Port, atau Monitoring Session; detail action dan pagination berbeda/lebih sederhana dari rancangan. |
| Prediction Detail | **NEED REVISION** | Detail ada dan menampilkan informasi utama, probabilities, raw features, dan flow; tetapi tidak ada section Model & Session yang lengkap, session/target IP, traffic flow ID di UI, maupun Top Feature Values. |
| Alert List | **NEED REVISION** | Tidak ada Date Range, search umum, Monitoring Session, atau row action; Alert Type aktual adalah predicted class/Attack Type; pagination hanya manual. |
| Alert Detail | **NEED REVISION** | Detail dan Acknowledge ada, tetapi title/description tidak ditampilkan, monitoring session/feature values/top features tidak tersedia, dan Mark as Resolved tidak didukung. |

Tidak ada item yang diberi **NOT VERIFIED**: seluruh kesimpulan di atas memiliki bukti statis yang dapat ditelusuri pada implementasi repository saat audit. Audit ini tidak menjalankan perubahan data ataupun menguji UI terhadap instance backend hidup; karena itu laporan memverifikasi kemampuan implementasi yang tersedia, bukan ketersediaan data runtime tertentu.
