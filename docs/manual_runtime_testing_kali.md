# Manual Testing Monitoring Traffic dan Simulasi Serangan via Kali

Tanggal dokumen: 2026-09-04

Dokumen ini menjelaskan langkah manual untuk menguji pipeline runtime RF-NIDS dengan:

- traffic normal dari Kali ke Ubuntu target
- simulasi `PortScan` dari Kali
- simulasi beban HTTP terkontrol yang dapat teramati sebagai traffic `DDoS`-like

Dokumen ini mengikuti batas yang sudah dijelaskan di `README.md`, `docs/experiment_c_lab.md`,
`docs/phase_10_runtime_capture_pipeline.md`, dan
`docs/phase_11_virtual_lab_runtime_validation.md`.

## 1. Tujuan

Tujuan pengujian ini adalah memverifikasi jalur runtime end-to-end:

`capture interface -> tcpdump -> PCAP -> CICFlowMeter V3 -> 78-feature adapter -> inference -> database -> alerts -> dashboard`

Pengujian ini memvalidasi integrasi runtime. Pengujian ini tidak digunakan untuk:

- retraining model
- tuning threshold
- mengubah artefak ilmiah yang sudah dibekukan
- mengklaim akurasi production

## 2. Batas dan keselamatan

Gunakan hanya lab privat milik sendiri atau yang memiliki izin eksplisit.

Aturan wajib:

- jangan gunakan jaringan publik, kantor, kampus, atau internet terbuka
- jangan gunakan bridged networking untuk traffic eksperimen
- target harus private IP di network terisolasi
- traffic serangan dijalankan manual dari Kali, bukan dari RF-NIDS
- hentikan pengujian bila routing/NAT tidak sesuai

Catatan:

- `PortScan` boleh dijalankan hanya ke host lab milik sendiri
- skenario `DDoS` di sini adalah beban HTTP single-source yang terkontrol, bukan serangan ke sistem nyata

## 3. Topologi lab

Gunakan tiga mesin atau role:

- Host macOS: menjalankan RF-NIDS
- Ubuntu target: host private yang menyediakan service HTTP
- Kali attacker/operator: menghasilkan traffic manual

Contoh rencana IP:

- Ubuntu: `192.168.56.10/24`
- Kali: `192.168.56.20/24`

Host RF-NIDS harus dapat melihat traffic pada interface private/host-only hypervisor.

## 4. Prasyarat

Pastikan hal berikut tersedia:

- Python environment project sudah siap
- PostgreSQL aktif
- migration database sudah dijalankan
- Docker aktif
- image CICFlowMeter V3 sudah bisa dibangun
- `tcpdump` tersedia di host
- akun admin RF-NIDS sudah dibuat
- Ubuntu dan Kali berada di jaringan private yang sama

## 5. Menjalankan RF-NIDS

Jalankan dari root project:

```bash
cd /Users/wahyudev/Wahyudev/ai_projects/rf_nids
source .venv/bin/activate
docker compose up -d postgres
alembic upgrade head
docker compose build cicflowmeter
docker compose up -d --build
```

Jalankan API:

```bash
uvicorn src.api.main:app --reload
```

Jalankan dashboard:

```bash
streamlit run dashboard/app.py
```

Akses:

- API: `http://localhost:8000`
- OpenAPI: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8501`

## 6. Verifikasi interface capture

Di host RF-NIDS, identifikasi interface yang benar:

```bash
python scripts/run_live_capture.py --list-interfaces
```

Pilih interface private yang benar-benar membawa traffic Ubuntu <-> Kali.

Jangan mengasumsikan `en0` otomatis benar. Nama seperti `bridge*`, `vmnet*`, `vboxnet*`,
`utun*`, atau `tap*` hanya kandidat.

## 7. Menyiapkan Ubuntu target

Di Ubuntu, pastikan private IP benar lalu jalankan HTTP service sederhana:

```bash
python3 -m http.server 8080 --bind 192.168.56.10
```

Service harus bind hanya ke private IP lab.

## 8. Menyiapkan Kali

Dari Kali, verifikasi konektivitas dasar ke Ubuntu:

```bash
ping -c 4 192.168.56.10
curl --fail http://192.168.56.10:8080/
```

Kalau ini gagal, jangan lanjut ke pengujian monitoring atau simulasi serangan.

## 9. Memulai monitoring session

1. Login ke dashboard sebagai admin.
2. Buka halaman `Monitoring`.
3. Start monitoring session.
4. Isi target IP dengan IP Ubuntu private, misalnya `192.168.56.10`.
5. Pilih interface capture private yang sudah diverifikasi.
6. Pastikan status sesi berubah menjadi `RUNNING`.

Setelah sesi aktif, RF-NIDS akan menjalankan window capture berulang:

`tcpdump -> PCAP -> flow extraction -> adapter -> predict -> persist`

Artefak runtime sesi disimpan di:

`data/runtime/monitoring/<session-id>/`

## 10. Skenario A: traffic normal

Tujuan skenario ini adalah memastikan traffic HTTP biasa dapat melewati pipeline dan dominan
terklasifikasi sebagai `Normal`.

Langkah:

1. Pastikan monitoring session masih `RUNNING`.
2. Jika halaman Monitoring mendukung validation run, buat validation `NORMAL_HTTP`.
3. Dari Kali, kirim request HTTP biasa:

```bash
curl http://192.168.56.10:8080/
curl http://192.168.56.10:8080/
curl http://192.168.56.10:8080/
```

4. Tunggu minimal satu window capture selesai.
5. Buka halaman `Monitoring` dan `Predictions`.
6. Jika validation run dibuat, complete validation setelah prediction masuk.

Expected result:

- session tetap `RUNNING`
- flow runtime bertambah
- prediction baru muncul untuk session aktif
- distribusi prediction dominan `Normal`
- halaman `Alerts` tidak menambah alert untuk flow yang diprediksi `Normal`

Evidence yang sebaiknya dicatat:

- screenshot Monitoring sebelum dan sesudah traffic
- screenshot Predictions
- session ID
- waktu mulai dan selesai uji

## 11. Skenario B: PortScan dari Kali

Tujuan skenario ini adalah memastikan scan TCP connect dari Kali terlihat oleh pipeline dan,
bila model mengenalinya, menghasilkan prediction `PortScan` dan alert `MEDIUM`.

Langkah:

1. Pastikan monitoring session tetap `RUNNING`.
2. Jika tersedia, buat validation `PORTSCAN` dari halaman Monitoring.
3. Dari Kali, jalankan scan hanya ke private IP target:

```bash
nmap -n -Pn -sT -T3 -p 1-200 192.168.56.10
```

Alternatif yang juga pernah direkam di dokumen eksperimen:

```bash
nmap -n -Pn -sT -T4 -p 300-520 192.168.56.10
```

4. Tunggu window capture, extraction, inference, dan persistence selesai.
5. Buka `Monitoring`, `Predictions`, dan `Alerts`.
6. Jika validation run dibuat, complete validation.

Expected result minimum:

- pipeline menangkap traffic dan menyimpan flow/prediction
- session tidak `FAILED`
- prediction terkait session monitoring aktif tercatat

Expected result jika model mendeteksi scan:

- setidaknya satu prediction berlabel `PortScan`
- alert baru dengan severity `MEDIUM`

Interpretasi hasil:

- `pipeline PASS` dan `detection FAIL` tetap valid
- ini berarti traffic scan berhasil tertangkap dan diproses, tetapi model memprediksi label lain

Evidence yang sebaiknya dicatat:

- command scan yang dipakai
- session ID dan validation ID
- screenshot Predictions yang menampilkan label hasil
- screenshot Alerts bila ada alert `MEDIUM`

## 12. Skenario C: HTTP flood terkontrol dari Kali

Tujuan skenario ini adalah menghasilkan beban HTTP single-source yang cukup padat sehingga
pipeline runtime menerima traffic intensif yang dapat muncul sebagai `DDoS`-like di model.

Skenario ini hanya untuk service lab milik sendiri. Jangan gunakan terhadap sistem lain.

Langkah:

1. Pastikan monitoring session masih `RUNNING`.
2. Dari Kali, jika `ab` tersedia, jalankan beban awal:

```bash
ab -n 600 -c 4 http://192.168.56.10:8080/
```

3. Bila ingin menaikkan beban secara bertahap, gunakan salah satu:

```bash
ab -n 1200 -c 8 http://192.168.56.10:8080/
```

```bash
ab -t 5 -c 12 http://192.168.56.10:8080/
```

4. Tunggu satu atau dua window capture selesai.
5. Buka `Monitoring`, `Predictions`, dan `Alerts`.

Expected result minimum:

- flow runtime meningkat signifikan dibanding skenario normal
- prediction tercatat untuk session aktif
- session tetap `RUNNING` atau dapat diselesaikan normal

Expected result jika model mendeteksi traffic attack-like:

- muncul satu atau lebih prediction `DDoS`
- alert baru dengan severity `HIGH`

Interpretasi hasil:

- bila prediction tetap `Normal`, jangan ubah threshold atau model hanya untuk membuat hasil tampak bagus
- catat hasil apa adanya karena pipeline correctness dan detection effectiveness adalah dua hal berbeda

Evidence yang sebaiknya dicatat:

- command `ab` yang dipakai
- screenshot Monitoring summary
- screenshot Predictions dengan label dan confidence
- screenshot Alerts bila severity `HIGH` muncul

## 13. Verifikasi pasca-uji

Setelah tiap skenario, verifikasi hal berikut:

- counter flow di Monitoring bertambah
- data prediction muncul di halaman Predictions
- `monitoring_session_id` pada prediction terkait session aktif
- `Normal` tidak membuat alert
- `PortScan` membuat alert `MEDIUM`
- `DDoS` membuat alert `HIGH`
- artefak sesi tersimpan di `data/runtime/monitoring/<session-id>/`

Jika session gagal:

- buka status error di Monitoring
- cek log API
- cek log container extractor
- cek apakah interface capture benar
- cek apakah `tcpdump` dan Docker memiliki izin yang dibutuhkan

## 14. Mengakhiri pengujian

1. Stop monitoring dari halaman `Monitoring`.
2. Pastikan status session berubah menjadi `STOPPED`.
3. Pastikan tidak ada prediction baru yang masih masuk ke session lama setelah stop.
4. Simpan screenshot dan catatan evidence.
5. Matikan service HTTP Ubuntu bila sudah selesai.

## 15. Format catatan hasil yang disarankan

Gunakan format ringkas berikut untuk setiap skenario:

```text
Tanggal:
Operator:
Scenario:
Target IP:
Kali IP:
Monitoring session ID:
Validation ID:
Command:
Start time:
End time:
Observed predictions:
Observed alerts:
Pipeline result:
Detection result:
Notes:
```

## 16. Kesimpulan interpretasi

Pengujian manual ini dianggap berhasil secara integrasi bila:

- traffic dari lab private benar-benar tertangkap
- flow berhasil diekstrak dan diadaptasi ke 78 fitur
- prediction berhasil dipersist ke database
- dashboard menampilkan data runtime session tersebut

Pengujian deteksi dianggap berhasil hanya bila label hasil sesuai skenario yang diuji.

Keduanya harus dicatat terpisah:

- keberhasilan pipeline runtime
- keberhasilan deteksi model
