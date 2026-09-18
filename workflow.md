# RF-NIDS Virtual Laboratory Testing Guide

Dokumen ini digunakan sebagai panduan pengujian dan demonstrasi runtime
RF-NIDS pada lingkungan virtual laboratory.

Pengujian memverifikasi dua aspek secara terpisah:

1.  **Pipeline Validation** --- memastikan trafik diproses end-to-end.
2.  **Detection Validation** --- mengevaluasi apakah Random Forest
    mengklasifikasikan trafik sesuai skenario.

> Pengujian hanya dilakukan pada virtual laboratory milik sendiri, bukan
> jaringan publik atau production.

## 1. Topologi Virtual Laboratory

  ------------------------------------------------------------------------
  VM                 Lab IP            Management IP     Role
  ------------------ ----------------- ----------------- -----------------
  `ubuntu-traffic`   `10.10.10.2`      `192.168.64.5`    Traffic Generator

  `ubuntu-nids`      `10.10.10.1`,     `192.168.64.20`   Router + RF-NIDS
                     `10.10.20.1`                        

  `ubuntu-target`    `10.10.20.2`      `192.168.64.6`    Target Server
  ------------------------------------------------------------------------

``` text
ubuntu-traffic                    ubuntu-nids                       ubuntu-target
10.10.10.2          10.10.10.1 ───────────── 10.10.20.1           10.10.20.2
     │                    │       Router/NIDS       │                    │
     └───────────────────►│                         │───────────────────►│
          10.10.10.0/24                              10.10.20.0/24
```

Traffic dari `ubuntu-traffic` menuju `ubuntu-target` harus melewati
`ubuntu-nids`.

## 2. Runtime Detection Pipeline

``` text
Network Traffic
      ↓
tcpdump
      ↓
PCAP
      ↓
CICFlowMeter V3
      ↓
Flow CSV
      ↓
Feature Adapter
      ↓
78 ordered features
      ↓
Random Forest (RF-v2)
      ↓
Normal / DDoS / PortScan
      ↓
Prediction
      ↓
PostgreSQL
      ↓
Streamlit Dashboard
```

## 3. Testing Workflow

``` text
Verify VM
   ↓
Verify Network Configuration
   ↓
Test Connection
   ↓
Test Target Service
   ↓
Verify Packet Capture
   ↓
Start RF-NIDS Monitoring
   ↓
Generate Normal Traffic
   ↓
Check Normal Prediction
   ↓
Generate PortScan Traffic
   ↓
Check PortScan Prediction
   ↓
Check Alert
   ↓
Stop Monitoring
   ↓
Runtime Validation
```

## 4. Test 1 --- Verify VM and Network Configuration

Jalankan pada masing-masing VM:

``` bash
hostname
ip -br addr
ip route
```

Pada `ubuntu-nids`, cek IP forwarding:

``` bash
sysctl net.ipv4.ip_forward
```

Expected:

``` text
net.ipv4.ip_forward = 1
```

Expected lab configuration:

``` text
ubuntu-traffic
  enp0s2: 10.10.10.2/24
  route : 10.10.20.0/24 via 10.10.10.1

ubuntu-nids
  enp0s2: 10.10.10.1/24
  enp0s3: 10.10.20.1/24

ubuntu-target
  enp0s2: 10.10.20.2/24
  route : 10.10.10.0/24 via 10.10.20.1
```

## 5. Test 2 --- Connectivity Test

Dari `ubuntu-nids`:

``` bash
ping -c 4 10.10.10.2
ping -c 4 10.10.20.2
```

Dari `ubuntu-traffic`:

``` bash
ping -c 4 10.10.20.2
ip route get 10.10.20.2
```

Expected route:

``` text
10.10.20.2 via 10.10.10.1 dev enp0s2 src 10.10.10.2
```

Ini membuktikan trafik menuju target diarahkan melalui `ubuntu-nids`.

## 6. Test 3 --- Target HTTP Service

Pada `ubuntu-target`, cek service HTTP lab, misalnya port 8080:

``` bash
ss -lntp | grep 8080
```

Dari `ubuntu-traffic`:

``` bash
curl -I http://10.10.20.2:8080/
```

Expected: HTTP response diterima.

## 7. Test 4 --- Verify Packet Capture

Pada `ubuntu-nids`:

``` bash
sudo tcpdump -ni enp0s2 host 10.10.20.2
```

Dari `ubuntu-traffic`:

``` bash
curl http://10.10.20.2:8080/
```

Paket harus terlihat pada `ubuntu-nids`.

Target-side interface juga dapat diverifikasi:

``` bash
sudo tcpdump -ni enp0s3 host 10.10.20.2
```

Hentikan manual capture dengan `Ctrl+C` sebelum monitoring aplikasi
dimulai.

## 8. Test 5 --- RF-NIDS Pre-check

Pada `ubuntu-nids`:

``` bash
cd ~/rf-nids
git status --short
docker ps
ls -lh models/
```

Pastikan aplikasi dapat diakses:

-   Login
-   Dashboard
-   Models
-   Evaluation
-   Monitoring
-   Predictions
-   Alerts
-   Runtime Validation

## 9. Test 6 --- Start Monitoring

Buka:

``` text
Streamlit → Monitoring
```

Gunakan target:

``` text
10.10.20.2
```

Pilih capture interface sesuai konfigurasi runtime, kemudian mulai
monitoring.

Expected lifecycle:

``` text
STARTING
   ↓
RUNNING
```

Jangan generate test traffic sebelum status `RUNNING`.

## 10. Test 7 --- Normal HTTP Traffic

Dari `ubuntu-traffic`:

``` bash
for i in $(seq 1 20); do
    curl -s http://10.10.20.2:8080/ > /dev/null
    sleep 0.5
done
```

Pipeline yang diuji:

``` text
HTTP Traffic
   ↓
tcpdump
   ↓
PCAP
   ↓
CICFlowMeter V3
   ↓
Flow CSV
   ↓
78-feature Adapter
   ↓
RF-v2
   ↓
Prediction
```

Buka `Streamlit → Predictions` dan catat hasil aktual:

``` text
Scenario   : Normal HTTP
Actual     : Normal
Predicted  : <actual prediction>
Probability: <actual probability>
```

`Normal → Normal` berarti Detection PASS. Prediksi kelas lain berarti
Detection FAIL. 

## 11. Test 8 --- PortScan Simulation

Pengujian ini hanya ditujukan ke VM target pada isolated lab.

Dari `ubuntu-traffic`:

``` bash
nmap -sT -p 1-1000 10.10.20.2
```

Pipeline:

``` text
PortScan
   ↓
ubuntu-nids routing/capture
   ↓
PCAP
   ↓
CICFlowMeter V3
   ↓
78-feature Adapter
   ↓
RF-v2
   ↓
Prediction + Probability
```

Buka `Streamlit → Predictions` dan catat:

``` text
Scenario   : PortScan
Actual     : PortScan
Predicted  : <actual prediction>
Probability: <actual probability>
```

`PortScan → PortScan` berarti Detection PASS. `PortScan → Normal`
berarti Detection FAIL.

## 12. Test 9 --- Alert Verification

Kebijakan alert:

``` text
Normal   → No alert
PortScan → MEDIUM
DDoS     → HIGH
```

Jika prediction adalah `PortScan`, buka `Streamlit → Alerts` dan
verifikasi alert MEDIUM terkait prediction/session.

Jika trafik PortScan diprediksi `Normal`, tidak adanya alert PortScan
konsisten dengan hasil prediction dan bukan kegagalan alert engine yang
terpisah.

## 13. Test 10 --- Stop Monitoring

Stop monitoring setelah pengujian selesai.

Expected:

``` text
RUNNING
   ↓
STOPPING
   ↓
STOPPED
```

Pastikan session tercatat pada monitoring history.

## 14. Test 11 --- Runtime Validation

Buka:

``` text
Streamlit → Runtime Validation
```

### Pipeline Validation

Periksa:

-   Traffic generated
-   Packet captured
-   PCAP artifact
-   CICFlowMeter output
-   Feature adapter
-   78-feature validation
-   RF inference
-   Prediction persistence

### Detection Validation

Bandingkan actual scenario dengan prediction:

``` text
Normal   → RF-v2 → Predicted ?
PortScan → RF-v2 → Predicted ?
```

## 15. Pipeline PASS vs Detection PASS

Pipeline dan detection adalah dua dimensi evaluasi berbeda.

Contoh:

``` text
PortScan generated        PASS
Traffic routed via NIDS   PASS
Packet captured           PASS
PCAP generated            PASS
Flow extracted            PASS
78 features validated     PASS
RF inference executed     PASS
Prediction stored         PASS

Actual                    PortScan
Predicted                 Normal

Pipeline Validation       PASS
Detection Validation      FAIL
```

Interpretasi: pipeline software berjalan end-to-end, tetapi model belum
berhasil menggeneralisasi trafik runtime tersebut.

## 16. Experiment D dan Experiment E

Workflow eksperimen:

``` text
CICIDS2017
   ↓
Training
   ↓
Experiment D / RF-v2
   ↓
Controlled Evaluation
   ↓
3-VM Runtime Validation
   ↓
Observed Runtime Distribution Shift
   ↓
Experiment E
Adaptation / Further Evaluation
```

Experiment E diperlakukan sebagai eksperimen lanjutan untuk
menyelidiki/adaptasi terhadap distribution shift yang ditemukan pada
runtime. Hasil Experiment E yang belum final tidak dipresentasikan
sebagai evidence final.

## 17. DDoS Scope

Model mendukung:

-   Normal
-   DDoS
-   PortScan

Demo virtual lab utama dalam dokumen ini berfokus pada:

-   Normal HTTP
-   PortScan

DDoS bukan skenario live utama pada demo ini dan keterbatasan
performanya tetap dilaporkan sebagai hasil eksperimen.

## 18. Final Testing Checklist

### Infrastructure

``` text
[ ] ubuntu-traffic running
[ ] ubuntu-nids running
[ ] ubuntu-target running
[ ] ubuntu-traffic = 10.10.10.2
[ ] ubuntu-nids = 10.10.10.1
[ ] ubuntu-nids = 10.10.20.1
[ ] ubuntu-target = 10.10.20.2
[ ] IP forwarding enabled
[ ] static routes correct
```

### Connectivity

``` text
[ ] ubuntu-nids → ubuntu-traffic PASS
[ ] ubuntu-nids → ubuntu-target PASS
[ ] ubuntu-traffic → ubuntu-target PASS
[ ] route passes through ubuntu-nids
```

### Target and Capture

``` text
[ ] HTTP service running
[ ] HTTP accessible from ubuntu-traffic
[ ] traffic visible on ubuntu-nids
[ ] correct capture interface selected
```

### Application

``` text
[ ] PostgreSQL running
[ ] FastAPI running
[ ] Streamlit running
[ ] Login works
[ ] Active model available
[ ] Monitoring works
[ ] Predictions works
[ ] Alerts works
[ ] Runtime Validation works
```

### Runtime Test

``` text
[ ] Start Monitoring
[ ] Status = RUNNING
[ ] Generate Normal HTTP
[ ] Record Normal prediction
[ ] Generate PortScan
[ ] Record PortScan prediction
[ ] Record probabilities
[ ] Verify alert if applicable
[ ] Stop Monitoring
[ ] Status = STOPPED
[ ] Execute Runtime Validation
[ ] Record Pipeline result
[ ] Record Detection result
[ ] Preserve evidence
```

## 19. Demo Sequence

``` text
1. Show 3-VM topology
       ↓
2. Show IP and routing
       ↓
3. Test connection
       ↓
4. Test HTTP target
       ↓
5. Verify packet capture
       ↓
6. Open Streamlit
       ↓
7. Start Monitoring
       ↓
8. Generate Normal HTTP
       ↓
9. Show Normal prediction
       ↓
10. Generate PortScan
       ↓
11. Show prediction/probability
       ↓
12. Show Alert if applicable
       ↓
13. Stop Monitoring
       ↓
14. Show Runtime Validation
       ↓
15. Explain Pipeline vs Detection result
```

Shortcut:

> **Network → Connection → Target → Capture → Monitoring → Normal →
> Prediction → PortScan → Prediction/Alert → Stop → Validation**
