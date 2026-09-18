# UBUNTU-TRAFFIC — TEST CONNECTION

``` bash
ip addr
ip route
ip route get 10.10.20.2

ping -c 4 10.10.20.2

curl http://10.10.20.2:8080/
```



# UBUNTU-NIDS — CHECK SYSTEM


``` bash
cd ~/rf-nids
source .venv/bin/activate

docker compose ps

curl http://localhost:8000/health

docker compose exec api env | grep RF_NIDS_DEMO_MODEL
```



# DASHBOARD

``` text
Target    : 10.10.20.2
Interface : enp0s3
Model     : rf-v3.0-candidate
START MONITORING
Tunggu sampai RUNNING
```


# UBUNTU-TRAFFIC — PORTSCAN

``` bash
sudo nmap -n -Pn -sS -T4 \
  --max-retries 1 \
  --min-rate 100 \
  -p 3001-3600 \
  10.10.20.2
```



# EXPECTED DASHBOARD

``` text
Prediction : PortScan
Alert      : MEDIUM
Model      : rf-v3.0-candidate
```