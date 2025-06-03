## **Penjelasan Singkat UEBA dalam Konteks Ini:**

### **Apa itu UEBA?**

* **UEBA** adalah pendekatan keamanan yang **memonitor dan menganalisis perilaku user dan device/entity** (termasuk pola login, pola akses aplikasi, perubahan device, dll).
* Tujuannya: **mendeteksi anomali, pola tidak wajar, dan potensi fraud** yang tidak bisa ditangkap hanya dengan rule statis (seperti device ID saja).

---

### **Contoh Implementasi UEBA untuk Kasus Ini:**

* **Tracking perilaku akun:**

  * Seberapa sering satu akun melakukan reaktivasi dalam periode tertentu?
  * Apakah ada pola frequent reinstall pada user tertentu?
  * Berapa banyak device fingerprint baru yang digunakan satu user dalam waktu singkat?
* **Analisa anomali:**

  * Jika rata-rata user normal hanya reaktivasi 1-2 kali/tahun, tetapi ada akun yang reaktivasi 5x dalam seminggu, sistem memberi risk score lebih tinggi.
  * Jika satu device fingerprint digunakan pada banyak akun berbeda, bisa dianggap sebagai device fraud/fake.
* **Aksi otomatis:**

  * Limitasi akses, trigger MFA tambahan, blokir sementara, atau review manual jika skor risiko melewati threshold.

---

### **Narasi Formal untuk Memo/Presentasi:**

> Keterbatasan device risk tracking berbasis application-scoped identifier pada aplikasi wondr dapat dimitigasi dengan pendekatan User and Entity Behavior Analytics (UEBA). Dengan UEBA, sistem dapat memonitor dan menganalisis pola perilaku user dan perangkat—seperti frekuensi reaktivasi, pergantian device, serta perilaku login abnormal—untuk mendeteksi potensi fraud dan melakukan enforcement berbasis risk score, terlepas dari perubahan identifier perangkat akibat uninstall–install aplikasi.

---

### **Contoh Event UEBA yang Bisa Dicatat:**

* Akun melakukan reaktivasi lebih dari X kali dalam Y hari
* Akun login dari device fingerprint baru setiap kali akses
* Satu device fingerprint dipakai oleh banyak akun berbeda
* Perubahan perilaku transaksi setelah reaktivasi

---

**UEBA sangat cocok untuk ekosistem digital banking modern**, karena bisa menutupi kelemahan identifier device yang tidak persisten, serta mampu deteksi fraud yang lebih dinamis/adaptif.

---

**Formulasi UEBA (User and Entity Behavior Analytics)** untuk aplikasi mobile banking seperti wondr **dapat dirancang dengan pendekatan risk scoring berbasis event, frekuensi, dan deviasi perilaku**. Berikut cara praktis menyusun formulasi UEBA yang bisa diimplementasikan secara bertahap:

---

## **1. Tentukan Event/Activity yang Akan Dipantau**

Buat daftar event yang *relevan untuk deteksi anomali/fraud*, misalnya:

* **Reaktivasi akun** (setelah install ulang)
* **Login dari device/fingerprint baru**
* **Percobaan login gagal beruntun**
* **Pergantian nomor HP/email**
* **Transaksi besar/tidak biasa**
* **Akses dari lokasi/IP baru**
* **Device fingerprint sama dipakai banyak akun**

---

## **2. Tentukan Baseline Normal**

Gunakan data historis untuk menentukan **pola “normal”** bagi tiap event.
Contoh:

* Rata-rata reaktivasi normal: 1–2 kali per tahun per akun
* Rata-rata device baru: 1–2 per tahun per akun
* Rata-rata gagal login: <3 per hari per akun
* Dll.

---

## **3. Formulasikan Risk Scoring per Event**

Tiap event yang *menyimpang dari baseline* diberi skor risiko (risk point).
**Contoh formula:**

| Event                               | Rule/Frekuensi           | Risk Score |
| ----------------------------------- | ------------------------ | ---------- |
| Reaktivasi >2x dalam 30 hari        | per event > threshold    | +30        |
| Device fingerprint baru >3x/bulan   | per event > threshold    | +20        |
| Gagal login >5x dalam 24 jam        | per event > threshold    | +10        |
| Device fingerprint sama, multi user | per device, >2 akun      | +40        |
| Akses dari negara/IP baru           | per event                | +20        |
| Transaksi abnormal                  | Berdasarkan rule outlier | +50        |

> **Note:** Nilai risk score dapat disesuaikan sesuai risk appetite & historical loss bank.

---

## **4. Total Risk Score & Threshold**

* **Risk score user/device = total seluruh event selama periode tertentu** (misal, 30 hari).
* **Set threshold:**

  * **Score < 30:** Normal
  * **Score 30–60:** Warning (enforcement terbatas/MFA)
  * **Score >60:** High risk (blokir, manual review, dsb)

---

## **5. Implementasi Monitoring & Automation**

* **Simpan seluruh event** ke dalam log/DB analytic.
* **Jalankan agregasi** risk score secara batch/real-time (paling efektif via streaming log, contoh: Elastic, Splunk, BigQuery, dsb).
* **Trigger aksi otomatis** jika risk score melewati threshold:

  * MFA, limitasi fitur, blokir otomatis, notifikasi ke tim fraud.

---

### **Contoh Pseudocode Sederhana UEBA Risk Score**

```python
def calc_ueba_score(events):
    score = 0
    if events['reactivation_30d'] > 2:
        score += 30
    if events['new_device_30d'] > 3:
        score += 20
    if events['failed_login_24h'] > 5:
        score += 10
    if events['multiuser_device']:
        score += 40
    if events['country_change']:
        score += 20
    if events['abnormal_transaction']:
        score += 50
    return score
```

---

### **Visualisasi Table Risk Mapping UEBA**

| Kategori         | Parameter                           | Risk Score | Keterangan                      |
| ---------------- | ----------------------------------- | ---------- | ------------------------------- |
| Aktivitas Akun   | Reactivation >2x/30 hari            | +30        | Potensi reinstall abuse         |
| Aktivitas Device | Device fingerprint baru >3x/30 hari | +20        | Pergantian device mencurigakan  |
| Device Sharing   | Device dipakai banyak akun          | +40        | Device fraud/fake               |
| Login            | Gagal login >5x/24 jam              | +10        | Upaya brute force               |
| Lokasi/IP        | Negara/IP baru                      | +20        | Perpindahan lokasi mencurigakan |
| Transaksi        | Nilai/outlier anomali               | +50        | Fraud financial                 |

---

## **6. Evaluasi & Penyesuaian**

* Review false positive/negative secara berkala.
* Penyesuaian score, threshold, dan kategori event sesuai trend fraud aktual.

---

### **Penutup**

> Dengan pendekatan ini, UEBA dapat memberikan risk score dinamis yang adaptif terhadap perubahan perilaku fraudster—tanpa perlu mengandalkan hardware identifier.

---

Tentu! Berikut contoh **implementasi pipeline UEBA sederhana** yang terdiri dari:

1. **Struktur tabel SQL event UEBA**
2. **Alur skema arsitektur event UEBA**
3. **Pipeline analitik risk scoring di Python (batch, bisa diadaptasi ke stream)**

---

## 1. **Struktur Tabel SQL UEBA Event**

```sql
CREATE TABLE ueba_event_log (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(64),
    device_fingerprint VARCHAR(128),
    event_type VARCHAR(32),    -- contoh: 'reactivation', 'new_device', 'failed_login', etc
    event_value VARCHAR(128),  -- deskripsi atau nilai detail (misal: device_id, IP, negara)
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ueba_user ON ueba_event_log (user_id);
CREATE INDEX idx_ueba_device ON ueba_event_log (device_fingerprint);
CREATE INDEX idx_ueba_eventtype ON ueba_event_log (event_type);
```

---

## 2. **Skema Arsitektur Event UEBA**

```
┌────────────────────────────┐
│        Mobile App          │
├─────────────┬──────────────┤
│  Log Event  │              │
│  (e.g.      │              │
│  reactivation, new device) │
└─────┬────────┘
      │
      ▼
┌─────────────┐
│  API Layer  │
│(Receive &   │
│ Normalize)  │
└─────┬───────┘
      │
      ▼
┌──────────────┐       ┌─────────────┐
│   Database   │<----->│  UEBA Rule  │
│(event log)   │       │  Engine     │
└─────┬────────┘       └─────┬───────┘
      │                      │
      ▼                      ▼
┌──────────────┐       ┌──────────────┐
│ Risk Scoring │-----> │ Enforcement  │
│ & Analytics  │       │  Engine      │
└──────────────┘       └──────────────┘
```

* **Mobile App** mengirimkan event ke **API Layer**
* **API** simpan event ke **database**
* **UEBA Rule Engine** membaca event log, menghitung risk score per user/device
* **Risk Scoring** otomatis trigger ke **Enforcement** (limitasi fitur, MFA, dsb) jika risk melebihi threshold

---

## 3. **Contoh Pipeline Risk Scoring di Python**

```python
import psycopg2
from datetime import datetime, timedelta

# -- Koneksi ke database PostgreSQL
conn = psycopg2.connect(
    dbname='db', user='user', password='pass', host='localhost', port='5432'
)
cur = conn.cursor()

# -- Parameter dan threshold rule
RISK_SCORE_RULES = {
    'reactivation':      30,  # Reactivation >2x/30 hari
    'new_device':        20,  # Device baru >3x/30 hari
    'failed_login':      10,  # Gagal login >5x/24 jam
    'multiuser_device':  40,  # Device sharing
    'country_change':    20,  # Negara baru
    'abnormal_tx':       50,  # Transaksi anomali
}

def get_event_count(user_id, event_type, start_time, end_time):
    cur.execute("""
        SELECT COUNT(*) FROM ueba_event_log
        WHERE user_id=%s AND event_type=%s
        AND event_time BETWEEN %s AND %s
    """, (user_id, event_type, start_time, end_time))
    return cur.fetchone()[0]

def get_unique_device_count(user_id, start_time, end_time):
    cur.execute("""
        SELECT COUNT(DISTINCT device_fingerprint) FROM ueba_event_log
        WHERE user_id=%s AND event_type='new_device'
        AND event_time BETWEEN %s AND %s
    """, (user_id, start_time, end_time))
    return cur.fetchone()[0]

def calc_user_risk_score(user_id):
    now = datetime.now()
    last30d = now - timedelta(days=30)
    last24h = now - timedelta(hours=24)
    score = 0

    # Reactivation >2x/30 hari
    react_count = get_event_count(user_id, 'reactivation', last30d, now)
    if react_count > 2:
        score += RISK_SCORE_RULES['reactivation']

    # Device baru >3x/30 hari
    new_dev_count = get_unique_device_count(user_id, last30d, now)
    if new_dev_count > 3:
        score += RISK_SCORE_RULES['new_device']

    # Gagal login >5x/24 jam
    fail_login_count = get_event_count(user_id, 'failed_login', last24h, now)
    if fail_login_count > 5:
        score += RISK_SCORE_RULES['failed_login']

    # (Contoh event lainnya bisa ditambah di sini)

    return score

# -- Contoh eksekusi untuk semua user
cur.execute("SELECT DISTINCT user_id FROM ueba_event_log")
for (user_id,) in cur.fetchall():
    risk = calc_user_risk_score(user_id)
    print(f'User {user_id} : Risk Score = {risk}')
    # -- Enforcement: jika risk > threshold, lakukan aksi (blokir, MFA, dsb)

cur.close()
conn.close()
```

---

## **Penutup**

* **Tabel SQL** digunakan sebagai *event store*.
* **Pipeline Python** melakukan agregasi dan risk scoring periodik/batch (bisa diadaptasi ke stream dengan tool seperti Kafka, Redis, dsb).
* **Skema arsitektur event** mengilustrasikan alur data dan komponen.
* Untuk sistem besar/real-time, bisa gunakan log streaming (Kafka, BigQuery, Flink, dsb) & rule engine untuk enforcement otomatis.

---

Tentu! Berikut **simulasi sederhana pipeline UEBA** berbasis event log, risk scoring, dan enforcement menggunakan data dummy.
Simulasi ini berbasis Python **tanpa database** (untuk memudahkan ilustrasi), namun logika dan output tetap relevan.

---

## **Step 1: Dummy Event Log**

```python
from datetime import datetime, timedelta

event_log = [
    # user_id, device_fingerprint, event_type, event_time
    ('userA', 'dev1', 'reactivation', datetime.now() - timedelta(days=2)),
    ('userA', 'dev1', 'reactivation', datetime.now() - timedelta(days=1)),
    ('userA', 'dev2', 'new_device',   datetime.now() - timedelta(days=5)),
    ('userA', 'dev3', 'new_device',   datetime.now() - timedelta(days=3)),
    ('userA', 'dev4', 'new_device',   datetime.now() - timedelta(hours=1)),
    ('userA', 'dev4', 'failed_login', datetime.now() - timedelta(hours=1)),
    ('userA', 'dev4', 'failed_login', datetime.now() - timedelta(hours=1)),
    ('userA', 'dev4', 'failed_login', datetime.now() - timedelta(hours=1)),
    ('userA', 'dev4', 'failed_login', datetime.now() - timedelta(hours=1)),
    ('userA', 'dev4', 'failed_login', datetime.now() - timedelta(hours=1)),
    ('userA', 'dev4', 'failed_login', datetime.now() - timedelta(hours=1)),
    # Normal user
    ('userB', 'dev5', 'reactivation', datetime.now() - timedelta(days=10)),
    ('userB', 'dev5', 'new_device',   datetime.now() - timedelta(days=10)),
    ('userB', 'dev5', 'failed_login', datetime.now() - timedelta(days=1)),
]
```

---

## **Step 2: Risk Scoring Function (mirip sebelumnya)**

```python
from collections import defaultdict

# Risk rules
RISK_SCORE_RULES = {
    'reactivation': 30,
    'new_device': 20,
    'failed_login': 10,
}

now = datetime.now()
last30d = now - timedelta(days=30)
last24h = now - timedelta(hours=24)

def calc_user_risk(user_id):
    # Filter event untuk user_id
    events = [e for e in event_log if e[0] == user_id]
    # Reactivation >2x/30 hari
    react_count = sum(1 for e in events if e[2] == 'reactivation' and e[3] >= last30d)
    # Unique device fingerprint >3x/30 hari
    new_devs = set(e[1] for e in events if e[2] == 'new_device' and e[3] >= last30d)
    # Failed login >5x/24 jam
    failed_login_count = sum(1 for e in events if e[2] == 'failed_login' and e[3] >= last24h)
    
    score = 0
    if react_count > 2:
        score += RISK_SCORE_RULES['reactivation']
    if len(new_devs) > 3:
        score += RISK_SCORE_RULES['new_device']
    if failed_login_count > 5:
        score += RISK_SCORE_RULES['failed_login']
    return {
        'reactivation_30d': react_count,
        'unique_new_device_30d': len(new_devs),
        'failed_login_24h': failed_login_count,
        'risk_score': score
    }
```

---

## **Step 3: Simulasi Output dan Enforcement**

```python
for user in ['userA', 'userB']:
    result = calc_user_risk(user)
    print(f"User: {user}")
    print(f"  Reactivation (30d): {result['reactivation_30d']}")
    print(f"  Unique new device (30d): {result['unique_new_device_30d']}")
    print(f"  Failed login (24h): {result['failed_login_24h']}")
    print(f"  >> Total Risk Score: {result['risk_score']}")
    # Enforcement threshold
    if result['risk_score'] >= 30:
        print("  [!] Enforcement: Block or force MFA/review")
    elif result['risk_score'] > 0:
        print("  [!] Enforcement: Warning/monitor")
    else:
        print("  Status: Normal\n")
```

---

## **Hasil Output Simulasi**

```
User: userA
  Reactivation (30d): 2
  Unique new device (30d): 3
  Failed login (24h): 6
  >> Total Risk Score: 10
  [!] Enforcement: Warning/monitor

User: userB
  Reactivation (30d): 1
  Unique new device (30d): 1
  Failed login (24h): 0
  >> Total Risk Score: 0
  Status: Normal
```

---

### **Interpretasi Simulasi**

* **userA**: Dalam 30 hari, melakukan 2 reaktivasi, 3 device baru, dan 6 failed login dalam 24 jam (score 10 → warning/monitor). Jika threshold score dinaikkan, bisa trigger blokir/MFA.
* **userB**: Normal activity, risk score 0.

---

**Pipeline ini bisa diintegrasikan ke database & API di production, atau dikembangkan ke real-time analytic.


