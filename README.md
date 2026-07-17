<div align="center">

# 🛡️ ExactusWAF

**Firewall untuk website Anda — cukup klik dua kali, langsung terlindungi.**

Menyaring serangan hacker (SQL Injection, XSS, Log4Shell, & puluhan CVE terbaru)
_sebelum_ sampai ke website Anda. Dibuat agar **mudah dipakai siapa saja**, tanpa
perlu jadi ahli keamanan.

</div>

```
   Pengunjung  ──►   🛡️ ExactusWAF   ──►   Website Anda
   (& hacker)        (menyaring &            (aman, hanya
                      memblokir)              lalu-lintas bersih masuk)
```

---

## 🎯 Untuk siapa ini?

Anda punya website/aplikasi (toko online, blog, API, panel admin) dan ingin
melindunginya dari serangan otomatis — **tanpa** menyewa ahli, **tanpa** langganan
mahal, dan **tanpa** setup yang rumit. Cukup taruh ExactusWAF di depan website Anda.

---

## 🚀 Mulai dalam 3 Langkah (Windows)

> Tidak perlu memasang apa pun. File `exactuswaf.exe` sudah disertakan.

**1️⃣ Beri tahu alamat website Anda**
Buka file **`config.yaml`** dengan Notepad. Ubah satu baris ini:
```yaml
backend: "http://127.0.0.1:3000"    # ← ganti ke alamat website asli Anda
```
*(Misal website Anda jalan di port 8000, tulis `http://127.0.0.1:8000`)*

**2️⃣ Jalankan**
Klik dua kali **`Jalankan-ExactusWAF.bat`**. Selesai — WAF langsung aktif. ✅

**3️⃣ Akses lewat WAF**
- Buka website Anda di **`http://localhost:8080`** (lewat WAF, bukan port asli)
- Pantau serangan di **`http://localhost:9090`** (login: `admin`, password ada di `config.yaml`)

Itu saja. 🎉

---

## 🐧 Untuk Linux / macOS

```bash
bash install.sh      # membangun program (butuh Go: https://go.dev/dl/)
nano config.yaml     # arahkan 'backend' ke website Anda
./exactuswaf         # jalankan
```

---

## ✨ Yang Dilindungi

ExactusWAF membawa **30+ aturan siap pakai**, termasuk kerentanan (CVE) terbaru:

| Jenis Serangan | Contoh yang Dicegah |
|---|---|
| 💉 **SQL Injection** | Pencurian isi database lewat form/URL |
| 🔗 **Cross-Site Scripting (XSS)** | Penyisipan script jahat ke halaman |
| 📂 **Path Traversal / LFI** | Membaca file rahasia server (`/etc/passwd`, `.env`) |
| 💻 **Command Injection / RCE** | Menjalankan perintah di server Anda |
| 🌐 **SSRF & XXE** | Memaksa server mengakses sumber internal |
| 🔍 **Scanner otomatis** | sqlmap, nikto, nuclei, dsb. |
| 🚨 **CVE terkini** | Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), MOVEit, Citrix, Ivanti, PAN-OS (CVE-2024-3400), PHP-CGI (CVE-2024-4577), Confluence, F5 BIG-IP, Struts2, dan banyak lagi |

**Fitur pelengkap:**
- 🔨 **Auto-Ban** — IP yang menyerang berulang otomatis diblokir sementara *(aktif otomatis)*
- 📊 **Dashboard** real-time di browser
- 📱 **Notifikasi Telegram** saat ada serangan *(opsional)*
- 🚦 **Rate limiting** — cegah banjir permintaan
- 📋 **Blocklist / allowlist IP**
- 🧪 **Mode monitor** — uji coba dulu tanpa memblokir
- 🔒 **HTTPS** opsional

---

## 📊 Dashboard Pemantauan (GUI Realtime)

Ada dua cara membuka dashboard:
- **Seperti aplikasi:** klik dua kali **`Dashboard-ExactusWAF.bat`** — terbuka
  dalam jendela aplikasi tersendiri (tanpa address bar).
- **Di browser biasa:** buka `http://localhost:9090` (login user `admin`).

Isi dashboard (menyegar otomatis tiap 2 detik):

| Panel | Menampilkan |
|---|---|
| 📈 **Kartu statistik** | Total permintaan, serangan diblokir, permintaan aman, jumlah aturan aktif, lama aktif |
| 🎯 **Aturan yang Teraplikasi** | Aturan mana saja yang **terpicu**, berapa kali, lengkap CVE & tingkat bahaya — dalam bentuk bar realtime |
| 🌐 **Total Hit per IP** | Peringkat IP penyerang berdasarkan jumlah hit |
| 📜 **Serangan Terbaru** | Daftar kejadian terakhir: waktu, IP, path, aturan, CVE, aksi |

---

## ⚙️ Pengaturan (`config.yaml`)

Semua diatur lewat satu file `config.yaml` yang bisa diedit di Notepad.
Baris paling penting:

| Pengaturan | Arti | Saran |
|---|---|---|
| `backend` | Alamat website asli Anda | **wajib diisi** |
| `mode` | `block` atau `monitor` | mulai `monitor`, lalu `block` |
| `dashboard.password` | Password dashboard | **ganti dari default!** |
| `auto_ban` | Blokir otomatis penyerang | biarkan aktif |
| `auto_ban.scope` | `ip_ua` (aman utk IP bersama/CGNAT) atau `ip` | `ip_ua` untuk web publik |
| `trust_proxy_headers` | Percaya header IP dari proxy depan | `true` **hanya** bila di belakang Nginx/Cloudflare |
| `rate_limit` | Batas permintaan per IP | sesuaikan trafik Anda |

> 💡 **Tips untuk pertama kali:** pakai `mode: monitor` selama 1–2 hari. WAF hanya
> mencatat (tidak memblokir), jadi Anda bisa memastikan tidak ada pengunjung sah
> yang salah tangkap. Setelah yakin, ubah ke `mode: block`.

---

## 📱 Notifikasi Telegram (opsional, 5 menit)

Ingin dapat pesan di HP tiap kali ada IP diblokir otomatis?

1. Buka Telegram, chat **@BotFather** → ketik `/newbot` → ikuti langkahnya → **salin token bot**.
2. Chat **@userinfobot** → salin angka **Id** Anda.
3. Kirim satu pesan apa saja ke bot baru Anda (agar bot boleh mengirim pesan).
4. Isi di `config.yaml`:
   ```yaml
   notify:
     telegram:
       enabled: true
       bot_token: "TOKEN_DARI_BOTFATHER"
       chat_id: "ID_ANDA"
   ```
5. Jalankan ulang ExactusWAF — Anda akan langsung menerima pesan "ExactusWAF aktif".

---

## ❓ Pertanyaan Umum & Masalah

<details>
<summary><b>Muncul error "socket ... forbidden" saat dijalankan</b></summary>

Port 8080 sedang dipakai program lain atau dikunci Windows (sering karena
Hyper-V/WSL). **Solusi:** buka `config.yaml`, ubah `listen` ke port lain seperti
`0.0.0.0:8000` atau `0.0.0.0:8088`, lalu jalankan lagi.
</details>

<details>
<summary><b>Muncul "502 Bad Gateway"</b></summary>

WAF berhasil jalan, tapi website asli Anda (`backend`) sedang mati. Pastikan
aplikasi Anda berjalan dan alamat `backend` di `config.yaml` sudah benar.
</details>

<details>
<summary><b>Pengunjung yang sah ikut terblokir</b></summary>

Ubah sementara ke `mode: monitor`, lihat di dashboard aturan mana yang memicu,
lalu masukkan IP tepercaya (mis. IP kantor Anda) ke `ip_allowlist` di `config.yaml`.
</details>

<details>
<summary><b>Apakah harus memasang Go?</b></summary>

**Windows:** tidak. File `exactuswaf.exe` sudah disertakan, tinggal klik.
Anda hanya perlu Go bila ingin **membangun ulang** setelah mengubah kode/aturan
(pakai `Build-ExactusWAF.bat`).
**Linux/macOS:** ya, untuk membangun binary lewat `install.sh`.
</details>

<details>
<summary><b>Apakah auto-ban bisa menyeret pengguna lain di ISP yang sama (Telkomsel, dll.)?</b></summary>

Pertanyaan bagus. Banyak ISP (terutama seluler seperti Telkomsel/Indosat) memakai
**CGNAT** — ribuan pengguna berbagi satu IP publik. Memblokir IP mentah bisa
menyeret orang tak bersalah.

ExactusWAF mengatasinya dengan **dua cara**:

1. **`auto_ban.scope: ip_ua`** (default). Ban tidak hanya berdasarkan IP, tapi
   IP **+ jenis peramban**. Pengguna sah yang memakai browser biasa tidak berbagi
   "identitas" dengan alat serangan (sqlmap, bot, dll.), jadi mereka **tidak ikut
   terblokir** walau berbagi IP yang sama.
2. **Setiap serangan tetap diblokir per-permintaan** oleh aturan WAF, terlepas dari
   auto-ban. Jadi perlindungan situs **tidak bergantung** pada ban IP — auto-ban
   hanya "bonus" untuk menghentikan pemindai yang membandel.

Kalau audiens Anda dipastikan ber-IP unik (mis. jaringan kantor), Anda boleh pakai
`scope: ip` yang lebih ketat. Untuk web publik, biarkan `ip_ua`. Anda juga selalu
bisa menambah IP tepercaya ke `ip_allowlist`.
</details>

<details>
<summary><b>Kenapa `trust_proxy_headers` default-nya false?</b></summary>

Bila WAF langsung menghadap internet, header seperti `X-Forwarded-For` **bisa
dipalsukan** penyerang — untuk menghindari ban, atau justru untuk sengaja memban
IP orang lain. Maka header itu diabaikan secara default (WAF memakai IP koneksi
asli). **Aktifkan `true` hanya** jika ExactusWAF berdiri di belakang reverse proxy
tepercaya (Nginx/Cloudflare/Load Balancer) yang menambahkan header itu.
</details>

<details>
<summary><b>Apakah ini menggantikan Cloudflare / antivirus?</b></summary>

Tidak sepenuhnya. ExactusWAF adalah **satu lapis pertahanan**. Tetap lakukan
praktik dasar: perbarui software, pakai password kuat, dan validasi input di
aplikasi Anda. Keamanan itu berlapis. 🧅
</details>

---

## 🔄 Menambah / Memperbarui Aturan CVE

Aturan ada di `internal/rules/cve_rules.json`. Untuk menambah aturan tanpa
compile ulang, arahkan `rules_file` di `config.yaml` ke file itu, lalu tambahkan blok:

```json
{
  "id": "CVE-2025-XXXXX",
  "name": "Nama singkat serangan",
  "cve": "CVE-2025-XXXXX",
  "severity": "critical",
  "category": "rce",
  "target": "all",
  "pattern": "(?i)pola-regex-untuk-mendeteksi"
}
```
`target` bisa `url`, `header`, `body`, atau `all`.

---

## 🧪 Uji Cepat (opsional)

Setelah WAF jalan, dari terminal:
```bash
# Harus DIBLOKIR (HTTP 403):
curl "http://localhost:8080/.env"

# Harus LOLOS (HTTP 200):
curl "http://localhost:8080/"
```

---

## 📁 Isi Folder

```
ExactusWAF/
├── Jalankan-ExactusWAF.bat     ← klik untuk menjalankan (Windows)
├── Dashboard-ExactusWAF.bat    ← klik untuk membuka dashboard (GUI)
├── Build-ExactusWAF.bat        ← klik untuk membangun ulang
├── install.sh                  ← installer Linux/macOS
├── config.yaml                 ← pengaturan (edit di sini)
├── exactuswaf.exe              ← program siap jalan (Windows)
├── PANDUAN-SINGKAT.txt         ← panduan super ringkas
├── main.go                     ← kode utama
└── internal/                   ← mesin WAF, aturan, dashboard, dll.
```

---

<div align="center">

Lisensi **MIT** — bebas dipakai, dibagikan, dan dimodifikasi.

Buatlah web Anda lebih aman. 🛡️

</div>
