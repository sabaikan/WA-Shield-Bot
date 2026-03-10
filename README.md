# WA-SHIELD Bot 🛡️

WA-SHIELD adalah asisten keamanan siber otomatis berbasis WhatsApp (WhatsApp Bot) yang mengintegrasikan AI (Gemini 2.5 Flash), pemindaian heuristik lokal, VirusTotal API, dan berbagai tool OSINT untuk melindungi pengguna awam dari ancaman digital sehari-hari.

## 🚀 Fitur Utama

- **Cek Link Berbahaya (Anti-Phishing):** Memindai URL dan tautan pendek untuk mendeteksi ancaman phishing, scam, atau malware menggunakan analisis lokal (resolusi DNS/SSL) dikombinasikan dengan VirusTotal.
- **Cek File & Dokumen (Anti-Malware):** Deteksi instan pada file APK, EXE, PDF, ZIP, dll., untuk menganalisis probabilitas malware melalui `deepScan` lokal dan VirusTotal, dilengkapi ekstraksi SHA-256.
- **Cek Nomor Telepon (Anti-Spam/Penipuan):** Terintegrasi dengan Truecaller dan database komunitas lokal untuk memverifikasi apakah sebuah nomor memiliki riwayat penipuan atau spam.
- **Cek QR Code (Anti-Quishing):** Menggunakan Computer Vision AI untuk memindai gambar QR code guna mengekstrak URL tersembunyi yang berpotensi membahayakan.
- **Smart AI Assistant:** Berinteraksi langsung dengan pengguna menggunakan Google Gemini 2.5 Flash untuk memberi panduan keamanan dengan bahasa awam yang ringkas dan ramah.

## 📱 Demo Bot

Kamu dapat langsung mencoba bot WA-SHIELD secara langsung melalui tautan WhatsApp di bawah ini:
👉 **[Chat dengan WA-SHIELD Bot](https://wa.me/6285177827496?text=Halo%20WA-SHIELD)** 

## ⚙️ Persyaratan Sistem

- Node.js (Versi 18 atau terbaru)
- WhatsApp Web (terhubung ke *whiskeysockets/baileys*)
- Akun API Keys:
  - Gemini API Key
  - VirusTotal API Key
  - Truecaller Data

## 🛠️ Instalasi & Menjalankan Bot

1. Kloning repositori ini (atau unduh source code):
   ```bash
   git clone https://github.com/sabaikan/WA-Shield-Bot.git
   cd WA-Shield-Bot
   ```

2. Instal semua dependensi:
   ```bash
   npm install
   ```

3. Konfigurasi kredensial pada file `.env` (contoh terdapat pada `.env.example`):
   ```env
   GEMINI_API_KEY=your_gemini_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   # Tambahkan variabel lain yang diperlukan
   ```

4. Jalankan bot:
   ```bash
   node index.js
   ```

5. **Pindai QR Code:** Pada saat pertama kali dijalankan, sistem akan memunculkan QR Code di terminal. Pindai menggunakan WhatsApp dari smartphone Anda untuk menautkan bot.

## 📂 Struktur Proyek

- `index.js` - File utama (*entry point*) yang menangani logika koneksi WhatsApp dan interaksi AI.
- `lib/` - Kumpulan modul pemindai (Virustotal, QRScanner, Truecaller, OSINT, dll.)
- `data/` - Penyimpanan database SQLite dan statistik penggunaan bot.

## 📜 Lisensi
ISC License
