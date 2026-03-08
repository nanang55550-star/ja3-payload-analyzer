# 🛡️ JA3 Payload Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![JA3 Integration](https://img.shields.io/badge/JA3-Ready-brightgreen)](https://github.com/nanang55550-star/JA3-Baseline-Detection-System)

**Advanced Payload Analysis untuk JA3 Detection System**

Mendeteksi anomali berdasarkan kombinasi JA3 fingerprint + isi payload.  
Cocok buat nangkep serangan kayak COBOL injection, SQLi, dan legacy attacks.

---

## 📋 **Daftar Isi**
- [Fitur](#-fitur)
- [Quick Start](#-quick-start)
- [Instalasi Detail](#-instalasi-detail)
  - [Di Termux](#di-termux)
  - [Di Linux/Ubuntu](#di-linuxubuntu)
  - [Di Windows (WSL)](#di-windows-wsl)
- [Konfigurasi](#-konfigurasi)
- [Cara Pakai](#-cara-pakai)
- [Integrasi dengan JA3](#-integrasi-dengan-ja3-detection)
- [Troubleshooting](#-troubleshooting)
- [Struktur Repository](#-struktur-repository)
- [Dokumentasi](#-dokumentasi)
- [Lisensi](#-lisensi)
- [Kontak](#-kontak)

---

## ✨ **Fitur Utama**

| Fitur | Deskripsi | File Terkait |
|-------|-----------|--------------|
| 🔍 **Payload Signature Detection** | Deteksi pola COBOL, SQL Injection, dan legacy attacks | [`signatures/cobol_patterns.txt`](signatures/cobol_patterns.txt) |
| 🔗 **JA3 Correlation** | Cocokkan fingerprint TLS dengan isi payload | [`core/analyzer.py`](core/analyzer.py) |
| 📊 **Real-time Alert** | Notifikasi ketika ada anomali terdeteksi | [`core/utils.py`](core/utils.py) |
| 🧪 **Test Suite** | Simulasi berbagai serangan untuk uji sistem | [`tests/test_analyzer.py`](tests/test_analyzer.py) |
| 📈 **Risk Scoring** | Penilaian risiko otomatis (LOW, HIGH, CRITICAL) | [`core/analyzer.py`](core/analyzer.py) |

---

## 🚀 **Quick Start**

```bash
# Clone repository
git clone https://github.com/nanang55550-star/ja3-payload-analyzer.git
cd ja3-payload-analyzer

# Install dependencies
pip install -r requirements.txt

# Jalankan analyzer
python core/analyzer.py
```

📖 **Baca selengkapnya:** [Dokumentasi Instalasi](docs/installation.md)

---

## 📦 **Instalasi Detail**

### **Di Termux**
```bash
# Update Termux
pkg update && pkg upgrade -y

# Install Python
pkg install python -y

# Install dependencies
pip install requests rich

# Clone repository
git clone https://github.com/nanang55550-star/ja3-payload-analyzer.git
cd ja3-payload-analyzer

# Jalankan
python core/analyzer.py
```

### **Di Linux/Ubuntu**
```bash
# Update system
sudo apt update

# Install Python dan pip
sudo apt install python3 python3-pip -y

# Install dependencies
pip3 install requests rich

# Clone repository
git clone https://github.com/nanang55550-star/ja3-payload-analyzer.git
cd ja3-payload-analyzer

# Jalankan
python3 core/analyzer.py
```

### **Di Windows (WSL)**
```bash
# Install WSL dulu dari Microsoft Store
# Buka WSL (Ubuntu), lalu ikuti langkah Linux di atas
```

📖 **Lihat file:** [`docs/installation.md`](docs/installation.md)

---

## ⚙️ **Konfigurasi**

### **File Konfigurasi**
```python
# core/analyzer.py - Sesuaikan threshold di sini
RISK_THRESHOLDS = {
    'LOW': 0,
    'MEDIUM': 20,
    'HIGH': 40,
    'CRITICAL': 70
}
```

### **Signature Patterns**
Edit file signature untuk menambah pola deteksi:
- 📄 [`signatures/cobol_patterns.txt`](signatures/cobol_patterns.txt) - Pola serangan COBOL
- 📄 [`signatures/sql_patterns.txt`](signatures/sql_patterns.txt) - Pola SQL injection
- 📄 [`signatures/legacy_patterns.txt`](signatures/legacy_patterns.txt) - Pola legacy attacks

📖 **Panduan lengkap:** [`docs/configuration.md`](docs/configuration.md)

---

## 🎯 **Cara Pakai**

### **Basic Usage**
```python
from core.analyzer import PayloadAnalyzer

# Buat instance analyzer
analyzer = PayloadAnalyzer()

# Analisis payload
result = analyzer.analyze("SELECT * FROM users", ja3_hash="cd08e314...")

print(f"Risk Level: {result['risk_level']}")
print(f"Recommendation: {result['recommendation']}")
```

### **Advanced Usage**
```python
# Tambah pattern kustom
analyzer.add_custom_pattern('cobol', 'CUSTOM-PATTERN')

# Lihat statistik
stats = analyzer.get_stats()
print(f"Total patterns: {stats['total_patterns']}")
```

📖 **Contoh lengkap:** [`examples/sample_attack.py`](examples/sample_attack.py)

---

## 🔗 **Integrasi dengan JA3 Detection System**

### **Integrasi Langsung**
```python
from core.analyzer import PayloadAnalyzer
import requests

analyzer = PayloadAnalyzer()

def check_request(payload, ja3_hash, ip_address):
    """Fungsi untuk mengecek request mencurigakan"""
    
    # Analisis payload
    result = analyzer.analyze(payload, ja3_hash)
    
    # Jika critical, block IP
    if result['risk_level'] == 'CRITICAL':
        requests.post("http://localhost:5000/block", 
                     json={"ip": ip_address})
        return "BLOCKED"
    
    # Jika high, log dan review
    elif result['risk_level'] == 'HIGH':
        return "REVIEW"
    
    return "ALLOW"
```

### **Webhook Integration**
```python
# Kirim alert ke sistem lain
from core.utils import format_alert

alert = format_alert(result)
requests.post("https://your-webhook.com/alert", 
              json={"message": alert})
```

📖 **Lihat file:** [`examples/ja3_integration.py`](examples/ja3_integration.py)

---

## 🔧 **Troubleshooting**

### **Error: "Module not found"**
```bash
# Install semua dependencies
pip install -r requirements.txt
```

### **Error: "No signatures loaded"**
```bash
# Pastikan folder signatures ada dan berisi file
ls signatures/
# Harus ada: cobol_patterns.txt sql_patterns.txt legacy_patterns.txt
```

### **Error: "Permission denied" di Termux**
```bash
# Beri izin storage
termux-setup-storage
```

### **Hasil analisis selalu LOW**
```bash
# Cek apakah patterns sudah sesuai
# Tambah pattern baru di file signatures/
```

📖 **Solusi lengkap:** [`docs/troubleshooting.md`](docs/troubleshooting.md)

---

## 📁 **Struktur Repository**

```
ja3-payload-analyzer/
├── 📄 [README.md](README.md)              # Dokumentasi utama (file ini)
├── 📄 [LICENSE](LICENSE)                  # Lisensi MIT
├── 📄 [requirements.txt](requirements.txt) # Dependencies Python
├── 📁 [core/](core/)
│   ├── 📄 [__init__.py](core/__init__.py) # Module initializer
│   ├── 📄 [analyzer.py](core/analyzer.py) # Engine utama analisis
│   └── 📄 [utils.py](core/utils.py)       # Fungsi bantuan
├── 📁 [signatures/](signatures/)
│   ├── 📄 [cobol_patterns.txt](signatures/cobol_patterns.txt) # Pola COBOL
│   ├── 📄 [sql_patterns.txt](signatures/sql_patterns.txt)     # Pola SQL
│   └── 📄 [legacy_patterns.txt](signatures/legacy_patterns.txt) # Pola legacy
├── 📁 [tests/](tests/)
│   └── 📄 [test_analyzer.py](tests/test_analyzer.py) # Unit testing
├── 📁 [examples/](examples/)
│   ├── 📄 [sample_attack.py](examples/sample_attack.py)     # Contoh serangan
│   └── 📄 [ja3_integration.py](examples/ja3_integration.py) # Integrasi JA3
└── 📁 [docs/](docs/)
    ├── 📄 [installation.md](docs/installation.md)   # Panduan instalasi
    ├── 📄 [configuration.md](docs/configuration.md) # Panduan konfigurasi
    └── 📄 [troubleshooting.md](docs/troubleshooting.md) # Solusi masalah
```

---

## 📚 **Dokumentasi**

| Dokumen | Deskripsi | Link |
|---------|-----------|------|
| **Panduan Instalasi** | Instalasi di berbagai platform | [`docs/installation.md`](docs/installation.md) |
| **Panduan Konfigurasi** | Setting threshold dan patterns | [`docs/configuration.md`](docs/configuration.md) |
| **Panduan Troubleshooting** | Solusi masalah umum | [`docs/troubleshooting.md`](docs/troubleshooting.md) |
| **API Reference** | Dokumentasi fungsi | [`docs/api-reference.md`](docs/api-reference.md) |
| **Contoh Kode** | Sample implementations | [`examples/`](examples/) |

---

## 🧪 **Testing**

```bash
# Jalankan unit tests
python -m pytest tests/ -v

# Test dengan sample attack
python examples/sample_attack.py

# Test integrasi JA3
python examples/ja3_integration.py
```

📖 **Lihat file:** [`tests/test_analyzer.py`](tests/test_analyzer.py)

---

## 📜 **Lisensi**

Proyek ini dilisensikan di bawah **MIT License** - lihat file [`LICENSE`](LICENSE) untuk detail.

---

## 📬 **Kontak**

**Creator:** [@nanang55550-star](https://github.com/nanang55550-star)

- GitHub: [nanang55550-star](https://github.com/nanang55550-star)
- Discord: [YRYwwEc8](https://discord.gg/YRYwwEc8)
- Email: [nanang55550@gmail.com](mailto:nanang55550@gmail.com)

Untuk laporan bug, silakan buat [issue baru](https://github.com/nanang55550-star/ja3-payload-analyzer/issues).

---

## ⭐ **Dukung Proyek Ini**

Jika bermanfaat, jangan lupa kasih ⭐ di [GitHub](https://github.com/nanang55550-star/ja3-payload-analyzer)!

[![GitHub stars](https://img.shields.io/github/stars/nanang55550-star/ja3-payload-analyzer?style=social)](https://github.com/nanang55550-star/ja3-payload-analyzer/stargazers)

---

**🔥 Happy Analyzing! 🔥**
