
# Advanced Port Scanner (Nmap-Style)

This is a Python-based GUI port scanner built with `tkinter`. It mimics Nmap functionality, offering:

- **TCP Connect Scan**
- **UDP Scan**
- **Service Detection (Banner Grabbing)**
- **OS Fingerprinting (via TTL analysis)**

## 🖥 Features

- Graphical interface with dark theme and real-time progress
- Scan multiple ports with service detection
- Export scan results to a text file
- Optional OS fingerprint guessing
- Supports scanning IPs or hostnames

## 🚀 How to Run

### 1. Requirements

- Python 3.x
- Works cross-platform (Windows/Linux/macOS)

### 2. Run the Scanner

```bash
python advanced_port_scanner.py
```

### 3. Usage

- Enter target IP/hostname
- Provide port range (e.g., 20-100)
- Choose scan type (TCP, UDP, Service Detection)
- Optionally enable OS Fingerprinting
- Click **Start Scan**

## 📤 Exporting Results

After scan completion, click **Export Results** to save output as a `.txt` file.

## 📁 Output Example

```
PORT     STATE    SERVICE         BANNER
20/tcp   closed   -
22/tcp   open     ssh             OpenSSH 7.4
...
```

---

> Developed with 💻 by [Your Name]
