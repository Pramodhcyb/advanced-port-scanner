
# Advanced Port Scanner (Nmap-Style)

This is a Python-based GUI port scanner built with `tkinter`. It mimics Nmap functionality, offering:

- **TCP Connect Scan**
- **UDP Scan**
- **Service Detection (Banner Grabbing)**
- **OS Fingerprinting (via TTL analysis)**



# 🛡️ Advanced Port Scanner (Nmap-style)

A GUI-based, Python-powered port scanner inspired by Nmap. It supports TCP Connect scans, UDP scans, service detection (banner grabbing), and OS fingerprinting via TTL analysis. Results can be exported, and the interface includes a progress bar and options for timeout and port range control.

---

## ⚙️ Features

- ✅ TCP Connect Scan
- ✅ UDP Port Detection
- ✅ Service/Banner Grabbing
- ✅ OS Fingerprinting (TTL analysis)
- ✅ Export Results to File
- ✅ Clean, Dark-Themed GUI (Tkinter)
- ✅ Multithreaded (fast scans)

---

## 🧰 Requirements

- Python 3.6+
- Tkinter (usually preinstalled)
- Windows, Linux, or macOS

---

## 🏃 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/Pramodhcyb/advanced-port-scanner/tree/main
cd advanced-port-scanner


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
## 🖥 Features

- Graphical interface with dark theme and real-time progress
- Scan multiple ports with service detection
- Export scan results to a text file
- Optional OS fingerprint guessing
- Supports scanning IPs or hostnames
---

> Developed with 💻 by [Your Name]
