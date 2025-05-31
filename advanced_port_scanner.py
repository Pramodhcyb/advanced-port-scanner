import socket
import threading
import platform
import sys
import subprocess
import datetime
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar, Style
from concurrent.futures import ThreadPoolExecutor

# --- Service Detection (Banner Grabbing) ---
def banner_grab(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send generic request for banner
        if port == 80:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            s.sendall(b'\r\n')
        banner = s.recv(1024)
        s.close()
        return banner.decode(errors='ignore').strip()
    except Exception:
        return ""

def get_service(port, proto="tcp"):
    try:
        return socket.getservbyport(port, proto)
    except:
        return "unknown"

# --- OS Fingerprinting (TTL Analysis) ---
def guess_os_by_ttl(ip):
    try:
        if sys.platform.startswith("win"):
            output = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode()
            ttl_line = [line for line in output.splitlines() if "TTL=" in line][0]
            ttl = int(ttl_line.split("TTL=")[-1])
        else:
            output = subprocess.check_output(f"ping -c 1 {ip}", shell=True).decode()
            ttl_line = [line for line in output.splitlines() if "ttl=" in line][0]
            ttl = int(ttl_line.split("ttl=")[-1].split()[0])
        # Guess based on TTL
        if ttl >= 128:
            return "Windows (TTL ~128)"
        elif ttl >= 64:
            return "Linux/Unix (TTL ~64)"
        elif ttl >= 255:
            return "Cisco/Network Device (TTL ~255)"
        else:
            return "Unknown OS"
    except Exception:
        return "Could not determine OS"

class AdvancedPortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap-Style Advanced Port Scanner")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.results = []
        self.scanning = False

        # Style
        style = Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Segoe UI", 11))
        style.configure("TLabel", font=("Segoe UI", 11))
        style.configure("TEntry", font=("Segoe UI", 11))
        style.configure("TProgressbar", thickness=20)

        # GUI Layout
        Label(root, text="Target IP/Hostname:").grid(row=0, column=0, padx=10, pady=10, sticky=W)
        self.target_ip_entry = Entry(root, width=35)
        self.target_ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky=W)

        Label(root, text="Port Range (e.g. 20-80):").grid(row=1, column=0, padx=10, pady=10, sticky=W)
        self.port_range_entry = Entry(root, width=35)
        self.port_range_entry.grid(row=1, column=1, padx=10, pady=10, sticky=W)

        Label(root, text="Scan Type:").grid(row=2, column=0, padx=10, pady=10, sticky=W)
        self.scan_type_var = StringVar(value="TCP Connect")
        scan_types = ["TCP Connect", "UDP", "Service Detection"]
        self.scan_type_menu = OptionMenu(root, self.scan_type_var, *scan_types)
        self.scan_type_menu.grid(row=2, column=1, padx=10, pady=10, sticky=W)

        self.os_fingerprint_var = IntVar()
        self.os_fingerprint_check = Checkbutton(root, text="Enable OS Fingerprinting", variable=self.os_fingerprint_var)
        self.os_fingerprint_check.grid(row=3, column=0, padx=10, pady=10, sticky=W)

        Label(root, text="Timeout (sec):").grid(row=4, column=0, padx=10, pady=10, sticky=W)
        self.timeout_entry = Entry(root, width=10)
        self.timeout_entry.insert(0, "1")
        self.timeout_entry.grid(row=4, column=1, padx=10, pady=10, sticky=W)

        Label(root, text="Output File (optional):").grid(row=5, column=0, padx=10, pady=10, sticky=W)
        self.output_file_entry = Entry(root, width=35)
        self.output_file_entry.grid(row=5, column=1, padx=10, pady=10, sticky=W)

        self.start_button = Button(root, text="Start Scan", command=self.start_scan, bg="#2e8b57", fg="white", font=("Segoe UI", 11, "bold"))
        self.start_button.grid(row=6, column=0, padx=10, pady=10, sticky=W+E)

        self.reset_button = Button(root, text="Reset", command=self.reset_fields, bg="#d9534f", fg="white", font=("Segoe UI", 11, "bold"))
        self.reset_button.grid(row=6, column=1, padx=10, pady=10, sticky=W+E)

        self.export_button = Button(root, text="Export Results", command=self.export_results, bg="#0275d8", fg="white", font=("Segoe UI", 11, "bold"))
        self.export_button.grid(row=6, column=2, padx=10, pady=10, sticky=W+E)

        self.progress = Progressbar(root, orient=HORIZONTAL, length=850, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

        self.result_listbox = Listbox(root, width=130, height=25, font=("Consolas", 10))
        self.result_listbox.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

        self.status_label = Label(root, text="Ready", fg="blue", font=("Segoe UI", 10, "italic"))
        self.status_label.grid(row=9, column=0, columnspan=3, sticky=W, padx=10, pady=5)

    def validate_inputs(self):
        try:
            target = self.target_ip_entry.get().strip()
            if not target:
                raise ValueError("Target IP/Hostname required.")
            socket.gethostbyname(target)
            port_range = self.port_range_entry.get().strip()
            if "-" not in port_range:
                raise ValueError("Port range must be in format start-end (e.g. 20-80)")
            start_port, end_port = map(int, port_range.split("-"))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Invalid port range")
            timeout = float(self.timeout_entry.get())
            if timeout < 0.1 or timeout > 10:
                raise ValueError("Timeout should be between 0.1 and 10 seconds")
            return True
        except Exception as e:
            messagebox.showerror("Input Error", str(e))
            return False

    def reset_fields(self):
        self.target_ip_entry.delete(0, END)
        self.port_range_entry.delete(0, END)
        self.timeout_entry.delete(0, END)
        self.timeout_entry.insert(0, "1")
        self.output_file_entry.delete(0, END)
        self.result_listbox.delete(0, END)
        self.progress['value'] = 0
        self.status_label.config(text="Ready", fg="blue")
        self.results = []

    def export_results(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if file_path:
            with open(file_path, "w") as f:
                for line in self.results:
                    f.write(line + "\n")
            messagebox.showinfo("Export", f"Results exported to {file_path}")

    def update_progress(self, value):
        self.progress['value'] = value
        self.root.update_idletasks()

    def add_result(self, text):
        self.result_listbox.insert(END, text)
        self.result_listbox.yview(END)
        self.results.append(text)

    def scan_tcp_connect(self, host, port, timeout, service_detection=False):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = banner_grab(host, port, timeout=timeout) if service_detection else ""
                service = get_service(port, "tcp")
                line = f"{port:5}/tcp  open     {service:15} {banner if banner else ''}"
                self.add_result(line)
            else:
                line = f"{port:5}/tcp  closed   -"
                self.add_result(line)
            s.close()
        except Exception as e:
            line = f"{port:5}/tcp  error    - {str(e)}"
            self.add_result(line)

    def scan_udp(self, host, port, timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b'', (host, port))
            try:
                data, _ = s.recvfrom(1024)
                service = get_service(port, "udp")
                line = f"{port:5}/udp  open     {service:15} {data.decode(errors='ignore').strip()}"
                self.add_result(line)
            except socket.timeout:
                line = f"{port:5}/udp  open|filtered"
                self.add_result(line)
            s.close()
        except Exception as e:
            line = f"{port:5}/udp  error    - {str(e)}"
            self.add_result(line)

    def start_scan(self):
        if not self.validate_inputs():
            return

        self.result_listbox.delete(0, END)
        self.results = []
        self.progress['value'] = 0
        self.status_label.config(text="Scanning...", fg="orange")
        self.root.update_idletasks()
        self.scanning = True

        target = self.target_ip_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        start_port, end_port = map(int, port_range.split("-"))
        scan_type = self.scan_type_var.get()
        timeout = float(self.timeout_entry.get())
        enable_os_fp = self.os_fingerprint_var.get()

        # Header
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"# Nmap-Style Port Scan Report\n# Target: {target}\n# Scan Type: {scan_type}\n# Date: {now}\n#"
        self.add_result(header)
        self.add_result(f"PORT     STATE    SERVICE         BANNER")
        self.add_result("-"*90)

        total_ports = end_port - start_port + 1
        completed = [0]

        def scan_port(port):
            if scan_type == "TCP Connect":
                self.scan_tcp_connect(target, port, timeout)
            elif scan_type == "UDP":
                self.scan_udp(target, port, timeout)
            elif scan_type == "Service Detection":
                self.scan_tcp_connect(target, port, timeout, service_detection=True)
            completed[0] += 1
            self.update_progress(completed[0] / total_ports * 100)

        def scan_all():
            threads = []
            for port in range(start_port, end_port + 1):
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            if enable_os_fp:
                os_guess = guess_os_by_ttl(target)
                self.add_result("-"*90)
                self.add_result(f"OS Fingerprint Guess: {os_guess}")
            self.status_label.config(text="Scan Complete.", fg="green")
            self.scanning = False

        threading.Thread(target=scan_all).start()

if __name__ == "__main__":
    root = Tk()
    app = AdvancedPortScanner(root)
    root.mainloop()
