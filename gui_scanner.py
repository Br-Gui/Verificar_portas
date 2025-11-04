#!/usr/bin/env python3

import threading
import queue
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox

try:
    from scanner import (
        get_local_ip,
        get_default_gateway,
        scan_port,
        get_service_name,
        DEFAULT_START_PORT,
        DEFAULT_END_PORT,
        MAX_THREADS,
        DEFAULT_TIMEOUT,
    )
except Exception:
    DEFAULT_START_PORT = 1
    DEFAULT_END_PORT = 1025
    MAX_THREADS = 200
    DEFAULT_TIMEOUT = 0.2

    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def get_default_gateway():
        local = get_local_ip()
        if not local:
            return None
        parts = local.split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3]) + '.1'
        return None

    def get_service_name(port):
        try:
            return socket.getservbyport(port, "tcp")
        except Exception:
            return None

    def scan_port(ip, port, timeout=DEFAULT_TIMEOUT):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return (port, True, get_service_name(port))
                return (port, False, None)
        except Exception:
            return (port, False, None)


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner TCP - GUI")
        self.root.geometry("820x560")
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self._build_ui()
        self._periodic_log_check()

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        opt = ttk.LabelFrame(frm, text="Opções de Escaneamento", padding=10)
        opt.pack(fill=tk.X)

        self.target_var = tk.StringVar(value="local")
        ttk.Radiobutton(opt, text="PC local", variable=self.target_var, value="local").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(opt, text="Roteador", variable=self.target_var, value="gw").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(opt, text="Ambos", variable=self.target_var, value="both").grid(row=0, column=2, sticky=tk.W)

        ttk.Label(opt, text="Porta inicial:").grid(row=1, column=0, sticky=tk.W, pady=6)
        self.start_port = tk.IntVar(value=DEFAULT_START_PORT)
        ttk.Entry(opt, textvariable=self.start_port, width=8).grid(row=1, column=1, sticky=tk.W)

        ttk.Label(opt, text="Porta final (exclusive):").grid(row=1, column=2, sticky=tk.W)
        self.end_port = tk.IntVar(value=DEFAULT_END_PORT)
        ttk.Entry(opt, textvariable=self.end_port, width=8).grid(row=1, column=3, sticky=tk.W)

        ttk.Label(opt, text="Máx threads:").grid(row=2, column=0, sticky=tk.W, pady=6)
        self.max_threads = tk.IntVar(value=MAX_THREADS)
        ttk.Entry(opt, textvariable=self.max_threads, width=8).grid(row=2, column=1, sticky=tk.W)

        ttk.Label(opt, text="Timeout (s):").grid(row=2, column=2, sticky=tk.W)
        self.timeout = tk.DoubleVar(value=DEFAULT_TIMEOUT)
        ttk.Entry(opt, textvariable=self.timeout, width=8).grid(row=2, column=3, sticky=tk.W)

        btn_frame = ttk.Frame(opt)
        btn_frame.grid(row=3, column=0, columnspan=4, pady=(8, 0), sticky=tk.W)
        self.start_btn = ttk.Button(btn_frame, text="Iniciar Escaneamento", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.stop_btn = ttk.Button(btn_frame, text="Parar", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        detect_frame = ttk.Frame(opt)
        detect_frame.grid(row=0, column=4, rowspan=3, padx=12)
        ttk.Button(detect_frame, text="Detectar IP local", command=self.detect_local).pack(fill=tk.X)
        ttk.Button(detect_frame, text="Detectar gateway", command=self.detect_gw).pack(fill=tk.X, pady=6)

        log_frame = ttk.LabelFrame(frm, text="Log", padding=8)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.log_text = tk.Text(log_frame, wrap=tk.NONE, state=tk.DISABLED)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ysb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text['yscrollcommand'] = ysb.set

        self.status = tk.StringVar(value="Pronto")
        status_bar = ttk.Label(self.root, textvariable=self.status, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _periodic_log_check(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        self.root.after(200, self._periodic_log_check)

    def _append_log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def detect_local(self):
        ip = get_local_ip()
        if ip:
            messagebox.showinfo("IP local", f"IP detectado: {ip}")
        else:
            messagebox.showwarning("IP local", "Não foi possível detectar IP local")

    def detect_gw(self):
        gw = get_default_gateway()
        if gw:
            messagebox.showinfo("Gateway", f"Gateway detectado: {gw}")
        else:
            messagebox.showwarning("Gateway", "Não foi possível detectar gateway")

    def start_scan(self):
        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            if end <= start:
                messagebox.showerror("Erro", "Intervalo de portas inválido")
                return
        except Exception:
            messagebox.showerror("Erro", "Portas inválidas")
            return

        max_thr = int(self.max_threads.get())
        timeout = float(self.timeout.get())

        sel = self.target_var.get()
        targets = []
        if sel in ("local", "both"):
            targets.append(("PC local", get_local_ip()))
        if sel in ("gw", "both"):
            targets.append(("Roteador", get_default_gateway()))

        if not targets:
            messagebox.showerror("Erro", "Nenhum alvo detectado. Use as opções de detecção ou insira manualmente em scanner.py")
            return

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.stop_event.clear()
        self.status.set("Escaneando...")
        self._log(f"Iniciando escaneamento: {targets}")

        t = threading.Thread(target=self._run_targets, args=(targets, start, end, max_thr, timeout), daemon=True)
        t.start()

    def stop_scan(self):
        self.stop_event.set()
        self._log("Pedido para parar recebido. Aguardando as threads terminarem...")
        self.stop_btn.config(state=tk.DISABLED)

    def _log(self, msg):
        self.log_queue.put(msg)

    def _run_targets(self, targets, start, end, max_workers, timeout):
        try:
            for label, ip in targets:
                if ip is None:
                    self._log(f"IP inválido para {label}. Pulando.")
                    continue

                total_ports = end - start
                self._log(f"Escaneando {label} ({ip}) portas {start}..{end-1} com {max_workers} threads")

                open_ports = []
                ports = range(start, end)
                scanned = 0

                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            break
                        port = futures[future]
                        try:
                            port, is_open, service = future.result()
                            scanned += 1
                            if is_open:
                                svc = f" - {service}" if service else ""
                                self._log(f"[+] {label} {ip} -> Porta {port} aberta{svc}")
                                open_ports.append((port, service))
                        except Exception as e:
                            self._log(f"Erro ao escanear porta {port} em {ip}: {e}")

                        if scanned % 100 == 0 or scanned == total_ports:
                            self._log(f"Progresso {label} {ip}: {scanned}/{total_ports} portas verificadas")

                if open_ports:
                    self._log("\n" + "="*40)
                    self._log(f"Resultados para {label} ({ip}):")
                    for p, svc in sorted(open_ports):
                        svc_text = f" - {svc}" if svc else ""
                        self._log(f"[+] Porta {p} aberta{svc_text}")
                    self._log(f"Total portas abertas: {len(open_ports)}")
                    self._log("="*40 + "\n")
                else:
                    self._log(f"Nenhuma porta aberta encontrada em {label} ({ip}).")

                if self.stop_event.is_set():
                    self._log("Escaneamento interrompido pelo usuário.")
                    break

            self._log("Escaneamento concluído.")
        finally:
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status.set("Pronto")


def main():
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
