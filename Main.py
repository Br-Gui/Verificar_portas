#!/usr/bin/env python3
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import sys

MAX_THREADS = 200
DEFAULT_TIMEOUT = 0.2
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1025
PRINT_LOCK = threading.Lock()

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
    try:
        for iface_info in psutil.net_if_addrs().values():
            for addr in iface_info:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if ip.startswith(("10.", "172.", "192.")):
                        parts = ip.split('.')
                        return '.'.join(parts[:3]) + '.1'
    except Exception:
        pass
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

def pretty_print_open_ports(label, ip, open_ports):
    with PRINT_LOCK:
        print("\n" + "="*40)
        print(f"Resultados para {label} ({ip}):")
        if open_ports:
            for port, service in sorted(open_ports):
                svc = f" - {service}" if service else ""
                print(f"[+] Porta {port} aberta{svc}")
            print(f"\nTotal portas abertas: {len(open_ports)}")
        else:
            print("Nenhuma porta aberta encontrada.")
        print("="*40 + "\n")

def run_scan(label, ip, start_port, end_port, max_workers, timeout):
    if ip is None:
        with PRINT_LOCK:
            print(f"IP inválido para {label}. Pulando.")
        return

    total_ports = end_port - start_port
    with PRINT_LOCK:
        print(f"\nEscaneando {label} ({ip}) de {start_port} até {end_port-1} com {max_workers} threads.\n")

    open_ports = []
    scanned = 0
    scanned_lock = threading.Lock()

    ports = range(start_port, end_port)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                port, is_open, service = future.result()
                if is_open:
                    with PRINT_LOCK:
                        print(f"[+] {label} {ip} -> Porta {port} aberta{' - ' + service if service else ''}")
                    open_ports.append((port, service))
            except Exception as e:
                with PRINT_LOCK:
                    print(f"Erro ao escanear porta {port} em {ip}: {e}")
            with scanned_lock:
                scanned += 1
                if scanned % 100 == 0 or scanned == total_ports:
                    with PRINT_LOCK:
                        print(f"Progresso {label} {ip}: {scanned}/{total_ports} portas verificadas...", end="\r")

    pretty_print_open_ports(label, ip, open_ports)

def input_int(prompt, default):
    try:
        s = input(f"{prompt} [{default}]: ").strip()
        return int(s) if s else int(default)
    except Exception:
        return int(default)

def main():
    print("Scanner TCP - PC local / Roteador / Ambos")
    print("1) Escanear PC local")
    print("2) Escanear Roteador")
    print("3) Escanear PC local e Roteador")
    print("0) Sair")

    choice = input("Escolha uma opção: ").strip()
    if choice not in ("0", "1", "2", "3"):
        print("Opção inválida. Saindo.")
        return
    if choice == "0":
        return

    start_port = input_int("Porta inicial", DEFAULT_START_PORT)
    end_port = input_int("Porta final (exclusive)", DEFAULT_END_PORT)
    if end_port <= start_port:
        print("Intervalo de portas inválido. Saindo.")
        return

    max_threads = input_int("Máximo de threads", MAX_THREADS)
    try:
        t = input(f"Timeout por conexão em segundos [{DEFAULT_TIMEOUT}]: ").strip()
        timeout = float(t) if t else DEFAULT_TIMEOUT
    except Exception:
        timeout = DEFAULT_TIMEOUT

    targets = []
    if choice in ("1", "3"):
        local_ip = get_local_ip()
        if not local_ip:
            manual = input("Não foi possível detectar IP local. Digitar manualmente? (s/N): ").strip().lower()
            if manual == "s":
                local_ip = input("Digite o IP local: ").strip()
        targets.append(("PC local", local_ip))
    if choice in ("2", "3"):
        gw = get_default_gateway()
        if not gw:
            manual = input("Não foi possível detectar gateway. Digitar manualmente? (s/N): ").strip().lower()
            if manual == "s":
                gw = input("Digite o IP do roteador: ").strip()
        targets.append(("Roteador", gw))

    for label, ip in targets:
        run_scan(label, ip, start_port, end_port, max_threads, timeout)

    print("Escaneamento concluído.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário. Saindo.")
        sys.exit(0)
