import socket
import threading
import psutil

# Recomendações:
# - Entre 100 e 500 threads para PCs rápidos.
# - 50 ou menos para evitar sobrecarga em máquinas mais fracas.
MAX_THREADS = 200 # ajuste
thread_limiter = threading.Semaphore(MAX_THREADS)

def get_default_gateway():
    for iface_info in psutil.net_if_addrs().values():
        for addr in iface_info:
            if addr.family == socket.AF_INET and addr.address.startswith(("192.", "10.", "172.")):
                ip_parts = addr.address.split('.')
                return '.'.join(ip_parts[:3]) + '.1'
    return None

def scan_port(ip, port):
    with thread_limiter:
        print(f"[*] Verificando porta {port}...", end="\r")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Porta {port} está ABERTA")

def scan_ports_router(start_port=1, end_port=1025):
    router_ip = get_default_gateway()
    if not router_ip:
        print("❌ Não foi possível detectar o IP do roteador.")
        return

    print(f"Escaneando roteador em {router_ip} de {start_port} até {end_port}...\n")

    threads = []
    for port in range(start_port, end_port):
        t = threading.Thread(target=scan_port, args=(router_ip, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n[✓] Escaneamento concluído.")

if __name__ == "__main__":
    scan_ports_router()
