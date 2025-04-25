import socket
import threading

# 🔧 Recomendações:
# - Para PCs modernos, usar entre 100 e 500 threads simultâneas é razoável.
# - Para PCs mais modestos, comece com 50 ou menos.
MAX_THREADS = 200  # ajuste
thread_limiter = threading.Semaphore(MAX_THREADS)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Erro ao obter IP local: {e}")
        return "127.0.0.1"

def scan_port(ip, port):
    with thread_limiter:
        print(f"[*] Verificando porta {port}...", end="\r")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Porta {port} está ABERTA")

def scan_ports_local(start_port=1, end_port=1025):
    ip = get_local_ip()
    print(f"Escaneando {ip} de {start_port} até {end_port}...\n")

    threads = []
    for port in range(start_port, end_port):
        t = threading.Thread(target=scan_port, args=(ip, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n[✓] Escaneamento concluído.")

if __name__ == "__main__":
    scan_ports_local()
