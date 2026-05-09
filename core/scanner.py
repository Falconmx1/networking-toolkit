import socket
import sys
from datetime import datetime

def port_scanner(target, ports_str):
    print(f"\n🔍 Escaneando {target}")
    print(f"Puertos: {ports_str}\n")
    start_time = datetime.now()

    try:
        ports = [int(p.strip()) for p in ports_str.split(",")]
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("❌ Error: Nombre de host no resuelve")
        return

    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"✅ Puerto {port} abierto")
            open_ports.append(port)
        else:
            print(f"❌ Puerto {port} cerrado")
        sock.close()

    end_time = datetime.now()
    print(f"\n📊 Escaneo completado en {end_time - start_time}")
    print(f"🔓 Puertos abiertos: {open_ports}")

def test():
    print("[TEST] Scanner module loaded")
