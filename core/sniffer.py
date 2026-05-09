try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy no instalado. Ejecuta: pip install scapy")

def packet_handler(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
        print(f"📦 {proto} {ip_src} -> {ip_dst}")

def packet_sniffer(interface=None, count=10):
    if not SCAPY_AVAILABLE:
        print("❌ Scapy no disponible. Instálalo y vuelve a intentar.")
        return

    print(f"\n📡 Iniciando sniffer en {interface or 'todas las interfaces'}...")
    print(f"Capturando {count} paquetes...\n")
    sniff(iface=interface, prn=packet_handler, count=count)
    print("\n✅ Captura finalizada")

def test():
    print("[TEST] Sniffer module loaded")
