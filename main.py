#!/usr/bin/env python3
"""
Networking Tool - Full CLI con todos los módulos
"""
import argparse
import sys
from core.ui import NetworkUI
from core.scanner import port_scanner
from core.sniffer import packet_sniffer
from core.arp_tools import ARPThreatDetector
from core.reporter import NetworkReporter
from core.dos import SYNFlood

def main():
    NetworkUI.banner()
    
    parser = argparse.ArgumentParser(
        description="🌐 Networking Tool - Complete Network Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py scan --target 192.168.1.1 --ports 22,80,443
  python main.py sniff --interface eth0 --count 50
  python main.py arp-detect --duration 60
  python main.py report --html
  python main.py dos-syn --target 192.168.1.100 --port 80 --duration 5 --threads 20
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos")
    
    # Scan
    scan_parser = subparsers.add_parser("scan", help="🔍 Escáner de puertos")
    scan_parser.add_argument("--target", required=True)
    scan_parser.add_argument("--ports", default="21,22,23,80,443,445,8080")
    
    # Sniff
    sniff_parser = subparsers.add_parser("sniff", help="📡 Sniffer de paquetes")
    sniff_parser.add_argument("--interface", help="Interfaz (eth0, wlan0)")
    sniff_parser.add_argument("--count", type=int, default=10)
    
    # ARP Detect
    arp_parser = subparsers.add_parser("arp-detect", help="🛡️ Detector de ARP spoofing")
    arp_parser.add_argument("--duration", type=int, default=60, help="Duración monitoreo (segundos)")
    arp_parser.add_argument("--interface", help="Interfaz de red")
    
    # Report
    report_parser = subparsers.add_parser("report", help="📊 Generar reportes")
    report_parser.add_argument("--html", action="store_true", help="Generar HTML")
    report_parser.add_argument("--json", action="store_true", help="Exportar JSON")
    
    # DoS (educativo)
    dos_parser = subparsers.add_parser("dos-syn", help="⚠️ SYN Flood (solo educativo)")
    dos_parser.add_argument("--target", required=True, help="IP objetivo (LAB)")
    dos_parser.add_argument("--port", type=int, default=80, help="Puerto objetivo")
    dos_parser.add_argument("--duration", type=int, default=10, help="Duración (segundos)")
    dos_parser.add_argument("--threads", type=int, default=50, help="Número de threads")
    
    args = parser.parse_args()
    
    # Inicializar reporter
    reporter = NetworkReporter()
    
    if args.command == "scan":
        NetworkUI.info(f"Escaneando {args.target}")
        # Aquí integraremos el scanner
        port_scanner(args.target, args.ports)
        reporter.log_scan(args.target, [], [], "N/A")
        
    elif args.command == "sniff":
        NetworkUI.info(f"Iniciando sniffer en {args.interface or 'auto'}")
        packet_sniffer(args.interface, args.count)
        
    elif args.command == "arp-detect":
        NetworkUI.warning("Iniciando monitoreo ARP (puede requerir sudo)")
        detector = ARPThreatDetector(args.interface)
        detector.scan_network()
        detector.start_monitoring(args.duration)
        
    elif args.command == "report":
        if args.html:
            html_file = reporter.generate_html_report()
            NetworkUI.success(f"Reporte HTML: {html_file}")
        if args.json:
            # Forzar guardado JSON
            reporter._save_json()
            NetworkUI.success("Reporte JSON guardado")
        reporter.print_summary()
        
    elif args.command == "dos-syn":
        NetworkUI.attack(f"Iniciando SYN flood contra {args.target}:{args.port}")
        flooder = SYNFlood(args.target, args.port)
        flooder.flood(duration=args.duration, threads=args.threads)
        
    else:
        parser.print_help()
        NetworkUI.info("\nUsa --help para más información")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        NetworkUI.warning("\nOperación cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        NetworkUI.error(f"Error inesperado: {e}")
        sys.exit(1)
