#!/usr/bin/env python3
"""
Networking Tool - Complete Network Toolkit
Versión: 2.0 - Con Shodan + Vulnerability Scanner + ARP Detection + DoS
"""
import argparse
import sys
import os
from datetime import datetime
from core.ui import NetworkUI
from core.scanner import port_scanner
from core.sniffer import packet_sniffer
from core.arp_tools import ARPThreatDetector
from core.reporter import NetworkReporter
from core.dos import SYNFlood
from core.vuln_scanner import VulnerabilityScanner
from core.shodan_integration import ShodanScanner

# Cargar variables de entorno para API keys
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def main():
    NetworkUI.clear_screen()
    NetworkUI.banner()
    
    parser = argparse.ArgumentParser(
        description="🌐 Networking Tool - Complete Network Toolkit for Pentesters & Admins",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════════════╗
║ 📌 EJEMPLOS DE USO:                                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  🔍 ESCANEO DE PUERTOS:                                              ║
║     python main.py scan --target 192.168.1.1 --ports 22,80,443       ║
║                                                                      ║
║  📡 SNIFFER DE PAQUETES:                                             ║
║     sudo python main.py sniff --interface eth0 --count 50            ║
║                                                                      ║
║  🛡️ DETECTOR ARP SPOOFING:                                           ║
║     sudo python main.py arp-detect --duration 120                    ║
║                                                                      ║
║  🔐 ESCÁNER DE VULNERABILIDADES:                                     ║
║     python main.py vuln-scan --target 192.168.1.100                  ║
║                                                                      ║
║  🌐 SHODAN INTELIGENCE:                                              ║
║     export SHODAN_API_KEY="tu_key"                                   ║
║     python main.py shodan host --ip 8.8.8.8                          ║
║     python main.py shodan search --query "apache country:MX"         ║
║                                                                      ║
║  📊 REPORTES:                                                        ║
║     python main.py report --html                                     ║
║                                                                      ║
║  ⚠️ DoS EDUCATIVO (SOLO LABORATORIO):                                ║
║     python main.py dos-syn --target 192.168.1.100 --duration 5       ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """
    )
    
    # ==================== SUBPARSERS ====================
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")
    
    # 1. Escáner de puertos
    scan_parser = subparsers.add_parser("scan", help="🔍 Escáner de puertos multi-hilo")
    scan_parser.add_argument("--target", required=True, help="IP o dominio (ej: 192.168.1.1)")
    scan_parser.add_argument("--ports", default="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017",
                             help="Puertos separados por coma (default: top 25)")
    scan_parser.add_argument("--timeout", type=float, default=0.5, help="Timeout en segundos (default: 0.5)")
    scan_parser.add_argument("--threads", type=int, default=50, help="Número de hilos (default: 50)")
    
    # 2. Sniffer de paquetes
    sniff_parser = subparsers.add_parser("sniff", help="📡 Sniffer de paquetes en tiempo real")
    sniff_parser.add_argument("--interface", help="Interfaz de red (eth0, wlan0, etc)")
    sniff_parser.add_argument("--count", type=int, default=20, help="Número de paquetes a capturar")
    sniff_parser.add_argument("--filter", default="", help="Filtro BPF (ej: 'tcp port 80')")
    
    # 3. Detector de ARP spoofing
    arp_parser = subparsers.add_parser("arp-detect", help="🛡️ Detector de ataques ARP spoofing")
    arp_parser.add_argument("--duration", type=int, default=60, help="Duración del monitoreo en segundos")
    arp_parser.add_argument("--interface", help="Interfaz de red")
    arp_parser.add_argument("--scan", action="store_true", help="Escanea la red antes de monitorear")
    
    # 4. Escáner de vulnerabilidades
    vuln_parser = subparsers.add_parser("vuln-scan", help="🔐 Escáner de vulnerabilidades (CVE, SSL, Headers)")
    vuln_parser.add_argument("--target", required=True, help="IP objetivo")
    vuln_parser.add_argument("--ports", help="Puertos a analizar (separados por coma)")
    vuln_parser.add_argument("--ssl", action="store_true", help="Verificar SSL/TLS")
    vuln_parser.add_argument("--http", action="store_true", help="Verificar headers HTTP")
    
    # 5. Shodan Integration
    shodan_parser = subparsers.add_parser("shodan", help="🌐 Shodan intelligence gathering")
    shodan_subparsers = shodan_parser.add_subparsers(dest="shodan_command", help="Comandos Shodan")
    
    # Shodan: Buscar host por IP
    shodan_host = shodan_subparsers.add_parser("host", help="Obtener información de una IP")
    shodan_host.add_argument("--ip", required=True, help="Dirección IP")
    shodan_host.add_argument("--history", action="store_true", help="Ver historial")
    
    # Shodan: Búsqueda por query
    shodan_query = shodan_subparsers.add_parser("search", help="Buscar equipos por query")
    shodan_query.add_argument("--query", required=True, help="Query de búsqueda (ej: apache country:US)")
    shodan_query.add_argument("--limit", type=int, default=10, help="Límite de resultados")
    
    # Shodan: Dispositivos expuestos
    shodan_exposed = shodan_subparsers.add_parser("exposed", help="Buscar dispositivos expuestos comunes")
    shodan_exposed.add_argument("--type", choices=["camera", "router", "database", "industrial", "raspberry_pi", "printer"], 
                                default="camera", help="Tipo de dispositivo")
    shodan_exposed.add_argument("--limit", type=int, default=15, help="Límite de resultados")
    
    # Shodan: Estadísticas
    shodan_stats = shodan_subparsers.add_parser("stats", help="Estadísticas de búsqueda")
    shodan_stats.add_argument("--query", required=True, help="Query para estadísticas")
    shodan_stats.add_argument("--facet", default="country", help="Faceta (country, port, org)")
    
    # 6. Reportes
    report_parser = subparsers.add_parser("report", help="📊 Generar reportes de actividad")
    report_parser.add_argument("--html", action="store_true", help="Generar reporte HTML")
    report_parser.add_argument("--json", action="store_true", help="Exportar a JSON")
    report_parser.add_argument("--csv", action="store_true", help="Exportar a CSV")
    report_parser.add_argument("--all", action="store_true", help="Generar todos los formatos")
    
    # 7. DoS Educativo
    dos_parser = subparsers.add_parser("dos-syn", help="⚠️ SYN Flood EDUCATIVO (solo laboratorio propio)")
    dos_parser.add_argument("--target", required=True, help="IP objetivo (SOLO LAB)")
    dos_parser.add_argument("--port", type=int, default=80, help="Puerto objetivo")
    dos_parser.add_argument("--duration", type=int, default=10, help="Duración en segundos")
    dos_parser.add_argument("--threads", type=int, default=50, help="Número de hilos")
    dos_parser.add_argument("--slow", action="store_true", help="Slow DoS (Slowloris style)")
    
    # 8. Información del sistema
    info_parser = subparsers.add_parser("info", help="ℹ️ Mostrar información del sistema y red")
    
    # 9. Utilidades extras
    utils_parser = subparsers.add_parser("utils", help="🔧 Utilidades varias")
    utils_subparsers = utils_parser.add_subparsers(dest="utils_command")
    
    # GeoIP lookup
    geoip = utils_subparsers.add_parser("geoip", help="Geolocalizar IP")
    geoip.add_argument("--ip", required=True, help="Dirección IP")
    
    # Ping sweep
    pingsweep = utils_subparsers.add_parser("pingsweep", help="Escaneo ICMP de red")
    pingsweep.add_argument("--network", required=True, help="Rango (ej: 192.168.1.0/24)")
    
    # DNS lookup
    dns_lookup = utils_subparsers.add_parser("dns", help="Consulta DNS")
    dns_lookup.add_argument("--domain", required=True, help="Dominio a consultar")
    dns_lookup.add_argument("--type", default="A", choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME"], help="Tipo de registro")
    
    # ==================== EJECUCIÓN DE COMANDOS ====================
    args = parser.parse_args()
    
    # Inicializar reporter
    reporter = NetworkReporter()
    
    # Comando: scan
    if args.command == "scan":
        NetworkUI.info(f"Iniciando escaneo de puertos a {args.target}")
        NetworkUI.info(f"Puertos: {args.ports}")
        try:
            from core.scanner import quick_scan
            open_ports = port_scanner(args.target, args.ports)
            reporter.log_scan(args.target, open_ports, [], "N/A")
            NetworkUI.success(f"Escaneo completado. Puertos abiertos: {len(open_ports)}")
        except Exception as e:
            NetworkUI.error(f"Error en escaneo: {e}")
    
    # Comando: sniff
    elif args.command == "sniff":
        if os.geteuid() != 0:
            NetworkUI.warning("Sniffer puede requerir permisos de root/administrador")
        NetworkUI.info(f"Iniciando sniffer en {args.interface or 'interfaz por defecto'}")
        packet_sniffer(args.interface, args.count, args.filter)
    
    # Comando: arp-detect
    elif args.command == "arp-detect":
        if os.geteuid() != 0:
            NetworkUI.error("ARP detection requiere permisos de root/administrador")
            NetworkUI.info("Ejecuta: sudo python main.py arp-detect --duration 60")
            sys.exit(1)
        
        NetworkUI.warning("Iniciando monitoreo ARP para detección de spoofing")
        detector = ARPThreatDetector(args.interface)
        
        if args.scan:
            detector.scan_network()
        
        detector.start_monitoring(args.duration)
        
        # Registrar amenazas en reporter
        if hasattr(detector, 'attack_log') and detector.attack_log:
            for attack in detector.attack_log:
                reporter.log_attack("ARP_Spoofing", attack.get("ip", "unknown"), attack)
    
    # Comando: vuln-scan
    elif args.command == "vuln-scan":
        NetworkUI.info(f"Iniciando análisis de vulnerabilidades en {args.target}")
        
        # Determinar puertos a escanear
        if args.ports:
            open_ports = [int(p.strip()) for p in args.ports.split(",")]
        else:
            # Escaneo rápido de puertos comunes
            NetworkUI.loading_animation("Escaneando puertos comunes", 3)
            from core.scanner import quick_scan
            open_ports = quick_scan(args.target)
        
        scanner = VulnerabilityScanner(args.target)
        vulnerabilities = scanner.scan_all(open_ports)
        
        # Registrar en reporter
        for vuln in vulnerabilities:
            reporter.log_attack("Vulnerability", args.target, vuln)
        
        NetworkUI.success(f"Análisis completado. {len(vulnerabilities)} vulnerabilidades encontradas")
        scanner.export_json()
    
    # Comando: shodan
    elif args.command == "shodan":
        shodan_key = os.getenv("SHODAN_API_KEY") or os.getenv("SHODAN_KEY")
        
        if not shodan_key:
            NetworkUI.error("SHODAN_API_KEY no configurada")
            NetworkUI.info("Configuración:")
            NetworkUI.info("  export SHODAN_API_KEY='tu_api_key_aqui'")
            NetworkUI.info("  O crea un archivo .env con: SHODAN_API_KEY=tu_key")
            sys.exit(1)
        
        shodan_scanner = ShodanScanner(shodan_key)
        
        if not shodan_scanner.api:
            NetworkUI.error("Error conectando a Shodan API")
            sys.exit(1)
        
        if args.shodan_command == "host":
            NetworkUI.info(f"Consultando Shodan para IP: {args.ip}")
            result = shodan_scanner.search_host(args.ip, history=args.history)
            if result:
                reporter.log_attack("Shodan_Query", args.ip, {"type": "host_lookup", "data": result})
                shodan_scanner.export_results()
        
        elif args.shodan_command == "search":
            NetworkUI.info(f"Búsqueda Shodan: {args.query}")
            results = shodan_scanner.search_query(args.query, args.limit)
            if results:
                reporter.log_attack("Shodan_Search", args.query, {"results_count": len(results)})
                shodan_scanner.export_results()
        
        elif args.shodan_command == "exposed":
            NetworkUI.info(f"Buscando {args.type} expuestos...")
            results = shodan_scanner.find_exposed_devices(args.type, args.limit)
            if results:
                shodan_scanner.export_results()
        
        elif args.shodan_command == "stats":
            NetworkUI.info(f"Obteniendo estadísticas para: {args.query}")
            stats = shodan_scanner.get_stats(args.query, args.facet)
            if stats:
                print("\n📊 Estadísticas:")
                print(json.dumps(stats, indent=2))
        
        else:
            shodan_parser.print_help()
    
    # Comando: report
    elif args.command == "report":
        NetworkUI.info("Generando reportes...")
        
        if args.html or args.all:
            html_file = reporter.generate_html_report()
            NetworkUI.success(f"Reporte HTML: {html_file}")
        
        if args.json or args.all:
            json_file = reporter._save_json()
            NetworkUI.success(f"Reporte JSON: {json_file}")
        
        if args.csv or args.all:
            csv_file = reporter._save_csv()
            NetworkUI.success(f"Reporte CSV: {csv_file}")
        
        reporter.print_summary()
    
    # Comando: dos-syn
    elif args.command == "dos-syn":
        NetworkUI.attack("⚠️ MODO EDUCATIVO - SOLO LABORATORIO ⚠️")
        
        if args.slow:
            flooder = SYNFlood(args.target, args.port)
            flooder.slow_dos(args.target, connections=200)
        else:
            flooder = SYNFlood(args.target, args.port)
            flooder.flood(duration=args.duration, threads=args.threads)
        
        reporter.log_attack("DoS_Educativo", args.target, {
            "type": "SYN_Flood",
            "duration": args.duration,
            "threads": args.threads
        })
    
    # Comando: info
    elif args.command == "info":
        import platform
        import socket
        
        print("\n" + "="*50)
        print("💻 INFORMACIÓN DEL SISTEMA")
        print("="*50)
        print(f"Sistema: {platform.system()} {platform.release()}")
        print(f"Hostname: {socket.gethostname()}")
        print(f"Python: {platform.python_version()}")
        
        # Obtener IP local
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            print(f"IP Local: {local_ip}")
        except:
            print("IP Local: No detectable")
        
        print(f"Usuario: {os.getenv('USER') or os.getenv('USERNAME')}")
        
        # Verificar API keys
        print("\n🔑 Configuración:")
        if os.getenv("SHODAN_API_KEY"):
            print("  ✅ Shodan API: Configurada")
        else:
            print("  ❌ Shodan API: No configurada (export SHODAN_API_KEY)")
    
    # Comando: utils
    elif args.command == "utils":
        import requests
        import subprocess
        
        if args.utils_command == "geoip":
            NetworkUI.info(f"Geolocalizando IP: {args.ip}")
            try:
                response = requests.get(f"http://ip-api.com/json/{args.ip}")
                data = response.json()
                if data.get('status') == 'success':
                    print(f"\n📍 Geolocalización de {args.ip}")
                    print(f"  🌍 País: {data.get('country')}")
                    print(f"  🏙️ Ciudad: {data.get('city')}")
                    print(f"  📡 ISP: {data.get('isp')}")
                    print(f"  🗺️ Coordenadas: {data.get('lat')}, {data.get('lon')}")
                else:
                    NetworkUI.error("No se pudo geolocalizar")
            except Exception as e:
                NetworkUI.error(f"Error: {e}")
        
        elif args.utils_command == "pingsweep":
            NetworkUI.info(f"Escaneando red: {args.network}")
            NetworkUI.warning("Requiere permisos")
            # Implementar ping sweep básico
            network_prefix = args.network.rsplit('.', 1)[0]
            print(f"\n📡 Hosts activos en {args.network}:")
            for i in range(1, 255):
                ip = f"{network_prefix}.{i}"
                response = subprocess.call(['ping', '-c', '1', '-W', '1', ip], 
                                          stdout=subprocess.DEVNULL, 
                                          stderr=subprocess.DEVNULL)
                if response == 0:
                    print(f"  ✅ {ip}")
        
        elif args.utils_command == "dns":
            NetworkUI.info(f"Consulta DNS: {args.domain} ({args.type})")
            try:
                import dns.resolver
                answers = dns.resolver.resolve(args.domain, args.type)
                print(f"\n📋 Registros {args.type} para {args.domain}:")
                for answer in answers:
                    print(f"  📌 {answer}")
            except ImportError:
                NetworkUI.warning("Instala dnspython: pip install dnspython")
                # Fallback a socket
                try:
                    ip = socket.gethostbyname(args.domain)
                    print(f"  📌 {ip}")
                except:
                    NetworkUI.error("No se pudo resolver")
            except Exception as e:
                NetworkUI.error(f"Error DNS: {e}")
        
        else:
            utils_parser.print_help()
    
    # Comando: help por defecto
    else:
        parser.print_help()
        NetworkUI.info("\n💡 Usa --help para más información sobre cada comando")
        NetworkUI.info("📌 Ejemplo rápido: python main.py scan --target google.com")

# ==================== PUNTO DE ENTRADA ====================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        NetworkUI.warning("\n\n⏹️ Operación cancelada por el usuario")
        sys.exit(0)
    except PermissionError as e:
        NetworkUI.error(f"Permisos insuficientes: {e}")
        NetworkUI.info("Algunos comandos requieren sudo/administrador")
        sys.exit(1)
    except Exception as e:
        NetworkUI.error(f"Error inesperado: {e}")
        NetworkUI.info("Revisa los requisitos y dependencias")
        sys.exit(1)
