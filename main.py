#!/usr/bin/env python3
"""
Networking Tool - Main CLI Entry Point
"""

import argparse
import sys
from core.scanner import port_scanner
from core.sniffer import packet_sniffer

def main():
    parser = argparse.ArgumentParser(
        description="🌐 Networking Tool - Swiss Army knife de red",
        epilog="Ejemplo: python main.py scan --target 192.168.1.1 --ports 22,80,443"
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Subcomando: scan
    scan_parser = subparsers.add_parser("scan", help="Escáner de puertos")
    scan_parser.add_argument("--target", required=True, help="IP o rango (ej: 192.168.1.1)")
    scan_parser.add_argument("--ports", default="21,22,23,80,443,445,8080",
                             help="Puertos separados por coma")

    # Subcomando: sniff
    sniff_parser = subparsers.add_parser("sniff", help="Sniffer de paquetes")
    sniff_parser.add_argument("--interface", help="Interfaz de red (eth0, wlan0, etc)")
    sniff_parser.add_argument("--count", type=int, default=10, help="Número de paquetes a capturar")

    args = parser.parse_args()

    if args.command == "scan":
        port_scanner(args.target, args.ports)
    elif args.command == "sniff":
        packet_sniffer(args.interface, args.count)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
