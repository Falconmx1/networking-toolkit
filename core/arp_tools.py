#!/usr/bin/env python3
"""
ARP Spoof Detector - Monitorea la red en busca de ataques MITM
"""
import time
import socket
import threading
from collections import defaultdict
try:
    from scapy.all import ARP, Ether, srp, sniff, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy no instalado. Ejecuta: pip install scapy")

# Base de datos MAC -> IPs
ip_mac_map = {}
attack_log = []

class ARPThreatDetector:
    def __init__(self, interface=None):
        self.interface = interface
        self.running = False
        self.known_hosts = {}
        
    def get_network_range(self):
        """Obtiene el rango de red automáticamente"""
        import netifaces
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        ip_parts = default_gateway[0].split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    def scan_network(self, network_range=None):
        """Escanea la red para construir tabla ARP inicial"""
        if not SCAPY_AVAILABLE:
            print("❌ Scapy no disponible")
            return
        
        if network_range is None:
            network_range = self.get_network_range()
        
        print(f"🔍 Escaneando red: {network_range}")
        
        arp_request = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        
        result = srp(packet, timeout=3, verbose=0, iface=self.interface)[0]
        
        for sent, received in result:
            self.known_hosts[received.psrc] = received.hwsrc
            ip_mac_map[received.psrc] = received.hwsrc
            
        print(f"✅ Encontrados {len(self.known_hosts)} hosts activos")
        return self.known_hosts
    
    def detect_arp_spoof(self, packet):
        """Detecta posibles ataques ARP spoofing"""
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP response
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            if ip in self.known_hosts:
                if self.known_hosts[ip] != mac:
                    threat = {
                        "timestamp": time.time(),
                        "ip": ip,
                        "expected_mac": self.known_hosts[ip],
                        "spoofed_mac": mac,
                        "severity": "HIGH"
                    }
                    attack_log.append(threat)
                    print(f"\n🚨 ¡ALERTA! Posible ARP spoofing detectado")
                    print(f"   IP: {ip}")
                    print(f"   MAC esperada: {self.known_hosts[ip]}")
                    print(f"   MAC maliciosa: {mac}")
                    return True
            else:
                self.known_hosts[ip] = mac
        return False
    
    def start_monitoring(self, duration=60):
        """Inicia monitoreo ARP continuo"""
        if not SCAPY_AVAILABLE:
            print("❌ Scapy no disponible")
            return
        
        self.running = True
        print(f"\n👁️ Monitoreando ARP por {duration} segundos...")
        print("Presiona Ctrl+C para detener\n")
        
        try:
            sniff(iface=self.interface, 
                  filter="arp", 
                  prn=self.detect_arp_spoof, 
                  timeout=duration,
                  store=0)
        except KeyboardInterrupt:
            print("\n⏹️ Monitoreo detenido por usuario")
        
        self.running = False
        self.show_report()
    
    def show_report(self):
        """Muestra reporte de amenazas detectadas"""
        print("\n" + "="*50)
        print("📊 REPORTE DE SEGURIDAD ARP")
        print("="*50)
        
        if attack_log:
            print(f"\n🚨 Amenazas detectadas: {len(attack_log)}")
            for threat in attack_log:
                print(f"\n  🔴 {threat['ip']}")
                print(f"     Esperado: {threat['expected_mac']}")
                print(f"     Suplantado: {threat['spoofed_mac']}")
        else:
            print("\n✅ No se detectaron ataques ARP spoofing")
        
        print(f"\n📡 Hosts en red: {len(self.known_hosts)}")
        for ip, mac in list(self.known_hosts.items())[:10]:
            print(f"   {ip} → {mac}")
    
    def arp_guard(self, target_ip, gateway_ip):
        """Protección activa: envía ARP correctivos"""
        if not SCAPY_AVAILABLE:
            return
        
        print(f"🛡️ Activando ARP Guard contra spoofing...")
        
        def restore_arp():
            while self.running:
                # Enviar ARP correctivos
                packet = ARP(op=2, psrc=gateway_ip, pdst=target_ip, 
                            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.get_my_mac())
                conf.iface = self.interface
                send(packet, verbose=0)
                time.sleep(2)
        
        restore_thread = threading.Thread(target=restore_arp)
        restore_thread.start()
        return restore_thread
    
    def get_my_mac(self):
        """Obtiene MAC de la interfaz actual"""
        import uuid
        return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) 
                        for i in range(0, 48, 8)][::-1])

def test():
    print("[TEST] ARP Tools module loaded")

# CLI directa
if __name__ == "__main__":
    print("🛡️ ARP Spoof Detector")
    print("="*40)
    detector = ARPThreatDetector()
    detector.scan_network()
    detector.start_monitoring(duration=30)
