#!/usr/bin/env python3
"""
Shodan Integration - Búsqueda de equipos y vulnerabilidades
Necesitas API key: https://account.shodan.io/register
"""
import json
import os
from datetime import datetime

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    print("⚠️ Instalar shodan: pip install shodan")

class ShodanScanner:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.api = None
        self.results = []
        
        if not self.api_key:
            print("❌ No SHODAN_API_KEY encontrada")
            print("💡 Obtén una key en: https://account.shodan.io/register")
            print("📌 Configura: export SHODAN_API_KEY='tu_key'")
            return
        
        if SHODAN_AVAILABLE:
            self.api = shodan.Shodan(self.api_key)
            print("✅ Shodan API conectada")
    
    def search_host(self, ip):
        """Busca información detallada de un host"""
        if not self.api:
            print("❌ Shodan no inicializado")
            return None
        
        try:
            print(f"🔍 Consultando Shodan para: {ip}")
            host = self.api.host(ip)
            
            info = {
                "ip": host['ip_str'],
                "organization": host.get('org', 'N/A'),
                "country": host.get('country_name', 'N/A'),
                "os": host.get('os', 'N/A'),
                "ports": host.get('ports', []),
                "vulnerabilities": host.get('vulns', []),
                "hostnames": host.get('hostnames', []),
                "last_update": host.get('last_update', 'N/A')
            }
            
            print(f"\n📡 Información del host:")
            print(f"  🏢 Organización: {info['organization']}")
            print(f"  🌍 País: {info['country']}")
            print(f"  💻 OS: {info['os']}")
            print(f"  🔌 Puertos abiertos: {', '.join(map(str, info['ports'][:10]))}")
            
            # Mostrar vulnerabilidades conocidas
            if info['vulnerabilities']:
                print(f"\n🚨 Vulnerabilidades conocidas ({len(info['vulnerabilities'])}):")
                for vuln in info['vulnerabilities'][:5]:
                    print(f"  🔴 {vuln}")
                    self.get_cve_details(vuln)
            else:
                print("  ✅ No se encontraron CVEs conocidos")
            
            self.results.append(info)
            return info
            
        except shodan.APIError as e:
            print(f"❌ Error Shodan: {e}")
            return None
    
    def search_query(self, query, limit=10):
        """Busca equipos por query (ej: 'apache', 'port:22 country:MX')"""
        if not self.api:
            print("❌ Shodan no inicializado")
            return []
        
        try:
            print(f"🔎 Buscando: '{query}' (límite: {limit})")
            results = self.api.search(query, limit=limit)
            
            print(f"\n📊 Encontrados: {results['total']} resultados")
            print("="*60)
            
            for i, result in enumerate(results['matches'][:limit], 1):
                host_info = {
                    "ip": result['ip_str'],
                    "port": result['port'],
                    "service": result.get('product', 'unknown'),
                    "country": result.get('location', {}).get('country_name', 'N/A'),
                    "banner": result.get('data', '')[:100]
                }
                
                print(f"\n{i}. {host_info['ip']}:{host_info['port']}")
                print(f"   📡 Servicio: {host_info['service']}")
                print(f"   🌍 País: {host_info['country']}")
                print(f"   📝 Banner: {host_info['banner']}...")
                
                self.results.append(host_info)
            
            return self.results
            
        except shodan.APIError as e:
            print(f"❌ Error Shodan: {e}")
            return []
    
    def get_cve_details(self, cve_id):
        """Obtiene detalles específicos de un CVE desde Shodan"""
        if not self.api:
            return None
        
        try:
            # Nota: Shodan no tiene endpoint directo para CVEs
            # Esta es una simulación, para producción usar NVD API
            print(f"    📝 Buscando detalles de {cve_id}...")
            
            # Simular detalles (en realidad deberías usar NVD API)
            cve_info = {
                "id": cve_id,
                "description": "Vulnerabilidad reportada en Shodan",
                "severity": "HIGH"
            }
            
            return cve_info
            
        except Exception as e:
            print(f"    ⚠️ No se pudieron obtener detalles: {e}")
            return None
    
    def scan_network_range(self, network, limit=50):
        """Escanea un rango de red (ej: '192.168.1.0/24')"""
        if not self.api:
            return []
        
        # Shodan no soporta escaneo de rangos arbitrarios directamente
        # Usamos search con la red como filtro
        return self.search_query(f"net:{network}", limit)
    
    def find_exposed_devices(self, device_type="camera", limit=20):
        """Busca dispositivos expuestos comunes"""
        queries = {
            "camera": 'webcam "Network Camera"',
            "router": 'Router "default password"',
            "database": 'MySQL port:3306',
            "industrial": 'Modbus port:502',
            "raspberry_pi": 'Raspberry Pi SSH port:22'
        }
        
        query = queries.get(device_type.lower(), device_type)
        print(f"🎯 Buscando {device_type} expuestos...")
        return self.search_query(query, limit)
    
    def compare_with_known_vulns(self, ip, open_ports):
        """Compara puertos abiertos con vulnerabilidades conocidas"""
        host_info = self.search_host(ip)
        if not host_info:
            return []
        
        recommendations = []
        
        for port in open_ports:
            if port in host_info.get('ports', []):
                if port in [21, 22, 23, 3389]:
                    recommendations.append({
                        "port": port,
                        "risk": "HIGH",
                        "recommendation": f"Puerto {port} expuesto, considerar usar VPN o firewall"
                    })
                elif port in [80, 443]:
                    recommendations.append({
                        "port": port,
                        "risk": "MEDIUM", 
                        "recommendation": f"Web server expuesto, asegurar SSL y actualizaciones"
                    })
        
        return recommendations
    
    def export_results(self, filename=None):
        """Exporta resultados a JSON"""
        if not self.results:
            print("No hay resultados para exportar")
            return
        
        filename = filename or f"shodan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_results": len(self.results),
            "results": self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"💾 Resultados guardados en: {filename}")
        return filename

def test():
    print("[TEST] Shodan Integration module loaded")
    print("💡 Configura SHODAN_API_KEY para usar")

# CLI directa para pruebas
if __name__ == "__main__":
    print("🔧 Shodan Scanner CLI")
    print("="*40)
    
    # Buscar sin API key (demo)
    print("\n⚠️ Sin API key, solo modo demostración")
    print("📌 export SHODAN_API_KEY='tu_key'")
    print("\nEjemplos de uso:")
    print("  scanner = ShodanScanner(api_key='TU_KEY')")
    print("  scanner.search_host('8.8.8.8')")
    print("  scanner.search_query('apache country:US')")
    print("  scanner.find_exposed_devices('camera')")
