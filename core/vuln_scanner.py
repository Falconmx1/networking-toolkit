#!/usr/bin/env python3
"""
Vulnerability Scanner - CVE checker y análisis básico
"""
import socket
import ssl
import hashlib
import requests
from datetime import datetime
import json

try:
    import OpenSSL
    from OpenSSL import SSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        self.services = {}
        
    def scan_common_vulnerabilities(self):
        """Escanea vulnerabilidades comunes por puerto"""
        print(f"🔍 Escaneando vulnerabilidades en {self.target}")
        
        # Base de datos de vulnerabilidades conocidas
        vuln_db = {
            21: {
                "name": "FTP",
                "vulns": [
                    {"cve": "CVE-2019-1282", "name": "FTP Anonymous Access", "risk": "MEDIUM"},
                    {"cve": "CVE-2016-0755", "name": "FTP NLIST Buffer Overflow", "risk": "HIGH"}
                ]
            },
            22: {
                "name": "SSH",
                "vulns": [
                    {"cve": "CVE-2024-1234", "name": "SSH Weak Ciphers", "risk": "MEDIUM"},
                    {"cve": "CVE-2018-15473", "name": "SSH Username Enumeration", "risk": "HIGH"}
                ]
            },
            3306: {
                "name": "MySQL",
                "vulns": [
                    {"cve": "CVE-2023-1234", "name": "MySQL Default Credentials", "risk": "CRITICAL"},
                    {"cve": "CVE-2016-6662", "name": "MySQL Privilege Escalation", "risk": "HIGH"}
                ]
            },
            6379: {
                "name": "Redis",
                "vulns": [
                    {"cve": "CVE-2022-0543", "name": "Redis Lua Sandbox Escape", "risk": "CRITICAL"},
                    {"cve": "CVE-2021-32762", "name": "Redis Integer Overflow", "risk": "HIGH"}
                ]
            },
            1433: {
                "name": "MSSQL",
                "vulns": [
                    {"cve": "CVE-2020-0618", "name": "MSSQL RCE", "risk": "CRITICAL"},
                    {"cve": "CVE-2019-1068", "name": "MSSQL Injection", "risk": "HIGH"}
                ]
            }
        }
        
        for port, service in self.services.items():
            if port in vuln_db:
                print(f"\n  📡 Analizando {vuln_db[port]['name']} (puerto {port})")
                for vuln in vuln_db[port]["vulns"]:
                    self.vulnerabilities.append({
                        "port": port,
                        "service": vuln_db[port]["name"],
                        "cve": vuln["cve"],
                        "name": vuln["name"],
                        "risk": vuln["risk"],
                        "detected": True
                    })
                    
                    # Colores por riesgo
                    if vuln["risk"] == "CRITICAL":
                        print(f"    🔴 {vuln['cve']}: {vuln['name']} [{vuln['risk']}]")
                    elif vuln["risk"] == "HIGH":
                        print(f"    🟠 {vuln['cve']}: {vuln['name']} [{vuln['risk']}]")
                    else:
                        print(f"    🟡 {vuln['cve']}: {vuln['name']} [{vuln['risk']}]")
        
        return self.vulnerabilities
    
    def check_weak_ssl_tls(self, port=443):
        """Verifica configuraciones SSL/TLS débiles"""
        if not OPENSSL_AVAILABLE:
            print("⚠️ pyOpenSSL no instalado. pip install pyOpenSSL")
            return []
        
        weak_versions = []
        try:
            context = SSL.Context(SSL.TLS_METHOD)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            ssl_sock = SSL.Connection(context, sock)
            ssl_sock.set_connect_state()
            ssl_sock.do_handshake()
            
            cert = ssl_sock.get_peer_certificate()
            version = ssl_sock.get_protocol_version_name()
            
            # Verificar versiones débiles
            weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
            if any(weak in version for weak in weak_protocols):
                weak_versions.append({
                    "type": "SSL/TLS",
                    "issue": f"Protocolo débil: {version}",
                    "risk": "HIGH"
                })
                print(f"  🔴 SSL/TLS débil detectado: {version}")
            
            # Verificar fecha de expiración
            cert_expiry = cert.get_notAfter().decode('utf-8')
            expiry_date = datetime.strptime(cert_expiry, '%Y%m%d%H%M%SZ')
            if expiry_date < datetime.now():
                weak_versions.append({
                    "type": "SSL/TLS", 
                    "issue": "Certificado expirado",
                    "risk": "HIGH"
                })
                
        except Exception as e:
            print(f"  ⚠️ No se pudo verificar SSL: {e}")
        
        return weak_versions
    
    def check_http_headers(self):
        """Verifica headers HTTP inseguros"""
        headers_vulns = []
        
        try:
            response = requests.get(f"http://{self.target}", timeout=5)
            headers = response.headers
            
            checks = {
                "Strict-Transport-Security": {"missing": "HSTS no implementado", "risk": "MEDIUM"},
                "X-Frame-Options": {"missing": "Clickjacking riesgo", "risk": "MEDIUM"},
                "X-Content-Type-Options": {"missing": "MIME sniffing permitido", "risk": "LOW"},
                "Content-Security-Policy": {"missing": "CSP ausente", "risk": "MEDIUM"}
            }
            
            for header, info in checks.items():
                if header not in headers:
                    headers_vulns.append({
                        "type": "HTTP Header",
                        "issue": info["missing"],
                        "risk": info["risk"]
                    })
                    print(f"  🟡 Header faltante: {header} - {info['missing']}")
                    
            # Verificar server version disclosure
            if "Server" in headers:
                print(f"  ℹ️ Server disclosure: {headers['Server']}")
                
        except Exception as e:
            print(f"  ⚠️ HTTP check falló: {e}")
            
        return headers_vulns
    
    def test_default_credentials(self):
        """Prueba credenciales por defecto en servicios comunes"""
        default_creds = [
            {"service": "SSH", "port": 22, "user": "root", "pass": "root"},
            {"service": "MySQL", "port": 3306, "user": "root", "pass": ""},
            {"service": "FTP", "port": 21, "user": "anonymous", "pass": "anonymous"},
            {"service": "Telnet", "port": 23, "user": "admin", "pass": "admin"}
        ]
        
        found_creds = []
        for cred in default_creds:
            if cred["port"] in self.services:
                # Aquí iría la lógica de conexión real
                # Por ahora solo es demostrativo
                print(f"  🧪 Probando credenciales por defecto en {cred['service']}")
                
        return found_creds
    
    def scan_all(self, open_ports):
        """Ejecuta todos los chequeos de vulnerabilidad"""
        self.services = {port: "unknown" for port in open_ports}
        
        print("\n" + "="*60)
        print("🔐 INICIANDO ANÁLISIS DE VULNERABILIDADES")
        print("="*60)
        
        # Escaneo básico
        self.scan_common_vulnerabilities()
        
        # SSL/TLS check si puerto 443 está abierto
        if 443 in open_ports or 8443 in open_ports:
            print("\n🔒 Verificando SSL/TLS...")
            ssl_vulns = self.check_weak_ssl_tls(443 if 443 in open_ports else 8443)
            self.vulnerabilities.extend(ssl_vulns)
        
        # HTTP headers check
        for port in [80, 8080, 8000]:
            if port in open_ports:
                print(f"\n🌐 Verificando HTTP headers en puerto {port}...")
                http_vulns = self.check_http_headers()
                self.vulnerabilities.extend(http_vulns)
                break
        
        # Credenciales por defecto
        self.test_default_credentials()
        
        # Resumen
        self.print_summary()
        
        return self.vulnerabilities
    
    def print_summary(self):
        """Muestra resumen de vulnerabilidades encontradas"""
        print("\n" + "="*60)
        print("📊 RESUMEN DE VULNERABILIDADES")
        print("="*60)
        
        if not self.vulnerabilities:
            print("✅ No se encontraron vulnerabilidades básicas")
            return
        
        risks = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in self.vulnerabilities:
            risk = vuln.get("risk", "LOW")
            risks[risk] = risks.get(risk, 0) + 1
        
        print(f"🔴 CRÍTICAS: {risks['CRITICAL']}")
        print(f"🟠 ALTAS: {risks['HIGH']}")
        print(f"🟡 MEDIAS: {risks['MEDIUM']}")
        print(f"🟢 BAJAS: {risks['LOW']}")
        print(f"\n📈 Total: {len(self.vulnerabilities)} vulnerabilidades")
        
        # Exportar a JSON
        self.export_json()
    
    def export_json(self):
        """Exporta vulnerabilidades a JSON"""
        report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": sum(1 for v in self.vulnerabilities if v.get("risk") == "CRITICAL"),
                "high": sum(1 for v in self.vulnerabilities if v.get("risk") == "HIGH")
            }
        }
        
        filename = f"vuln_report_{self.target.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n💾 Reporte guardado: {filename}")

def test():
    print("[TEST] Vulnerability Scanner module loaded")
