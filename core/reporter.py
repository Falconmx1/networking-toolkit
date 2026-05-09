#!/usr/bin/env python3
"""
Sistema de reportes y logging para Networking Tool
"""
import json
import csv
import os
import time
from datetime import datetime
from pathlib import Path

class NetworkReporter:
    def __init__(self, log_dir="logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.current_session = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_data = []
        self.attack_data = []
        
    def log_scan(self, target, open_ports, closed_ports, scan_time):
        """Registra resultados de escaneo"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "port_scan",
            "target": target,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "scan_duration": scan_time,
            "total_ports": len(open_ports) + len(closed_ports)
        }
        self.scan_data.append(entry)
        self._save_json()
        self._save_csv()
        return entry
    
    def log_attack(self, attack_type, target, details):
        """Registra detección de ataques"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": attack_type,
            "target": target,
            "details": details,
            "severity": details.get("severity", "MEDIUM")
        }
        self.attack_data.append(entry)
        self._save_attack_log()
        
        # Si es crítico, guardar en archivo especial
        if entry["severity"] == "HIGH":
            self._save_critical_alert(entry)
        
        return entry
    
    def _save_json(self):
        """Guarda reporte completo en JSON"""
        report = {
            "session": self.current_session,
            "generated": datetime.now().isoformat(),
            "scans": self.scan_data,
            "attacks": self.attack_data,
            "summary": {
                "total_scans": len(self.scan_data),
                "total_alerts": len(self.attack_data),
                "critical_alerts": sum(1 for a in self.attack_data if a.get("severity") == "HIGH")
            }
        }
        
        json_file = self.log_dir / f"report_{self.current_session}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        return json_file
    
    def _save_csv(self):
        """Exporta escaneos a CSV"""
        csv_file = self.log_dir / f"scans_{self.current_session}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Target", "Open Ports", "Closed Ports", "Duration"])
            for scan in self.scan_data:
                writer.writerow([
                    scan["timestamp"],
                    scan["target"],
                    ", ".join(map(str, scan["open_ports"])),
                    ", ".join(map(str, scan["closed_ports"][:5])),  # Limitar
                    scan["scan_duration"]
                ])
    
    def _save_attack_log(self):
        """Guarda log de ataques en texto plano"""
        log_file = self.log_dir / f"attacks_{self.current_session}.log"
        with open(log_file, 'a') as f:
            for attack in self.attack_data[-1:]:  # Último ataque
                f.write(f"[{attack['timestamp']}] {attack['type']} - {attack['target']}\n")
                f.write(f"  Details: {attack['details']}\n")
                f.write("-" * 50 + "\n")
    
    def _save_critical_alert(self, alert):
        """Guarda alertas críticas en archivo separado"""
        critical_file = self.log_dir / "CRITICAL_ALERTS.log"
        with open(critical_file, 'a') as f:
            f.write("🚨 " + "="*50 + "\n")
            f.write(f"⚠️ ALERTA CRÍTICA - {alert['timestamp']}\n")
            f.write(f"Tipo: {alert['type']}\n")
            f.write(f"Target: {alert['target']}\n")
            f.write(f"Detalles: {alert['details']}\n")
            f.write("="*50 + "\n\n")
    
    def generate_html_report(self):
        """Genera reporte HTML bonito"""
        html_file = self.log_dir / f"report_{self.current_session}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Networking Tool Report - {self.current_session}</title>
            <style>
                body {{ font-family: monospace; margin: 40px; background: #0a0e27; color: #00ffaa; }}
                h1 {{ color: #ff3366; }}
                .container {{ max-width: 1200px; margin: auto; }}
                .card {{ background: #16213e; padding: 20px; margin: 20px 0; border-radius: 10px; }}
                .critical {{ border-left: 5px solid #ff3366; }}
                .warning {{ border-left: 5px solid #ffaa00; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
                th {{ background: #ff3366; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🌐 Networking Tool Report</h1>
                <p>Generated: {datetime.now().isoformat()}</p>
                
                <div class="card">
                    <h2>📊 Summary</h2>
                    <ul>
                        <li>Total Scans: {len(self.scan_data)}</li>
                        <li>Total Alerts: {len(self.attack_data)}</li>
                        <li>Critical Alerts: {sum(1 for a in self.attack_data if a.get('severity') == 'HIGH')}</li>
                    </ul>
                </div>
                
                <div class="card">
                    <h2>🔍 Recent Scans</h2>
                    <table>
                        <tr><th>Time</th><th>Target</th><th>Open Ports</th></tr>
                        {''.join(f'<tr><td>{s["timestamp"]}</td><td>{s["target"]}</td><td>{", ".join(map(str, s["open_ports"]))}</td></tr>' for s in self.scan_data[-5:])}
                    </table>
                </div>
                
                <div class="card">
                    <h2>🚨 Security Alerts</h2>
                    {''.join(f'<div class="card critical"><strong>{a["timestamp"]}</strong><br/>{a["type"]} - {a["target"]}<br/>{a["details"]}</div>' for a in self.attack_data if a.get("severity") == "HIGH")}
                    {''.join(f'<div class="card warning"><strong>{a["timestamp"]}</strong><br/>{a["type"]} - {a["target"]}</div>' for a in self.attack_data if a.get("severity") != "HIGH")}
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        return html_file
    
    def print_summary(self):
        """Muestra resumen en consola"""
        print("\n" + "="*50)
        print("📈 RESUMEN DE SESIÓN")
        print("="*50)
        print(f"📁 Logs guardados en: {self.log_dir}")
        print(f"🔍 Escaneos realizados: {len(self.scan_data)}")
        print(f"🚨 Alertas generadas: {len(self.attack_data)}")
        print(f"⚠️ Alertas críticas: {sum(1 for a in self.attack_data if a.get('severity') == 'HIGH')}")
        print("="*50)

def test():
    print("[TEST] Reporter module loaded")

# Uso rápido
if __name__ == "__main__":
    reporter = NetworkReporter()
    reporter.log_scan("192.168.1.1", [22,80,443], [21,23,25], "1.2s")
    reporter.log_attack("ARP_Spoof", "192.168.1.1", {"severity": "HIGH", "mac": "aa:bb:cc:dd:ee:ff"})
    reporter.print_summary()
    print(f"📄 HTML Report: {reporter.generate_html_report()}")
