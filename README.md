# 🌐 Networking Tool — El toolkit de red definitivo

**Networking Tool** es un conjunto de utilidades de red para **Linux y Windows**, construido con Python puro y dependencies under control con `pip` + entorno virtual.

Ideal para:
- 🕵️ Pentesters
- 👨‍💻 Administradores de red
- 🧠 Estudiantes de ciberseguridad

## ⚡ Características (planned)

- 🔍 Escáner de puertos multi-hilo
- 📡 Sniffer de paquetes (con filtros)
- 🎭 ARP spoofing detector / MITM básico
- ⚡ Slow DoS (TCP SYN flood educativo)
- 🌍 Geo-IP lookup
- 🧪 Tester de conectividad (ping multi-target)
- 📊 Reporte en JSON / CSV

## 🐍 Requisitos

- Python 3.8+
- pip + venv
- Permisos de administrador/root (para ciertos modos raw socket)

## 🚀 Instalación rápida

```bash
git clone https://github.com/Falconmx1/networking-toolkit
cd networking-toolkit
python -m venv venv

# Activar venv:
# Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
python main.py --help
