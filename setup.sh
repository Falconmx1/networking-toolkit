#!/bin/bash
echo "🚀 Configurando Networking Tool..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Listo. Ejecuta: python main.py --help"
