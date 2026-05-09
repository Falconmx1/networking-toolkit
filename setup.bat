@echo off
echo 🚀 Configurando Networking Tool...
python -m venv venv
call venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements.txt
echo ✅ Listo. Ejecuta: python main.py --help
