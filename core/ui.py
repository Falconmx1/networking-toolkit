#!/usr/bin/env python3
"""
UI mejorada con colores y efectos para Networking Tool
"""
import platform
import subprocess

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = BLACK = ''
        RESET = ''
    class Back:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = BLACK = ''
        RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

class NetworkUI:
    """Interfaz de usuario con estilo"""
    
    @staticmethod
    def banner():
        """Banner principal"""
        banner_text = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🌐  NETWORKING TOOL v1.0                                   ║
║   🔧  Swiss Army knife para pentesters                       ║
║   🐍  Python + Scapy + Venv                                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """
        print(banner_text)
    
    @staticmethod
    def info(msg):
        """Mensaje de información"""
        print(f"{Fore.CYAN}ℹ️  {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def success(msg):
        """Mensaje de éxito"""
        print(f"{Fore.GREEN}✅ {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def warning(msg):
        """Mensaje de advertencia"""
        print(f"{Fore.YELLOW}⚠️  {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def error(msg):
        """Mensaje de error"""
        print(f"{Fore.RED}❌ {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def attack(msg):
        """Mensaje de ataque/seguridad"""
        print(f"{Fore.RED}{Style.BRIGHT}🔥 {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def table(data, headers):
        """Dibuja tabla simple"""
        # Calcular anchos
        col_widths = [len(h) for h in headers]
        for row in data:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Header
        header_line = " | ".join(headers[i].ljust(col_widths[i]) for i in range(len(headers)))
        print(f"{Fore.CYAN}{header_line}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-' * len(header_line)}{Style.RESET_ALL}")
        
        # Data
        for row in data:
            line = " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(row)))
            print(line)
    
    @staticmethod
    def progress_bar(current, total, prefix='', suffix='', length=50):
        """Barra de progreso"""
        percent = 100 * (current / float(total))
        filled_length = int(length * current // total)
        bar = '█' * filled_length + '░' * (length - filled_length)
        print(f'\r{prefix} |{Fore.GREEN}{bar}{Style.RESET_ALL}| {percent:.1f}% {suffix}', end='')
        if current == total:
            print()
    
    @staticmethod
    def clear_screen():
        """Limpia pantalla"""
        cmd = 'cls' if platform.system() == 'Windows' else 'clear'
        subprocess.call(cmd, shell=True)
    
    @staticmethod
    def menu(options, title="📋 Menú Principal"):
        """Menú interactivo"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
        for i, option in enumerate(options, 1):
            print(f"{Fore.YELLOW}{i}.{Style.RESET_ALL} {option}")
        print(f"{Fore.YELLOW}0.{Style.RESET_ALL} Salir")
        
        while True:
            try:
                choice = int(input(f"\n{Fore.GREEN}➜{Style.RESET_ALL} Selecciona: "))
                if 0 <= choice <= len(options):
                    return choice
                else:
                    NetworkUI.error(f"Opción inválida. Elige 0-{len(options)}")
            except ValueError:
                NetworkUI.error("Ingresa un número")
    
    @staticmethod
    def loading_animation(text="Procesando", duration=2):
        """Animación de carga"""
        import itertools
        import time
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        start_time = time.time()
        for char in itertools.cycle(chars):
            print(f'\r{Fore.CYAN}{char} {text}...{Style.RESET_ALL}', end='')
            time.sleep(0.1)
            if time.time() - start_time > duration:
                break
        print('\r' + ' ' * 50 + '\r', end='')

def test():
    print("[TEST] UI module loaded")
    NetworkUI.banner()
    NetworkUI.success("Sistema listo")
    NetworkUI.warning("Esta es una advertencia")
    NetworkUI.error("Esto es un error")
    NetworkUI.attack("Ataque detectado")

if __name__ == "__main__":
    test()
    
    # Demo del menú
    options = ["Escáner de puertos", "Sniffer de paquetes", "ARP Spoof Detector", "Generar Reporte"]
    choice = NetworkUI.menu(options, "🔧 Networking Tool")
    NetworkUI.info(f"Seleccionaste opción {choice}")
