import sys
import os

# Añade el directorio del módulo utils al PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import frida
import time
import traceback
from connection import detect_ios_devices
from utils import generate_dynamic_analysis_report, save_html_report

def on_message(message, data, script_name, results):
    """Maneja los mensajes recibidos del script de Frida."""
    msg_type = message.get('type', '')
    if msg_type == 'send':
        print(f"[{script_name}] {message.get('payload', '')}")
        results.append(f"[{script_name}] {message.get('payload', '')}")
    elif msg_type == 'error':
        print(f"[ERROR] [{script_name}] {message.get('stack', '')}")
        results.append(f"[ERROR] [{script_name}] {message.get('stack', '')}")

def load_script(script_name):
    """Carga el contenido del script de Frida desde la carpeta scripts."""
    script_path = os.path.join(os.path.dirname(__file__), 'scripts', script_name)
    try:
        with open(script_path, 'r', encoding='utf-8') as script_file:
            return script_file.read()
    except FileNotFoundError:
        print(f"Error: No se pudo encontrar el script {script_name} en la ruta {script_path}")
        sys.exit(1)

def inject_script(device, script_code, identifier, script_name, results):
    """Inyecta y gestiona el script en el dispositivo iOS."""
    try:
        print(f"Iniciando la aplicación'{identifier}'...")
        pid = device.spawn([identifier])
        device.resume(pid)
        time.sleep(1)  # Aumentar el tiempo de espera antes de adjuntar

        processes = device.enumerate_processes()
        if any(proc.pid == pid for proc in processes):
            session = device.attach(pid)
            script = session.create_script(script_code)
            script.on('message', lambda message, data: on_message(message, data, script_name, results))
            script.load()
            print(f"Script '{script_name}' inyectado exitosamente en {identifier} (PID {pid}).")
            time.sleep(10)
        else:
            print(f"El proceso con PID {pid} no está en ejecución. No fue posible evadir Frida Detection/Jailbreak Detection, por lo cual no permite ejecutar el correcto análisis dinámico")
    except frida.ProcessNotFoundError as e:
        print(f"Error: No se pudo encontrar el proceso con PID {pid}: {str(e)}")
        traceback.print_exc()
    except frida.NotSupportedError as e:
        print(f"Error de Frida: {str(e)}")
        traceback.print_exc()
    except Exception as e:
        print(f"Error en la función principal: {str(e)}")
        traceback.print_exc()

def main():
    if len(sys.argv) < 2:
        print("Uso: python ios_dynamic_analysis.py <identificador_objetivo>")
        sys.exit(1)

    target_identifier = sys.argv[1]
    scripts = [
        'testAntiDebuggingDetection.js',
        'testWhetherAppIsDebuggable.js',
        'testReverseEngineeringToolsDetection.js'
    ]
    
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
        
        device = usb_devices[0] if usb_devices else (remote_devices[0] if remote_devices else None)
        if device:
            combined_results = []
            for script_name in scripts:
                script_code = load_script(script_name)
                results = []
                inject_script(device, script_code, target_identifier, script_name, results)
                combined_results.append('\n'.join(results))

            # Imprimir los resultados separados por '---split---'
            print('---split---'.join(combined_results))
        else:
            print("No se encontraron dispositivos iOS conectados.")
    except Exception as e:
        print(f"Error en la función principal: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main()