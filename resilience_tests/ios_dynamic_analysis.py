import frida
import sys
import time
import traceback
import os
from connection import detect_ios_devices, list_ios_processes

def on_message(message, data):
    """Maneja los mensajes recibidos del script de Frida."""
    msg_type = message.get('type', '')
    if msg_type == 'send':
        print(f"[INFO] {message.get('payload', '')}")
    elif msg_type == 'error':
        print(f"[ERROR] {message.get('stack', '')}")

def load_script(script_name):
    """Carga el contenido del script de Frida desde la carpeta scripts."""
    script_path = os.path.join(os.path.dirname(__file__), 'scripts', script_name)
    try:
        with open(script_path, 'r', encoding='utf-8') as script_file:
            return script_file.read()
    except FileNotFoundError:
        print(f"Error: No se pudo encontrar el script {script_name} en la ruta {script_path}")
        sys.exit(1)

def inject_script(device, script_code, identifier):
    """Inyecta y gestiona el script en el dispositivo iOS."""
    try:
        print(f"Iniciando la aplicación '{identifier}'...")
        pid = device.spawn([identifier])
        device.resume(pid)
        time.sleep(2)  # Aumentar el tiempo de espera antes de adjuntar

        processes = device.enumerate_processes()
        if any(proc.pid == pid for proc in processes):
            session = device.attach(pid)
            script = session.create_script(script_code)
            script.on('message', on_message)
            script.load()
            print(f"Script inyectado exitosamente en {identifier} (PID {pid}).")
            time.sleep(10)
        else:
            print(f"El proceso con PID {pid} no está en ejecución.")
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
    """Función principal que detecta dispositivos iOS y monitorea un binario."""
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Uso: python ios_dynamic_analysis.py <identificador_objetivo> [<nombre_script>]")
        sys.exit(1)

    target_identifier = sys.argv[1]
    script_name = sys.argv[2] if len(sys.argv) == 3 else 'masvs-ios-frida-script.js'
    
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
        print(output)
        
        device = usb_devices[0] if usb_devices else (remote_devices[0] if remote_devices else None)
        if device:
            print(f"Dispositivo conectado: {device}")
            script_code = load_script(script_name)
            inject_script(device, script_code, target_identifier)
        else:
            print("No se encontraron dispositivos iOS conectados.")
    except Exception as e:
        print(f"Error en la función principal: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main()