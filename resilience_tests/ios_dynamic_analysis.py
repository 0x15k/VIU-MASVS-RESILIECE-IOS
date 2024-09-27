import frida
import sys
import time
import traceback
from connection import detect_ios_devices

def on_message(message, data):
    """Maneja los mensajes recibidos del script de Frida."""
    msg_type = message.get('type', '')
    if msg_type == 'send':
        print(f"[INFO] {message.get('payload', '')}")
    elif msg_type == 'error':
        print(f"[ERROR] {message.get('stack', '')}")

def inject_script(device, script_code, identifier):
    """Inyecta y gestiona el script en el dispositivo iOS."""
    try:
        print(f"Iniciando la aplicación '{identifier}'...")
        pid = device.spawn([identifier])
        device.resume(pid)
        time.sleep(2)  # Aumenta el tiempo de espera antes de adjuntar

        print(f"Verificando si el proceso con PID {pid} sigue en ejecución...")
        processes = device.enumerate_processes()
        if any(proc.pid == pid for proc in processes):
            print(f"Adjuntando al proceso con PID {pid}...")
            session = device.attach(pid)

            print("Inyectando script...")
            script = session.create_script(script_code)
            script.on('message', on_message)
            script.load()

            print(f"Script inyectado exitosamente en {identifier} (PID {pid}).")
            time.sleep(10)

            if session.is_detached:
                print("El binario detectó que el dispositivo está jailbreak.")
            else:
                print("El binario no detectó que el dispositivo está jailbreak.")
        else:
            print(f"El proceso con PID {pid} no se encuentra en ejecución.")
            print("El binario detectó que el dispositivo está jailbreak.")
    except frida.ProcessNotFoundError as e:
        print(f"Error: No se pudo encontrar el proceso con PID {pid}: {str(e)}")
        traceback.print_exc()
        print("El binario detectó que el dispositivo está jailbreak.")
    except frida.NotSupportedError as e:
        print(f"Error de Frida: {str(e)}")
        traceback.print_exc()
    except Exception as e:
        print(f"Error en la función principal: {str(e)}")
        traceback.print_exc()

def main():
    """Función principal que detecta dispositivos iOS y monitorea un binario."""
    if len(sys.argv) != 2:
        print("Usage: python ios_dynamic_analysis.py <target_identifier>")
        sys.exit(1)

    target_identifier = sys.argv[1]
    
    try:
        print("Detectando dispositivos iOS...")
        output, usb_devices, remote_devices = detect_ios_devices()
        print(output)
        
        device = usb_devices[0] if usb_devices else (remote_devices[0] if remote_devices else None)
        
        if device:
            print(f"Dispositivo conectado: {device}")

            # Script de Frida para interceptar funciones de detección de jailbreak
            script_code = """
            console.log("Iniciando bypass de detección de jailbreak...");

            var paths_to_bypass = [
                "/private/jailbreak.txt", "/Applications/Cydia.app",
                "/usr/sbin/sshd", "/etc/apt", "/bin/bash", "/usr/bin/ssh",
                "/Library/MobileSubstrate/MobileSubstrate.dylib", "/var/cache/apt",
                "/var/lib/apt", "/var/lib/cydia", "/var/tmp/cydia.log"
            ];

            function bypass(path) {
                if (paths_to_bypass.includes(path)) {
                    console.log("Bypassing check for: " + path);
                    return -1;
                }
                return 0;
            }

            var functions_to_intercept = ["stat", "open", "access", "lstat", "fopen", "opendir"];

            functions_to_intercept.forEach(function(func) {
                try {
                    Interceptor.attach(Module.findExportByName(null, func), {
                        onEnter: function(args) {
                            var path = Memory.readUtf8String(args[0]);
                            console.log("Interceptando llamada a " + func + " con ruta: " + path);
                            this.bypass = bypass(path);
                        },
                        onLeave: function(retval) {
                            if (this.bypass) {
                                console.log("Bypass activado para " + func + " con ruta " + path);
                                retval.replace(-1);
                            }
                        }
                    });
                } catch (err) {
                    console.log("Error al interceptar " + func + ": " + err.message);
                }
            });

            console.log("Bypass completado.");
            """
            inject_script(device, script_code, target_identifier)
        else:
            print("No se encontraron dispositivos iOS conectados.")
    except Exception as e:
        print(f"Error en la función principal: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main()