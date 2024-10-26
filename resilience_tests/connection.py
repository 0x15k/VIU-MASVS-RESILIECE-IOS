import frida
import socket
import argparse

def is_ssh_tunnel_active(host='127.0.0.1', port=27042):
    """Verifica si el túnel SSH está activo intentando conectarse al puerto local redirigido."""
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def detect_ios_devices():
    """Detecta dispositivos iOS conectados por USB y remotamente usando frida."""
    try:
        # Obtiene la lista de dispositivos conectados
        devices = frida.enumerate_devices()
        
        # Filtra los dispositivos iOS conectados por USB y remotamente
        usb_devices = [device for device in devices if device.type == 'usb']
        remote_devices = [device for device in devices if device.type == 'remote']
        
        device_list = ""
        usb_connected = bool(usb_devices)
        ssh_connected = is_ssh_tunnel_active() and bool(remote_devices)
        
        if not usb_connected and not ssh_connected:
            device_list += "No se encontraron dispositivos iOS conectados por USB.\n"
            device_list += "Consejo: Asegúrate de que el dispositivo esté conectado por USB y que Frida esté ejecutándose en el dispositivo.\n"
            device_list += "No se encontró un túnel SSH activo. Asegúrate de ejecutar el siguiente comando:\n"
            device_list += "ssh -L 27042:127.0.0.1:27042 root@<IP_DEL_DISPOSITIVO>\n"
            return device_list, [], []

        if usb_connected:
            device_list += "Dispositivo(s) iOS conectados por USB.\n"
            for device in usb_devices:
                device_list += f"ID: {device.id}, Nombre: {device.name}\n"
        
        if ssh_connected:
            device_list += "Dispositivo(s) iOS conectados remotamente (túnel SSH):\n"
            for device in remote_devices:
                # Verificar si el nombre del dispositivo está disponible
                device_name = device.name if device.name else "Nombre no disponible"
                device_list += f"ID: {device.id}, Nombre: {device_name}\n"
        
        return device_list, usb_devices, remote_devices if ssh_connected else []
    except Exception as e:
        # Maneja errores en la detección de dispositivos
        print(f"Error al detectar dispositivos iOS: {e}")
        return "Ocurrió un error al intentar detectar dispositivos iOS.", [], []

def list_ios_processes(device):
    """Lista los identificadores de las aplicaciones en el dispositivo iOS conectado, excluyendo las nativas de Apple."""
    try:
        # Obtiene la lista de aplicaciones en el dispositivo
        processes = device.enumerate_applications()
        
        if not processes:
            return "No se encontraron aplicaciones en el dispositivo iOS."
        else:
            # Filtra las aplicaciones que no son nativas de Apple
            non_native_apps = [process for process in processes if not process.identifier.startswith("com.apple.")]
            app_identifiers = [process.identifier for process in non_native_apps]
            return f"Identificadores de aplicaciones en el dispositivo iOS:\n" + "\n".join(app_identifiers)
    except frida.TransportError as e:
        # Maneja errores de transporte (conexión)
        return f"Failed to enumerate applications: {e}"
    except Exception as e:
        # Maneja otros errores
        return f"Ocurrió un error al intentar listar aplicaciones en el dispositivo iOS: {e}"

def main():
    """Función principal para detectar dispositivos y listar aplicaciones."""
    parser = argparse.ArgumentParser(description="Detectar dispositivos iOS y listar aplicaciones.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Mostrar detalles de los dispositivos conectados.")
    parser.add_argument('-ps', '--processes', action='store_true', help="Listar los identificadores de las aplicaciones en el dispositivo iOS.")
    args = parser.parse_args()

    output, usb_devices, remote_devices = detect_ios_devices()

    # Mostrar siempre el estado de los dispositivos conectados
    if usb_devices or remote_devices:
        print("Dispositivo(s) iOS conectado(s).")
    else:
        print("No se encontraron dispositivos iOS conectados.")

    # Mostrar device_list solo si se usa el parámetro -v
    if args.verbose:
        print(output)

    if args.processes:
        if usb_devices:
            print("Aplicaciones en el primer dispositivo iOS conectado por USB:")
            process_output = list_ios_processes(usb_devices[0])
            print(process_output)
        
        if remote_devices:
            try:
                print("Aplicaciones en el primer dispositivo iOS conectado remotamente (túnel SSH):")
                process_output = list_ios_processes(remote_devices[0])
                print(process_output)
            except frida.TransportError as e:
                print(f"Failed to enumerate applications: {e}")
            except Exception as e:
                print(f"Ocurrió un error al intentar listar aplicaciones en el dispositivo iOS: {e}")

if __name__ == "__main__":
    main()