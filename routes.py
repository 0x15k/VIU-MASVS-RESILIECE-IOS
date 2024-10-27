import sys
import os
import logging
import frida  # Asegúrate de importar frida aquí
from flask import Blueprint, render_template, request, redirect, url_for, send_file, jsonify, Response
from werkzeug.utils import secure_filename
import subprocess
import json
import time
from config import UPLOAD_FOLDER, RESULTS_FOLDER, ALLOWED_EXTENSIONS
from utils import allowed_file, save_html_report, generate_html_report, generate_dynamic_analysis_report, list_scripts

# Add 'resilience_tests' directory to PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'resilience_tests'))

from connection import detect_ios_devices, is_ssh_tunnel_active

routes = Blueprint('routes', __name__)

# Configurar el registro
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear subcarpetas 'static' y 'dynamic' si no existen
os.makedirs(os.path.join(RESULTS_FOLDER, 'static'), exist_ok=True)
os.makedirs(os.path.join(RESULTS_FOLDER, 'dynamic'), exist_ok=True)

def get_apps(devices):
    """
    Obtiene las aplicaciones no nativas de Apple de los dispositivos proporcionados.
    
    :param devices: Lista de dispositivos (usb_devices o remote_devices)
    :return: Lista de tuplas con (nombre de la app, identificador)
    """
    apps = []
    if devices:
        try:
            apps = [
                (process.name, process.identifier)
                for process in devices[0].enumerate_applications()
                if not process.identifier.startswith("com.apple.")
            ]
            logger.info(f"Aplicaciones enumeradas: {[app[1] for app in apps]}")
        except frida.TransportError as e:
            logger.error(f"Error de transporte al enumerar aplicaciones: {e}")
            apps = []
        except Exception as e:
            logger.exception(f"Error inesperado al enumerar aplicaciones: {e}")
            apps = []
    return apps

@routes.route('/')
def index():
    """Página principal que lista los reportes generados y muestra el estado de los dispositivos."""
    static_reports = [f for f in os.listdir(os.path.join(RESULTS_FOLDER, 'static')) if f.endswith('.html')]
    dynamic_reports = [f for f in os.listdir(os.path.join(RESULTS_FOLDER, 'dynamic')) if f.endswith('.html')]
    
    # Detectar dispositivos conectados
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
        device_connected = bool(usb_devices or remote_devices)
    except Exception as e:
        logger.exception("Error al detectar dispositivos iOS.")
        device_connected = False
        usb_devices, remote_devices = [], []
    
    # Obtener aplicaciones no nativas
    if usb_devices:
        apps = get_apps(usb_devices)
    elif remote_devices:
        apps = get_apps(remote_devices)
    else:
        apps = []
    
    return render_template('index.html', static_reports=static_reports, dynamic_reports=dynamic_reports, device_connected=device_connected, apps=apps)

@routes.route('/dynamic_analyzer')
def dynamic_analyzer():
    """Página para análisis dinámico."""
    dynamic_reports = [f for f in os.listdir(os.path.join(RESULTS_FOLDER, 'dynamic')) if f.endswith('.html')]
    
    # Detectar dispositivos conectados
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
        device_connected = bool(usb_devices or remote_devices)
    except Exception as e:
        logger.exception("Error al detectar dispositivos iOS.")
        device_connected = False
        usb_devices, remote_devices = [], []
    
    # Obtener aplicaciones no nativas
    if usb_devices:
        apps = get_apps(usb_devices)
    elif remote_devices:
        apps = get_apps(remote_devices)
    else:
        apps = []
    
    # Listar scripts disponibles
    scripts = list_scripts()

    return render_template('dynamic_analyzer.html', dynamic_reports=dynamic_reports, device_connected=device_connected, apps=apps, scripts=scripts)

@routes.route('/run_dynamic_analysis', methods=['POST'])
def run_dynamic_analysis():
    """Ejecuta análisis dinámico en el dispositivo iOS."""
    identifier = request.form.get('identifier')
    if not identifier:
        return jsonify({"error": "No se proporcionó el identificador."}), 400

    # Detectar dispositivos conectados
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
        device_connected = bool(usb_devices or remote_devices)
    except Exception as e:
        logger.exception("Error al detectar dispositivos iOS.")
        device_connected = False
        usb_devices, remote_devices = [], []
    
    # Obtener aplicaciones no nativas
    if usb_devices:
        apps = get_apps(usb_devices)
    elif remote_devices:
        apps = get_apps(remote_devices)
    else:
        apps = []
    
    # Validar que el identificador esté en la lista de aplicaciones identificadas
    valid_identifiers = [app[1] for app in apps]
    if identifier not in valid_identifiers:
        return jsonify({"error": "Identificador inválido proporcionado."}), 400
    
    script_path = os.path.join('resilience_tests', 'ios_dynamic_analysis.py')
    
    # Ejecutar el script de análisis dinámico
    try:
        python_executable = 'python3' if os.system("which python3") == 0 else 'python'
        result = subprocess.run([python_executable, script_path, identifier], check=True, capture_output=True, text=True)
        dynamic_analysis_results = result.stdout
        logger.info("Análisis dinámico ejecutado correctamente.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al ejecutar el script de análisis dinámico: {e}")
        return jsonify({"error": "Ocurrió un error al ejecutar el análisis dinámico."}), 500
    except Exception as e:
        logger.exception("Error inesperado al ejecutar el análisis dinámico.")
        return jsonify({"error": "Ocurrió un error inesperado."}), 500
    
    # Dividir los resultados y verificar
    results_parts = dynamic_analysis_results.split('---split---')
    if len(results_parts) < 3:
        logger.error("Resultados insuficientes para generar el reporte.")
        return jsonify({"error": "Resultados insuficientes para generar el reporte."}), 500
    
    results1, results2, results3 = results_parts[:3]
    
    # Generar reporte HTML
    try:
        html_report = generate_dynamic_analysis_report(identifier, results1.splitlines(), results2.splitlines(), results3.splitlines(), url_for)
        html_report_path = save_html_report(html_report, identifier, RESULTS_FOLDER, 'dynamic')
        logger.info(f"Reporte dinámico guardado en {html_report_path}.")
    except Exception as e:
        logger.exception("Error al generar o guardar el reporte HTML.")
        return jsonify({"error": "Ocurrió un error al generar el reporte."}), 500
    
    return jsonify({"message": "Análisis dinámico completado exitosamente."}), 200

@routes.route('/upload', methods=['POST'])
def upload_file():
    """Maneja la carga de archivos."""
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        logger.info(f"Archivo cargado: {file_path}")
        return redirect(url_for('routes.index'))
    return redirect(request.url)

@routes.route('/view_report/<path:filename>')
def view_report(filename):
    """Muestra el reporte cargado."""
    report_path = os.path.join(RESULTS_FOLDER, filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=False)
    logger.warning(f"Reporte no encontrado: {report_path}")
    return jsonify({"error": "Reporte no encontrado."}), 404

@routes.route('/run_test/masvs_resilience_ios.py', methods=['POST'])
def run_test():
    """Ejecuta el script de prueba especificado."""
    if 'file' not in request.files:
        return jsonify({"error": "No se proporcionó ningún archivo."}), 400
    
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename, ALLOWED_EXTENSIONS):
        return jsonify({"error": "Archivo inválido."}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    logger.info(f"Archivo para prueba cargado: {file_path}")

    script_path = os.path.join('resilience_tests', 'masvs_resilience_ios.py')

    # Medir tiempo de ejecución
    start_time = time.time()
    try:
        python_executable = 'python3' if os.system("which python3") == 0 else 'python'
        result = subprocess.run([python_executable, script_path, filename], check=True, capture_output=True, text=True)
        analysis_results = json.loads(result.stdout)
        logger.info("Prueba ejecutada correctamente.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al ejecutar el script de prueba: {e}")
        return jsonify({"error": "Ocurrió un error al ejecutar la prueba."}), 500
    except json.JSONDecodeError:
        logger.error("Error al decodificar la salida JSON del script de prueba.")
        return jsonify({"error": "Salida inválida del script de prueba."}), 500
    except Exception as e:
        logger.exception("Error inesperado al ejecutar la prueba.")
        return jsonify({"error": "Ocurrió un error inesperado."}), 500
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"Tiempo de ejecución para masvs_resilience_ios.py: {execution_time:.2f} segundos")

    # Generar reporte HTML
    try:
        html_report = generate_html_report(filename, analysis_results, url_for)
        save_html_report(html_report, filename, RESULTS_FOLDER, 'static')
        logger.info(f"Reporte estático guardado para {filename}.")
    except Exception as e:
        logger.exception("Error al generar o guardar el reporte HTML estático.")
        return jsonify({"error": "Ocurrió un error al generar el reporte."}), 500

    return jsonify({"message": "Prueba ejecutada y reporte generado exitosamente."}), 200

@routes.route('/preview_report/<filename>')
def preview_report(filename):
    """Previsualiza el reporte HTML generado."""
    report_path = os.path.join(RESULTS_FOLDER, filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=False)
    logger.warning(f"Reporte para previsualizar no encontrado: {report_path}")
    return jsonify({"error": "Reporte no encontrado."}), 404

@routes.route('/frida_console')
def frida_console():
    """Renderiza la consola interactiva de Frida."""
    # Detectar dispositivos conectados
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
        device_connected = bool(usb_devices or remote_devices)
    except Exception as e:
        logger.exception("Error al detectar dispositivos iOS para consola de Frida.")
        device_connected = False
        usb_devices, remote_devices = [], []
    
    # Obtener aplicaciones no nativas
    if usb_devices:
        apps = get_apps(usb_devices)
    elif remote_devices:
        apps = get_apps(remote_devices)
    else:
        apps = []
    
    # Listar scripts disponibles
    scripts = list_scripts()

    return render_template('frida_console.html', device_connected=device_connected, apps=apps, scripts=scripts)

@routes.route('/run_frida', methods=['GET'])
def run_frida_command():
    """Ejecuta un comando de Frida en tiempo real y transmite la salida."""
    identifier = request.args.get('identifier')
    script = request.args.get('script')

    # Verificar que los campos estén presentes
    if not identifier or not script:
        logger.warning("Identificador o script no proporcionado en run_frida.")
        return jsonify({"output": "Error: No se proporcionó el identificador o el script."}), 400

    # Ruta completa del script en resilience_tests/scripts
    script_path = os.path.join(os.path.dirname(__file__), 'resilience_tests', 'scripts', script)

    if not os.path.exists(script_path):
        logger.warning(f"Script no encontrado: {script_path}")
        return jsonify({"output": f"Error: El script {script} no se encuentra en la ruta {script_path}."}), 404

    # Detectar dispositivos conectados (USB o SSH)
    try:
        output, usb_devices, remote_devices = detect_ios_devices()
    except Exception as e:
        logger.exception("Error al detectar dispositivos iOS para ejecutar comando Frida.")
        return jsonify({"output": "Error: No se pudieron detectar dispositivos conectados."}), 500

    # Verificar si hay dispositivos conectados por USB o SSH y definir el comando Frida
    if usb_devices:
        full_command = f"frida -U -f {identifier} -l {script_path}"
    elif remote_devices:
        full_command = f"frida -H 127.0.0.1 -f {identifier} -l {script_path}"
    else:
        logger.warning("No se encontraron dispositivos conectados para ejecutar comando Frida.")
        return jsonify({"output": "Error: No se encontraron dispositivos conectados."}), 400

    # Usar Server-Sent Events (SSE) para transmitir la salida en tiempo real
    def stream_output():
        try:
            logger.info(f"Ejecutando comando Frida: {full_command}")
            process = subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            
            # Transmitir stdout
            for line in process.stdout:
                yield f"data: {line}\n\n"
            
            process.stdout.close()
            process.wait()
            
            # Transmitir stderr si hay errores
            if process.returncode != 0:
                error_output = process.stderr.read()
                logger.error(f"Error al ejecutar comando Frida: {error_output}")
                yield f"data: Error ejecutando el comando:\n{error_output}\n\n"
            
            process.stderr.close()
        
        except Exception as e:
            logger.exception("Error interno al ejecutar el comando Frida.")
            yield f"data: Error interno al ejecutar el comando: {str(e)}\n\n"

    return Response(stream_output(), mimetype='text/event-stream')
