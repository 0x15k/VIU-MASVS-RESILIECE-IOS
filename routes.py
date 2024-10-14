import sys
import os
from flask import Blueprint, render_template, request, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import subprocess
import json
import time
from config import UPLOAD_FOLDER, RESULTS_FOLDER, ALLOWED_EXTENSIONS
from utils import allowed_file, save_html_report, generate_html_report, generate_dynamic_analysis_report, list_scripts

# Add 'resilience_tests' directory to PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'resilience_tests'))

from connection import detect_ios_devices

routes = Blueprint('routes', __name__)

# Crear subcarpetas 'static' y 'dynamic' si no existen
os.makedirs(os.path.join(RESULTS_FOLDER, 'static'), exist_ok=True)
os.makedirs(os.path.join(RESULTS_FOLDER, 'dynamic'), exist_ok=True)

@routes.route('/')
def index():
    """Main page listing generated reports and showing device status."""
    static_reports = [f for f in os.listdir(os.path.join(RESULTS_FOLDER, 'static')) if f.endswith('.html')]
    dynamic_reports = [f for f in os.listdir(os.path.join(RESULTS_FOLDER, 'dynamic')) if f.endswith('.html')]
    
    # Detect connected iOS devices
    output, usb_devices, remote_devices = detect_ios_devices()
    device_connected = bool(usb_devices or remote_devices)
    
    # Get names and identifiers of non-Apple native apps
    apps = []
    if usb_devices:
        apps = [(process.name, process.identifier) for process in usb_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    elif remote_devices:
        apps = [(process.name, process.identifier) for process in remote_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    
    return render_template('index.html', static_reports=static_reports, dynamic_reports=dynamic_reports, device_connected=device_connected, apps=apps)

@routes.route('/dynamic_analyzer')
def dynamic_analyzer():
    """Page for dynamic analysis."""
    dynamic_reports = [f for f in os.listdir(os.path.join(RESULTS_FOLDER, 'dynamic')) if f.endswith('.html')]
    
    # Detect connected iOS devices
    output, usb_devices, remote_devices = detect_ios_devices()
    device_connected = bool(usb_devices or remote_devices)
    
    # Get names and identifiers of non-Apple native apps
    apps = []
    if usb_devices:
        apps = [(process.name, process.identifier) for process in usb_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    elif remote_devices:
        apps = [(process.name, process.identifier) for process in remote_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    
    # List available scripts
    scripts = list_scripts()

    return render_template('dynamic_analyzer.html', dynamic_reports=dynamic_reports, device_connected=device_connected, apps=apps, scripts=scripts)

@routes.route('/run_dynamic_analysis', methods=['POST'])
def run_dynamic_analysis():
    """Run dynamic analysis on the iOS device."""
    identifier = request.form.get('identifier')
    if not identifier:
        return "No identifier provided", 400

    # Detect connected iOS devices
    output, usb_devices, remote_devices = detect_ios_devices()
    device_connected = bool(usb_devices or remote_devices)
    
    # Get names and identifiers of non-Apple native apps
    apps = []
    if usb_devices:
        apps = [(process.name, process.identifier) for process in usb_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    elif remote_devices:
        apps = [(process.name, process.identifier) for process in remote_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]

    # Validar que el identificador esté en la lista de aplicaciones identificadas
    valid_identifiers = [app[1] for app in apps]  # Lista de identificadores válidos
    if identifier not in valid_identifiers:
        return "Invalid identifier provided", 400

    script_path = os.path.join('resilience_tests', 'ios_dynamic_analysis.py')

    # Run the dynamic analysis script with the provided identifier
    try:
        result = subprocess.run(['python', script_path, identifier], check=True, capture_output=True, text=True)
        dynamic_analysis_results = result.stdout  # Get script output
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while running the script: {e}\n"
        error_message += f"stdout: {e.stdout}\n"
        error_message += f"stderr: {e.stderr}\n"
        return error_message, 500

    # Split the results into parts and take the first three
    results_parts = dynamic_analysis_results.split('---split---')
    if len(results_parts) < 3:
        return "Error: Not enough results to generate the report", 500

    results1, results2, results3 = results_parts[:3]

    # Generate HTML report
    html_report = generate_dynamic_analysis_report(identifier, results1.splitlines(), results2.splitlines(), results3.splitlines(), url_for)

    # Save HTML report to a file
    html_report_path = save_html_report(html_report, identifier, RESULTS_FOLDER, 'dynamic')
 
    return "", 204

@routes.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload."""
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        return redirect(url_for('routes.index'))
    return redirect(request.url)

@routes.route('/view_report/<path:filename>')
def view_report(filename):
    """Display the uploaded file report."""
    report_path = os.path.join(RESULTS_FOLDER, filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=False)
    return "Report not found", 404

@routes.route('/run_test/masvs_resilience_ios.py', methods=['POST'])
def run_test():
    """Run the specified test script."""
    if 'file' not in request.files:
        return "", 204
    
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename, ALLOWED_EXTENSIONS):
        return "", 204

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    script_path = os.path.join('resilience_tests', 'masvs_resilience_ios.py')

    # Measure script execution time
    start_time = time.time()
    try:
        result = subprocess.run(['python', script_path, filename], check=True, capture_output=True, text=True)
        analysis_results = json.loads(result.stdout)  # Convert JSON output to dictionary
    except subprocess.CalledProcessError as e:
        return "", 204
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution time for script masvs_resilience_ios.py: {execution_time:.2f} seconds")

    # Generate HTML report
    html_report = generate_html_report(filename, analysis_results, url_for)

    # Save HTML report to a file
    save_html_report(html_report, filename, RESULTS_FOLDER, 'static')

    return "", 204

@routes.route('/preview_report/<filename>')
def preview_report(filename):
    """Preview the generated HTML report."""
    report_path = os.path.join(RESULTS_FOLDER, filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=False)
    return "Report not found", 404