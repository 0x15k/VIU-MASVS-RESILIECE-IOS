import sys
import os
from flask import Blueprint, render_template, request, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import subprocess
import json
import time
from config import UPLOAD_FOLDER, RESULTS_FOLDER, ALLOWED_EXTENSIONS
from utils import allowed_file, save_html_report, generate_html_report

# Add 'resilience_tests' directory to PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'resilience_tests'))

from connection import detect_ios_devices

routes = Blueprint('routes', __name__)

@routes.route('/')
def index():
    """Main page listing generated reports and showing device status."""
    generated_reports = [f for f in os.listdir(RESULTS_FOLDER) if f.endswith('.html')]
    
    # Detect connected iOS devices
    output, usb_devices, remote_devices = detect_ios_devices()
    device_connected = bool(usb_devices or remote_devices)
    
    # Get names and identifiers of non-Apple native apps
    apps = []
    if usb_devices:
        apps = [(process.name, process.identifier) for process in usb_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    elif remote_devices:
        apps = [(process.name, process.identifier) for process in remote_devices[0].enumerate_applications() if not process.identifier.startswith("com.apple.")]
    
    return render_template('index.html', files=generated_reports, device_connected=device_connected, apps=apps)

@routes.route('/run_dynamic_analysis', methods=['POST'])
def run_dynamic_analysis():
    """Run dynamic analysis on the iOS device."""
    identifier = request.form.get('identifier')
    if not identifier:
        return "No identifier provided", 400

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

    # Generate HTML report
    html_report = generate_html_report(identifier, {}, dynamic_analysis_results, url_for)

    # Save HTML report to a file
    html_report_path = save_html_report(html_report, identifier, RESULTS_FOLDER)

    # Return a success message or redirect to another page
    return "Dynamic analysis completed successfully"

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

@routes.route('/view_report/<filename>')
def view_report(filename):
    """Display the uploaded file report."""
    report_path = os.path.join(RESULTS_FOLDER, filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=False)
    else:
        return "Report not found", 404

@routes.route('/run_test/masvs_resilience_ios.py', methods=['POST'])
def run_test():
    """Run the specified test script."""
    if 'file' not in request.files:
        return "", 204
    file = request.files['file']
    if file.filename == '':
        return "", 204
    if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
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
    html_report_path = save_html_report(html_report, filename, RESULTS_FOLDER)

    # Return no content
    return "", 204

@routes.route('/preview_report/<filename>')
def preview_report(filename):
    """Preview the generated HTML report."""
    report_path = os.path.join(RESULTS_FOLDER, filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=False)
    else:
        return "Report not found", 404