from flask import Flask, render_template, request, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import os
import sys
import subprocess
import pdfkit

# Añadir el directorio 'resilience_tests' al PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'resilience_tests'))

# Configuración de la aplicación
UPLOAD_FOLDER = 'resilience_tests/binary'
RESULTS_FOLDER = 'resilience_tests/results'
ALLOWED_EXTENSIONS = {'ipa', 'apk'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER

# Asegurarse de que los directorios existen
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Página principal que lista los archivos subidos."""
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=uploaded_files)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Maneja la subida de archivos."""
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return redirect(url_for('test_page', filename=filename))
    return redirect(request.url)

@app.route('/test_page/<filename>')
def test_page(filename):
    """Página de pruebas para el archivo subido."""
    return render_template('test_page.html', filename=filename)

@app.route('/view_report/<filename>')
def view_report(filename):
    """Muestra el reporte del archivo subido."""
    pdf_report_path = os.path.join(app.config['RESULTS_FOLDER'], f'{filename}.pdf')
    if os.path.exists(pdf_report_path):
        return send_file(pdf_report_path, as_attachment=False)
    else:
        return "Report not found", 404

@app.route('/run_test/<script_name>')
def run_test(script_name):
    """Ejecuta el script de prueba especificado."""
    filename = request.args.get('filename')
    if not filename:
        return "Filename not provided", 400

    script_path = os.path.join('resilience_tests', script_name)

    # Ejecutar el script correspondiente
    try:
        result = subprocess.run(['python', script_path, filename], check=True, capture_output=True, text=True)
        analysis_result = result.stdout
    except subprocess.CalledProcessError as e:
        return f"An error occurred while running the script: {e}", 500

    # Generar el reporte en formato HTML
    html_report = generate_html_report(filename, analysis_result)

    # Convertir el reporte HTML a PDF
    pdf_report_path = convert_html_to_pdf(html_report, filename)

    return send_file(pdf_report_path, as_attachment=True)

def generate_html_report(filename, analysis_result):
    """Genera un reporte de vulnerabilidades en formato HTML."""
    report_lines = analysis_result.split('\n')
    formatted_report = f"""
    <html>
    <head>
        <title>Reporte de Vulnerabilidades</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .container {{ width: 80%; margin: auto; }}
            h1, h2 {{ color: #333; }}
            .report-section {{ margin-bottom: 20px; }}
            .report-section h2 {{ border-bottom: 2px solid #333; padding-bottom: 5px; }}
            .report-section ul {{ list-style-type: none; padding: 0; }}
            .report-section ul li {{ background: #f9f9f9; margin: 5px 0; padding: 10px; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Reporte de Vulnerabilidades para {filename}</h1>
            <div class="report-section">
                <h2>Resultados del Análisis</h2>
                <ul>
    """

    for line in report_lines:
        if line.strip():
            formatted_report += f"<li>{line}</li>"

    formatted_report += """
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

    return formatted_report

def convert_html_to_pdf(html_content, filename):
    """Convierte el contenido HTML a un archivo PDF."""
    pdf_report_path = os.path.join(app.config['RESULTS_FOLDER'], f'{filename}.pdf')
    # Especifica la ruta completa al ejecutable wkhtmltopdf
    config = pdfkit.configuration(wkhtmltopdf='/usr/local/bin/wkhtmltopdf')
    pdfkit.from_string(html_content, pdf_report_path, configuration=config)
    return pdf_report_path

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')