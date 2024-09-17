import os
import sys
import subprocess
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

# Añadir el directorio 'resilience_tests' al PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'resilience_tests'))

app = Flask(__name__)

UPLOAD_FOLDER = 'resilience_tests/binary'
RESULTS_FOLDER = 'resilience_tests/results'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER

# Asegurarse de que los directorios existen
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

@app.route('/')
def index():
    # Listar los archivos ya subidos
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=uploaded_files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Redirigir a la página de pruebas
        return redirect(url_for('test_page', filename=filename))

@app.route('/test_page/<filename>')
def test_page(filename):
    # Aquí puedes agregar cualquier lógica adicional que necesites para la página de pruebas
    return render_template('test_page.html', filename=filename)

@app.route('/run_test/<script_name>')
def run_test(script_name):
    filename = request.args.get('filename')
    if not filename:
        return "Filename not provided", 400

    script_path = os.path.join('resilience_tests', script_name)
    result_file = os.path.join(app.config['RESULTS_FOLDER'], f'result_{filename}.txt')

    # Asegurarse de que el directorio de resultados existe
    os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

    # Ejecutar el script correspondiente
    try:
        subprocess.run(['python', script_path, script_name, filename, result_file], check=True)
    except subprocess.CalledProcessError as e:
        return f"An error occurred while running the script: {e}", 500

    # Verificar si el archivo de resultados fue creado
    if not os.path.exists(result_file):
        return f"Result file not created: {result_file}", 500

    # Leer el resultado del archivo
    with open(result_file, 'r') as f:
        analysis_result = f.read()

    return render_template('result.html', filename=filename, result=analysis_result)

if __name__ == "__main__":
    app.run(debug=True)