from werkzeug.utils import secure_filename
import os

def allowed_file(filename, allowed_extensions):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_html_report(html_content, filename, results_folder, report_type):
    """Save HTML content to a file."""
    valid_filename = secure_filename(filename)
    report_folder = os.path.join(results_folder, report_type)
    os.makedirs(report_folder, exist_ok=True)
    html_report_path = os.path.join(report_folder, f'{valid_filename}.html')
    
    try:
        with open(html_report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    except IOError as e:
        print(f"Error saving HTML report: {e}")
        return None
    
    return html_report_path

def compliance_color(percentage):
    """Calculate the color based on the compliance percentage."""
    red = int((100 - percentage) * 2.55)
    green = int(percentage * 2.55)
    return f'rgb({red},{green},0)'

def generate_html_report(filename, analysis_results, url_for):
    """Generate a vulnerability report in HTML format."""
    clean_filename = filename.replace('|', '')
    compliance_percentage = analysis_results[-1]['compliance_percentage']
    color = compliance_color(compliance_percentage)

    formatted_report = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Reporte de Análisis Estático de {clean_filename}</title>
        <link rel="stylesheet" href="{url_for('static', filename='report_style.css', _external=True)}">
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="htext">Anális Estático de {clean_filename}</h1>
            </div>
            <div class="report-section">
                <h2>Análisis de resultados</h2>
                <div class="percentage-ring">
                    <div class="circle" style="background-color: {color};">
                        <div class="mask full" style="transform: rotate({compliance_percentage * 1.8}deg);"></div>
                        <div class="mask half">
                            <div class="fill" style="transform: rotate({compliance_percentage * 1.8}deg);"></div>
                        </div>
                        <div class="inside-circle">{compliance_percentage:.2f}%</div>
                    </div>
                </div>
    """

    for result in analysis_results[:-1]:  # Excluye el último elemento que es el porcentaje de cumplimiento
        if isinstance(result, str):
            formatted_report += """
            <div class="test-result">
                <div class="wrapped-text">
            """
            for line in result.split('\n'):
                if line.strip() and "Detectando dispositivos iOS" not in line and "No se encontraron dispositivos iOS" not in line:
                    formatted_report += f'<p class="wrapped-text">{line}</p>'
            formatted_report += "</div></div>"

    formatted_report += """
            </div>
        </div>
    </body>
    </html>
    """

    return formatted_report

def generate_dynamic_analysis_report(identifier, results1, results2, results3, url_for):
    """Generate a dynamic analysis report in HTML format."""
    clean_identifier = identifier.replace('|', '')

    # Inicia el contenido del reporte HTML
    formatted_report = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Dynamic Analysis Report for {clean_identifier}</title>
        <link rel="stylesheet" href="{url_for('static', filename='report_style.css', _external=True)}">
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="htext">Reporte de Análisis Dinámico de {clean_identifier}</h1>
            </div>
    """
    formatted_report += """
        
    <div class="report-frame">
       <h2>MASVS-RESILIENCE-4</h2>
        <p><strong id="control">La aplicación aplica técnicas de análisis antidinámico</strong></p>
        <p>
            <strong id="description">Descripción: </strong> A veces, el análisis estático puro es muy difícil y lleva mucho tiempo, por lo que suele ir de la mano del análisis dinámico. Observar y manipular una aplicación durante el tiempo de ejecución hace mucho más fácil descifrar su comportamiento.
        </p>
        <br>
        <p>
            <strong id="description">Control: </strong> Este control pretende dificultar al máximo la realización de análisis dinámicos, así como impedir la instrumentación dinámica que podría permitir a un atacante modificar el código en tiempo de ejecución.
        </p>
    """
    # Añade la sección del primer análisis
    formatted_report += """
            <div class="analysis-frame">
                <h2>Testing Anti-Debugging Detection</h2>
                <div class="console-container">
                    <div class="console-header">
                        <div class="buttons">
                            <div class="button close"></div>
                            <div class="button minimize"></div>
                            <div class="button maximize"></div>
                        </div>
                        <div class="title">Terminal</div>
                    </div>
                    <div class="console-output">
    """
    for line in results1:
        if line.strip():
            formatted_report += f'{line}\n'
    formatted_report += """
                    </div>
                </div>
            </div>
    """

    # Añade la sección del segundo análisis
    formatted_report += """
            <div class="analysis-frame">
                <h2>Testing whether the App is Debuggable</h2>
                <div class="console-container">
                    <div class="console-header">
                        <div class="buttons">
                            <div class="button close"></div>
                            <div class="button minimize"></div>
                            <div class="button maximize"></div>
                        </div>
                        <div class="title">Terminal</div>
                    </div>
                    <div class="console-output">
    """
    for line in results2:
        if line.strip():
            formatted_report += f'{line}\n'
    formatted_report += """
                    </div>
                </div>
            </div>
    """

    # Añade la sección del tercer análisis
    formatted_report += """
            <div class="analysis-frame">
                <h2>Testing Reverse Engineering Tools Detection</h2>
                <div class="console-container">
                    <div class="console-header">
                        <div class="buttons">
                            <div class="button close"></div>
                            <div class="button minimize"></div>
                            <div class="button maximize"></div>
                        </div>
                        <div class="title">Terminal</div>
                    </div>
                    <div class="console-output">
    """
    for line in results3:
        if line.strip():
            formatted_report += f'{line}\n'
    formatted_report += """
                    </div>
                </div>
            </div>
        </div>
    </div>
    </body>
    </html>
    """

    return formatted_report

def list_scripts(directory='resilience_tests/scripts'):
    """Lista todos los scripts disponibles en el directorio dado."""
    try:
        return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    except FileNotFoundError:
        print(f"Error: No se pudo encontrar el directorio {directory}")
        return []