from werkzeug.utils import secure_filename
import os

def allowed_file(filename, allowed_extensions):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_html_report(html_content, filename, results_folder):
    """Save HTML content to a file."""
    valid_filename = secure_filename(filename)
    html_report_path = os.path.join(results_folder, f'{valid_filename}.html')
    
    with open(html_report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_report_path

def format_test_name(test_name):
    """Format the test name to be more readable."""
    return test_name.replace('_', ' ').title()

def compliance_color(percentage):
    """Calculate the color based on the compliance percentage."""
    red = int((100 - percentage) * 2.55)
    green = int(percentage * 2.55)
    return f'rgb({red},{green},0)'

def generate_html_report(filename, analysis_results, url_for):
    """Generate a vulnerability report in HTML format."""
    clean_filename = filename.replace('|', '')
    compliance_percentage = analysis_results.get('compliance_percentage', 0)
    color = compliance_color(compliance_percentage)

    formatted_report = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>MASVS Test Report for {clean_filename}</title>
        <link rel="stylesheet" href="{url_for('static', filename='report_style.css', _external=True)}">
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="htext">MASVS Test Report for {clean_filename}</h1>
            </div>
            <div class="report-section">
                <h2>Analysis Results</h2>
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

    for test_name, result in analysis_results.items():
        if test_name == 'compliance_percentage':
            continue
        formatted_test_name = format_test_name(test_name)
        formatted_report += f"""
                <div class="test-result">
                    <h3 class="wrapped-text">{formatted_test_name}</h3>
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