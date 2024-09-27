import os
import zipfile
import r2pipe
import sys
import subprocess
import xml.etree.ElementTree as ET
import json

def masvs_test(func):
    """Decorador para marcar las funciones de prueba de MASVS."""
    func.is_masvs_test = True
    return func

def list_files(directory):
    """Lista todos los archivos en el directorio dado."""
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

def extract_ipa(ipa_path, extract_to):
    """Extrae el archivo IPA directamente al directorio extract_to."""
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)
    
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    
    return extract_to

def find_binaries(extracted_folder):
    """Encuentra todos los binarios dentro de la carpeta .app extraída."""
    binaries = []
    app_folder = os.path.join(extracted_folder, 'Payload')
    for root, dirs, _ in os.walk(app_folder):
        for dir_name in dirs:
            if dir_name.endswith('.app'):
                # Construye la ruta al directorio .app
                app_path = os.path.join(root, dir_name)
                # Busca el archivo binario (debe ser el nombre de la carpeta .app sin extensión)
                binary_name = dir_name.rsplit('.', 1)[0]  # Elimina la extensión .app
                binary_path = os.path.join(app_path, binary_name)
                if os.path.isfile(binary_path):
                    binaries.append(binary_path)
    return binaries

@masvs_test
def test_jailbreak_detection(r2):
    """Prueba de detección de Jailbreak."""
    analysis_output = ""
    passed = 0
    
    # Verifica símbolos relacionados con "jail" usando is~+jail
    output = r2.cmd('is~+jail')
    if "Jail" in output or "jail" in output:
        analysis_output += f"Radare2 encontró símbolos relacionado con 'Jailbreak':\n{output}\n"
    else:
        passed += 1
    
    # Verifica cadenas relacionadas con "jail" usando iz~+jail
    output = r2.cmd('iz~+jail')
    if "Jail" in output or "jail" in output:
        analysis_output += f"Radare2 encontró cadenas relacionada con 'Jailbreak':\n{output}\n"
    else:
        passed += 1
    
    if passed == 2:
        analysis_output += "Radare2 NO encontró ningún símbolo ni cadena relacionada con 'Jailbreak'.\n"
    
    return analysis_output, passed

@masvs_test
def test_app_signed(binary_path):
    """Prueba si la app está firmada correctamente verificando archivos específicos."""
    analysis_output = ""
    passed = 0
    app_dir = os.path.dirname(binary_path)
    
    # Rutas a verificar
    code_signature_dir = os.path.join(app_dir, '_CodeSignature')
    code_resources_file = os.path.join(code_signature_dir, 'CodeResources')
    info_plist_file = os.path.join(app_dir, 'Info.plist')
    embedded_mobileprovision_file = os.path.join(app_dir, 'embedded.mobileprovision')
    
    # Verifica la existencia de cada ruta
    if os.path.isdir(code_signature_dir) and \
       os.path.isfile(code_resources_file) and \
       os.path.isfile(info_plist_file) and \
       os.path.isfile(embedded_mobileprovision_file):
        analysis_output += "El IPA está firmado correctamente. Se encontraron todos los archivos y directorios necesarios.\n"
        passed += 1
    else:
        analysis_output += "El IPA no está firmado correctamente. Faltan uno o más archivos o directorios necesarios:\n"
        if not os.path.isdir(code_signature_dir):
            analysis_output += "- No se encontró el directorio _CodeSignature.\n"
        if not os.path.isfile(code_resources_file):
            analysis_output += "- No se encontró el archivo _CodeSignature/CodeResources.\n"
        if not os.path.isfile(info_plist_file):
            analysis_output += "- No se encontró el archivo Info.plist.\n"
        if not os.path.isfile(embedded_mobileprovision_file):
            analysis_output += "- No se encontró el archivo embedded.mobileprovision.\n"
    
    return analysis_output, passed

@masvs_test
def test_debugging_code(binary_path):
    """Prueba de código de depuración y registro de errores verbosos."""
    analysis_output = ""
    passed = 0
    try:
        # Ejecuta la herramienta ldid para verificar código de depuración y registro de errores verbosos
        ldid_path = os.path.join('tools', 'ldid.exe')
        result = subprocess.run([ldid_path, '-e', binary_path], capture_output=True, text=True)
        if result.stderr:
            analysis_output += f"Errores de ldid:\n{result.stderr}\n"
        
        # Divide la salida en múltiples documentos XML
        xml_docs = result.stdout.split('<?xml version="1.0" encoding="UTF-8"?>')
        processed_docs = set()
        for xml_doc in xml_docs:
            if xml_doc.strip():
                xml_doc = '<?xml version="1.0" encoding="UTF-8"?>' + xml_doc
                if xml_doc in processed_docs:
                    continue
                processed_docs.add(xml_doc)
                try:
                    root = ET.fromstring(xml_doc)
                    get_task_allow = False
                    elements = list(root.iter())
                    for i, elem in enumerate(elements):
                        if elem.tag == 'key' and elem.text == 'get-task-allow':
                            if i + 1 < len(elements) and elements[i + 1].tag == 'true':
                                get_task_allow = True
                                break
                    
                    if get_task_allow:
                        analysis_output += "El IPA tiene habilitada la depuración\nLa opción 'get-task-allow' está presente y configurada como 'true' en el binario.\n"
                    else:
                        analysis_output += "La opción 'get-task-allow' puede NO estar presente o está configurada como 'false' en el binario.\n"
                        passed += 1
                except ET.ParseError as e:
                    analysis_output += f"Error al analizar el documento XML: {e}\n"
    except Exception as e:
        analysis_output += f"Ocurrió un error al ejecutar ldid en {binary_path}: {e}\n"
    
    return analysis_output, passed

@masvs_test
def test_debugging_symbols(r2):
    """Prueba de detección de símbolos de depuración."""
    analysis_output = ""
    passed = 0
    
    # Verifica símbolos relacionados con "debug" usando is~+debug
    output = r2.cmd('is~+debug')
    if "Debug" in output or "debug" in output:
        analysis_output += f"Radare2 encontró símbolos relacionados con 'Debug':\n{output}\n"
    else:
        passed += 1
    
    # Verifica cadenas relacionadas con "debug" usando iz~+debug
    output = r2.cmd('iz~+debug')
    if "Debug" in output or "debug" in output:
        analysis_output += f"Radare2 encontró cadenas relacionadas con 'Debug':\n{output}\n"
    else:
        passed += 1
    
    if passed == 2:
        analysis_output += "Radare2 NO encontró ningún símbolo ni cadena relacionada con 'Debug'.\n"
    
    return analysis_output, passed

# Variables globales para acumulación
passed_subtests = 0

def analyze_with_r2(binary_path):
    """Analiza el binario con radare2 usando r2pipe."""
    global passed_subtests
    analysis_results = {}
    # Número total de pruebas y subpruebas (comentarios informativos)
    # total_tests = 4
    # total_subtests = 6
    passed_subtests = 0  # Reinicia el contador de subpruebas pasadas

    try:
        # Ajusta PATH para incluir el directorio con r2r.exe
        radare2_dir = os.path.join('tools', 'radare', 'bin')
        os.environ['PATH'] = radare2_dir + os.pathsep + os.environ['PATH']
        
        # Abre el binario con r2pipe
        r2 = r2pipe.open(binary_path)
        
        # Ejecuta comandos de radare2
        r2.cmd('e bin.relocs.apply=true')
        r2.cmd('aaa')
        
        # Realiza las pruebas MASVS
        for _, func in globals().items():
            if callable(func) and getattr(func, 'is_masvs_test', False):
                if 'r2' in func.__code__.co_varnames:
                    result, passed = func(r2)
                    analysis_results[format_test_name(func.__name__)] = result
                    passed_subtests += passed
                else:
                    result, passed = func(binary_path)
                    analysis_results[format_test_name(func.__name__)] = result
                    passed_subtests += passed
        
        # Cierra la sesión de r2pipe
        r2.quit()
        
    except Exception as e:
        analysis_results['error'] = f"Ocurrió un error inesperado con {binary_path}: {e}\n"

    # Calcular el porcentaje de cumplimiento
    # Pesos de cada subprueba
    test_1_1 = 12.5
    test_1_2 = 12.5
    test_2 = 25
    test_3 = 25
    test_4_1 = 12.5
    test_4_2 = 12.5

    # Suma de los pesos de las subpruebas pasadas
    suma = (test_1_1 if passed_subtests >= 1 else 0) + \
           (test_1_2 if passed_subtests >= 2 else 0) + \
           (test_2 if passed_subtests >= 3 else 0) + \
           (test_3 if passed_subtests >= 4 else 0) + \
           (test_4_1 if passed_subtests >= 5 else 0) + \
           (test_4_2 if passed_subtests >= 6 else 0)

    compliance_percentage = suma
    analysis_results['compliance_percentage'] = compliance_percentage

    return analysis_results

def format_test_name(test_name):
    """Formatea el nombre de la prueba para que sea más legible."""
    return test_name.replace('_', ' ').title()

def main(ipa_file):
    binary_directory = 'resilience_tests/binary'  # Directorio donde se encuentran los archivos IPA
    extract_base_dir = 'resilience_tests/extracted'  # Directorio base para extraer los archivos IPA

    # Asegura que los directorios existan
    if not os.path.exists(binary_directory):
        os.makedirs(binary_directory)
    if not os.path.exists(extract_base_dir):
        os.makedirs(extract_base_dir)

    ipa_path = os.path.join(binary_directory, ipa_file)
    specific_extract_to = os.path.join(extract_base_dir, os.path.splitext(ipa_file)[0])
    
    # Extrae el archivo IPA
    extract_ipa(ipa_path, specific_extract_to)

    # Encuentra los binarios
    binaries = find_binaries(specific_extract_to)
    if not binaries:
        print(f"No se encontraron binarios en {specific_extract_to}.")
        return

    # Analiza los binarios y muestra los resultados
    for binary_path in binaries:
        results = analyze_with_r2(binary_path)
        print(json.dumps(results, indent=4))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python masvs_resilience_ios.py <archivo_ipa>")
        sys.exit(1)
    ipa_file = sys.argv[1]
    main(ipa_file)