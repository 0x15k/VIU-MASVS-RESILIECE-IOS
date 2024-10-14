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
def test_jailbreak_and_emulator_detection(r2):
    """Prueba de detección de Jailbreak y Emulator"""
    analysis_output = """
    <div class="report-frame">
        <h2>MASVS-RESILIENCE-1</h2>
        <p><strong id="control">La aplicación valida la integridad de la plataforma</strong></p>
        <p>
            <strong id="description">Descripción: </strong> Ejecutarse en una plataforma que ha sido manipulada puede ser muy peligroso para las aplicaciones, ya que esto puede desactivar ciertas características de seguridad, poniendo en riesgo los datos de la aplicación. Confiar en la plataforma es esencial para muchos de los controles MASVS que dependen de que la plataforma sea segura (almacenamiento seguro, biometría, sandboxing, etc.).
        </p>
        <p>
            <strong id="description">Control: </strong> Este control se prueba para validar que el sistema operativo no se ha visto comprometido y que, por tanto, se puede confiar en sus funciones de seguridad.
        </p>
    
        <div class="analysis-frame">
            <h3>Testing Jailbreak Detection</h3>
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
    passed = 0
    
    # Verifica símbolos relacionados con "jail" usando is~+jail
    output = r2.cmd('is~+jailbreak')
    if "Jail" in output or "jail" in output:
        analysis_output += f"Radare2 encontró símbolos relacionado con 'Jailbreak':\n{output}\n"
    else:
        analysis_output += "Radare2 no encontró símbolos relacionados con 'Jailbreak'.\n"
        passed += weights[1]  # Suma el peso 7 si no se encuentra Jailbreak
    
    # Verifica cadenas relacionadas con "jail" usando iz~+jail
    output = r2.cmd('iz~+jailbreak')
    if "Jail" in output or "jail" in output:
        analysis_output += f"Radare2 encontró cadenas relacionada con 'Jailbreak':\n{output}\n"
    else:
        analysis_output += "Radare2 no encontró cadenas relacionadas con 'Jailbreak'.\n"
        passed += weights[2]  # Suma el peso 7 si no se encuentra Jailbreak
    
    analysis_output += "</div></div></div>"  # Cierra los divs de console-output, console-container, analysis-frame y report-frame aquí
    
    analysis_output += """
    <div class="analysis-frame">
        <h3>Testing Emulator Detection</h3>
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
    
    # Inicializa contadores para símbolos y cadenas
    symbols_found = False
    strings_found = False

    # Verifica símbolos relacionados con "emulator" usando is~+emulator
    output = r2.cmd('is~+emulator')
    if "Emulator" in output or "emulator" in output:
        analysis_output += f"Radare2 encontró símbolos relacionados con 'Emulator':\n{output}\n"
        symbols_found = True
    else:
        analysis_output += "Radare2 no encontró símbolos relacionados con 'Emulator'.\n"
        passed += weights[3]  # Incrementa el puntaje si no se encontraron símbolos

    # Verifica cadenas relacionadas con "emulator" usando iz~+emulator
    output = r2.cmd('iz~+emulator')
    if "Emulator" in output or "emulator" in output:
        analysis_output += f"Radare2 encontró cadenas relacionadas con 'Emulator':\n{output}\n"
        strings_found = True
    else:
        analysis_output += "Radare2 no encontró cadenas relacionadas con 'Emulator'.\n"
        passed += weights[4]  # Incrementa el puntaje si no se encontraron cadenas

    # No es necesario verificar ambos juntos ya que cada uno se maneja por separado
        
    analysis_output += "</div></div></div>"  # Cierra los divs de console-output, console-container, analysis-frame y report-frame aquí
        
    analysis_output += "</div>"  # Cierra el div de report-frame aquí
        
    return analysis_output, passed

@masvs_test
def test_file_integrity_and_app_signed(r2, binary_path):
    """Prueba de verificación de integridad del archivo y firma de la app para MASVS-Resilience-2"""
    analysis_output = """
    <div class="report-frame">
        <h2>MASVS-RESILIENCE-2</h2>
        <p><strong id="control">La aplicación garantiza la integridad de la funcionalidad</strong></p>
        <p>
            <strong id="description">Descripción: </strong> Las aplicaciones se ejecutan en un dispositivo controlado por el usuario y, sin las protecciones adecuadas, es relativamente fácil ejecutar una versión modificada localmente (por ejemplo, para hacer trampas en un juego o activar funciones premium sin pagar), o subir una versión pirateada a tiendas de aplicaciones de terceros. 
        <br>
            <strong id="description">Control: </strong> Este control se prueba para verificar la integridad de la funcionalidad de la aplicación evitando modificaciones en el código y los recursos originales.
        </p>
    
        <div class="analysis-frame">
            <h3>Testing File Integrity Check</h3>
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
    passed = 0
    
    try:
        # Reabre el archivo en modo lectura/escritura
        r2.cmd('oo+')
        analysis_output += "Archivo reabierto en modo lectura/escritura.\n"

        # Añadir una nueva sección
        r2.cmd('s 0x1000')  # Ir a una dirección específica
        
        # Escribir "dylib" en esa dirección
        r2.cmd('w dylib')
        analysis_output += 'Se escribió "dylib" en la dirección 0x1000.\n'

        # Verificar que se escribió "dylib"
        dylib_written = r2.cmd('px 5 @ 0x1000')  # Leer solo los primeros 5 bytes que modificaste
        if '64 79 6c 69 62' in dylib_written:  # Verifica que sean los valores hexadecimales de "dylib"
            analysis_output += "Se escribió correctamente la sección 'dylib' en la dirección 0x1000.\n"
        else:
            raise Exception('La sección .dylib no se escribió correctamente.')

        # Añadir un nuevo comando de carga
        r2.cmd('aae')  # Analizar todo
        r2.cmd('af')   # Analizar funciones
        output = r2.cmd('/x 00')  # Buscar espacio libre
        if "0x" in output:
            address = output.split()[0]  # Extrae la primera dirección
            r2.cmd(f's {address}')  # Posicionarse en la dirección encontrada
            r2.cmd('wx 0c000000000000000000000000000000')  # Escribir el nuevo comando de carga

            # Verificar que se escribió el nuevo comando de carga
            load_command_written = r2.cmd(f'px 16 @ {address}')  # Leer solo los 16 bytes escritos
            if '0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' in load_command_written:
                analysis_output += "Nuevo comando de carga escrito correctamente.\n"
            else:
                raise Exception('El nuevo comando de carga no se escribió correctamente.')

        # Guardar los cambios y salir
        r2.quit()

        analysis_output += "La verificación de integridad del archivo se completó correctamente.\n"

    except Exception as e:
        analysis_output += f"Ocurrió un error durante la verificación de integridad del archivo: {e}\n"

        passed += weights[5] 
    
    analysis_output += "</div></div></div>"  # Cierra los divs de console-output, console-container, analysis-frame aquí
    
    # Prueba de firma de la app
    analysis_output += """
    <div class="analysis-frame">
        <h3>Making Sure that the App Is Properly Signed</h3>
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
        passed += weights[6] 
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
    
    analysis_output += "</div></div></div>"  # Cierra los divs de console-output, console-container, analysis-frame aquí
    
    analysis_output += "</div>"  # Cierra el div de report-frame aquí
    
    return analysis_output, passed

@masvs_test
def test_resilience_3(r2, binary_path):
    """Prueba de código de depuración, ofuscación y símbolos de depuración para MASVS-Resilience-3."""
    analysis_output = """
    <div class="report-frame">
        <h2>MASVS-RESILIENCE-3</h2>
        <p><strong id="control">La aplicación aplica mecanismos de análisis antiestáticos.</strong></p>
        <p>
            <strong id="description">Descripción: </strong> Las aplicaciones no deben contener código de depuración, registro de errores verbosos, ni símbolos de depuración en su versión de producción. Además, el código debe estar ofuscado adecuadamente para dificultar el análisis inverso.
        <br>
            <strong id="description">Control: </strong> Este control se prueba para verificar que se impida la comprensión haciendo lo más difícil posible averiguar cómo funciona una aplicación mediante análisis estático.
        
        </p>
    """
    passed = 0

    # Prueba de código de depuración y registro de errores verbosos
    analysis_output += """
    <div class="analysis-frame">
        <h3>Testing for Debugging Code and Verbose Error Logging</h3>
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

    try:
        # Detecta el sistema operativo
        if os.name == 'nt':
            # Windows
            ldid_path = os.path.join('tools', 'ldid.exe')
        else:
            # Linux
            ldid_path = 'ldid'

        # Ejecuta la herramienta ldid para verificar código de depuración y registro de errores verbosos
        analysis_output += f"Ejecutando comando: ldid -e {binary_path}\n"
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

                # Escapar caracteres especiales para mostrar tags XML
                xml_doc_escaped = xml_doc.replace('<', '&lt;').replace('>', '&gt;')

                # Mostrar el contenido del XML
                analysis_output += f"<pre><code>Contenido del XML:\n{xml_doc_escaped}\n</code></pre>"

                try:
                    root = ET.fromstring(xml_doc)
                    get_task_allow = False
                    elements = list(root.iter())
                    for i, elem in enumerate(elements):
                        if elem.tag == 'key' and elem.text == 'get-task-allow':
                            if i + 1 < len(elements):
                                next_elem = elements[i + 1]
                                if next_elem.tag == 'true':
                                    get_task_allow = True
                                    analysis_output += "<pre><code>&lt;true/&gt;\n</code></pre>"
                                elif next_elem.tag == 'false':
                                    analysis_output += "<pre><code>&lt;false/&gt;\n</code></pre>"
                                break
                    if get_task_allow:
                        analysis_output += "El IPA tiene habilitada la depuración\nLa opción 'get-task-allow' está presente y configurada como 'true' en el binario.\n"
                    else:
                        analysis_output += "La opción 'get-task-allow' puede NO estar presente o está configurada como 'false' en el binario.\n"
                        passed += weights[7] 
                except ET.ParseError as e:
                    analysis_output += f"Error al analizar el documento XML: {e}\n"
    except FileNotFoundError as e:
        analysis_output += f"Error: No se encontró la herramienta ldid. Verifica la ruta: {e}\n"
    except Exception as e:
        analysis_output += f"Ocurrió un error al ejecutar ldid en {binary_path}: {e}\n"

    analysis_output += "</div></div></div>"

    # Prueba de verificación de ofuscación
    analysis_output += """
    <div class="analysis-frame">
        <h3>Testing Obfuscation</h3>
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
    # 1. Verificar nombres de clases y métodos
    analysis_output += "<h4>Verificando nombres de clases y métodos</h4>\n"
    class_info_auth = r2.cmd('is~auth')
    class_info_password = r2.cmd('is~password')
    class_info_login = r2.cmd('is~login')
    class_info_user = r2.cmd('is~user')
    
    if "auth" in class_info_auth.split() or "password" in class_info_password.split() or "login" in class_info_login.split() or "user" in class_info_user.split():
        analysis_output += "Se encontraron nombres de clases o métodos descriptivos.\n"
    else:
        analysis_output += "Los nombres de clases y métodos están ofuscados correctamente.\n"
        passed += weights[8] 
    
    # 2. Verificar encriptación de cadenas
    analysis_output += "<h4>Verificando encriptación de cadenas</h4>\n"
    strings_output_auth = r2.cmd('iz~auth')
    strings_output_password = r2.cmd('iz~password')
    strings_output_login = r2.cmd('iz~login')
    strings_output_username = r2.cmd('iz~username')
    
    if "auth" in strings_output_auth.split() or "password" in strings_output_password.split() or "login" in strings_output_login.split() or "username" in strings_output_username.split():
        analysis_output += f'Se encontraron cadenas sensibles no encriptadas: {strings_output_auth}, {strings_output_password}, {strings_output_login}, {strings_output_username}\n'
    else:
        analysis_output += "Las cadenas están encriptadas correctamente.\n"
        passed += weights[9] 
    
    # 3. Verificar ofuscación o encriptación del código crítico
    analysis_output += "<h4>Verificando ofuscación o encriptación del código crítico</h4>\n"
    r2.cmd('aa')  # Analizar todo
    functions_auth = r2.cmd('aflj~auth')
    functions_password = r2.cmd('aflj~password')
    functions_login = r2.cmd('aflj~login')
    
    if "auth" in functions_auth.split() or "password" in functions_password.split() or "login" in functions_login.split():
        analysis_output += f'Se encontraron funciones críticas sin ofuscación: {functions_auth}, {functions_password}, {functions_login}\n'
    else:
        analysis_output += "El código crítico está ofuscado o protegido adecuadamente.\n"
        passed += weights[10] 
    
    analysis_output += "La verificación de ofuscación se completó correctamente.\n"
    r2.quit()
    
    analysis_output += "</div></div></div>"

    # Prueba de detección de símbolos de depuración
    analysis_output += """
    <div class="analysis-frame">
        <h3>Testing for Debugging Symbols</h3>
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
    # Verifica símbolos relacionados con "debug" usando is~+debug
    output = r2.cmd('is~+debug')
    if "Debug" in output or "debug" in output:
        analysis_output += f"Radare2 encontró símbolos relacionados con 'Debug':\n{output}\n"
    else:
        analysis_output += "Radare2 no encontró símbolos relacionados con 'Debug'.\n"
        passed += weights[11] 
    
    # Verifica cadenas relacionadas con "debug" usando iz~+debug
    output = r2.cmd('iz~+debug')
    if "Debug" in output or "debug" in output:
        analysis_output += f"Radare2 encontró cadenas relacionadas con 'Debug':\n{output}\n"
    else:
        analysis_output += "Radare2 no encontró cadenas relacionadas con 'Debug'.\n"
        passed += weights[12] 
    
    if passed == 3:
        analysis_output += "Radare2 NO encontró ningún símbolo ni cadena relacionada con 'Debug'.\n"
    
    analysis_output += "</div></div></div>"

    analysis_output += "</div>"  # Cierra el div de report-frame aquí
    
    return analysis_output, passed

# Diccionario de pesos para cada subprueba
weights = {
    1: 7,
    2: 7,
    3: 7,
    4: 7,
    5: 14,
    6: 15,
    7: 14,
    8: 7,
    9: 5,
    10: 5,
    11: 5,
    12: 7
}

def calculate_compliance_percentage(passed_subtests):
    """Calcula el porcentaje de cumplimiento basado en las subpruebas pasadas."""
    total_weight = sum(weights.values())  # Suma total de los pesos
    return (passed_subtests / total_weight) * 100  # Porcentaje basado en la suma total


def analyze_with_r2(binary_path):
    """Analiza el binario con radare2 usando r2pipe."""
    try:
        # Detecta el sistema operativo y ajusta el ejecutable
        if os.name == 'nt':
            radare2_executable = 'r2.bat'  # Windows
        else:
            radare2_executable = 'r2'  # Linux
        
        # Verifica si radare2 está en el PATH
        if not any(os.access(os.path.join(path, radare2_executable), os.X_OK) for path in os.environ['PATH'].split(os.pathsep)):
            raise EnvironmentError("ERROR: Cannot find radare2 in PATH")
        
        # Abre el binario con r2pipe
        r2 = r2pipe.open(binary_path)
        
        # Ejecuta comandos de radare2
        r2.cmd('e bin.relocs.apply=true')
        r2.cmd('e io.cache=true')
        r2.cmd('aaa')
        
        return r2

    except Exception as e:
        print(f"Error durante el análisis: {e}")
        return None

def run_masvs_tests(r2, binary_path):
    """Realiza las pruebas MASVS."""
    passed_subtests = 0  # Reinicia el contador de subpruebas pasadas

    results = []
    for _, func in globals().items():
        if callable(func) and getattr(func, 'is_masvs_test', False):
            if 'r2' in func.__code__.co_varnames and 'binary_path' in func.__code__.co_varnames:
                result, passed = func(r2, binary_path)
            elif 'r2' in func.__code__.co_varnames:
                result, passed = func(r2)
            else:
                result, passed = func(binary_path)
            results.append(result)  # Aquí solo se guarda el resultado, sin el nombre de la función
            passed_subtests += passed

    return results, passed_subtests

def handle_analysis_results(results, passed_subtests):
    """Maneja los resultados del análisis y calcula el porcentaje de cumplimiento."""
    compliance_percentage = calculate_compliance_percentage(passed_subtests)
    results.append({'compliance_percentage': compliance_percentage})
    return results

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
        r2 = analyze_with_r2(binary_path)
        if isinstance(r2, str):  # Si r2 es un mensaje de error
            print(r2)
            continue
        analysis_results, passed_subtests = run_masvs_tests(r2, binary_path)
        final_results = handle_analysis_results(analysis_results, passed_subtests)
        print(json.dumps(final_results, indent=4))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python masvs_resilience_ios.py <archivo_ipa>")
        sys.exit(1)
    ipa_file = sys.argv[1]
    main(ipa_file)