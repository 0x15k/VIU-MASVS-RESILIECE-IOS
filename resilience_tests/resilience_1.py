import os
import zipfile
import r2pipe

def list_files(directory):
    """List all files in the given directory."""
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

def extract_ipa(ipa_path, extract_to):
    """Extract the IPA file directly to the extract_to directory."""
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)
    
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    
    return extract_to

def find_binaries(extracted_folder):
    """Find all binaries inside the extracted .app folder."""
    binaries = []
    app_folder = os.path.join(extracted_folder, 'Payload')
    for root, dirs, files in os.walk(app_folder):
        for dir_name in dirs:
            if dir_name.endswith('.app'):
                # Construct path to the .app directory
                app_path = os.path.join(root, dir_name)
                # Look for the binary file (it should be the name of the .app folder without extension)
                binary_name = dir_name.rsplit('.', 1)[0]  # Remove the .app extension
                binary_path = os.path.join(app_path, binary_name)
                if os.path.isfile(binary_path):
                    binaries.append(binary_path)
    return binaries

def analyze_with_r2(binary_path):
    """Analyze the binary with radare2 using r2pipe."""
    analysis_output = ""
    try:
        # Open the binary with r2pipe
        r2 = r2pipe.open(binary_path)
        
        # Run radare2 commands
        r2.cmd('e bin.relocs.apply=true')
        r2.cmd('aaa')
        output = r2.cmd('iz~+jail')
        
        # Check if the output contains "Jail" or "jail"
        if "Jail" in output or "jail" in output:
            analysis_output += f"Se encontró una referencia a 'Jail' o 'jail' en {binary_path}:\n{output}\n"
        else:
            analysis_output += f"No se encontró ninguna referencia a 'Jail' o 'jail' en {binary_path}.\n"
        
        # Close the r2pipe session
        r2.quit()
        
    except Exception as e:
        analysis_output += f"An unexpected error occurred with {binary_path}: {e}\n"

    return analysis_output

def main(output_file):
    binary_directory = 'resilience_tests/binary'  # Updated directory where the IPA files are located
    extract_base_dir = 'resilience_tests/extracted'  # Base directory to extract the IPA files

    # Ensure the directories exist
    if not os.path.exists(binary_directory):
        os.makedirs(binary_directory)
    if not os.path.exists(extract_base_dir):
        os.makedirs(extract_base_dir)

    # List IPA files in the binary directory
    files = list_files(binary_directory)
    if not files:
        return "No files found in the binary directory."

    extracted_dirs = []
    for ipa_file in files:
        ipa_path = os.path.join(binary_directory, ipa_file)
        specific_extract_to = os.path.join(extract_base_dir, os.path.splitext(ipa_file)[0])
        
        # Extract IPA file
        extract_ipa(ipa_path, specific_extract_to)
        extracted_dirs.append(specific_extract_to)

    if not extracted_dirs:
        return "No IPA files were extracted."

    selected_dir = extracted_dirs[0]  # Analyze the first extracted directory

    # Find the binaries
    binaries = find_binaries(selected_dir)
    if not binaries:
        return f"No binaries found in {selected_dir}."

    # Analyze binaries and store output in results
    results = ""
    for binary_path in binaries:
        results += analyze_with_r2(binary_path)

    # Ensure the results directory exists
    results_dir = os.path.dirname(output_file)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    # Save results to file
    with open(output_file, 'w') as f:
        f.write(results)

    return f"Analysis results saved to {output_file}."

if __name__ == '__main__':
    output_file = 'resilience_tests/results/analysis_results.txt'  # Path to save the analysis results
    print(main(output_file))
