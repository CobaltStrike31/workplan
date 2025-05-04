import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import time
from utils.verification import verify_workflow
from utils.pe_analyzer import analyze_pe
from utils.encryption_tester import test_encryption
from utils.memory_execution import test_memory_execution
from utils.evasion_checker import check_evasion
from utils.cleanup_validator import validate_cleanup

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "opsec_loader_verification_key")
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
        session['verification_id'] = verification_id
        
        # Log the verification request
        result = {
            "id": verification_id,
            "framework_path": framework_path,
            "os_type": os_type,
            "status": "processing",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": {}
        }
        
        # Run the verification (in a real app, you might do this asynchronously)
        try:
            result["results"] = verify_workflow(
                framework_path=framework_path,
                os_type=os_type,
                pe_file_path=filename
            )
            result["status"] = "completed"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        
        session['verification_result'] = result
        
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
    # In a real app, you would retrieve results from a database
    # For this example, we're using session
    stored_id = session.get('verification_id')
    result = session.get('verification_result', {})
    
    if not stored_id or stored_id != verification_id:
        return redirect(url_for('index'))
    
    return render_template('results.html', result=result)

@app.route('/api/verify-component', methods=['POST'])
def verify_component():
    try:
        component = request.json.get('component')
        framework_path = request.json.get('framework_path')
        
        if not component or not framework_path:
            return jsonify({"status": "error", "message": "Component and framework path are required"}), 400
        
        result = {}
        
        if component == 'pe_conversion':
            result = analyze_pe(framework_path)
        elif component == 'encryption':
            result = test_encryption(framework_path)
        elif component == 'memory_execution':
            result = test_memory_execution(framework_path)
        elif component == 'evasion':
            result = check_evasion(framework_path)
        elif component == 'cleanup':
            result = validate_cleanup(framework_path)
        else:
            return jsonify({"status": "error", "message": f"Unknown component: {component}"}), 400
        
        return jsonify({"status": "success", "data": result})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
