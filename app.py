# This is the main API for the FLASK server
import hashlib

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from pathlib import Path
import os
import json
# from static_analysis import analyzer
from ingest.ingest import ingest_file
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = "uploads"
RESULTS_FOLDER = "results"
ALLOWED_EXTENSIONS = {"exe", "dll", "elf", "bin", "txt", "vbs", "vbe", "wsf", "wsh", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "pdf", "zip", "7z", "gz", "tar"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(RESULTS_FOLDER).mkdir(exist_ok=True)


@app.route("/")
def dashboard():
    """Dashboard: show list of analyzed files + graphs later."""
    files = list(Path(RESULTS_FOLDER).glob("*.json"))
    analyses = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as j:
                analyses.append(json.load(j))
        except Exception as e:
            print(f"Failed to read {f}: {e}")

    return render_template("index.html", analyses=analyses)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/uploads")
def uploads_page():
    """Page for uploading files."""
    return render_template("file_upload.html")


@app.route("/search")
def search_page():
    """Page for searching files."""
    return render_template("file_search.html")


@app.route("/graph")
def graph_page():
    """Page for graphing files."""
    return render_template("file_graph.html")


@app.route("/settings")
def settings_page():
    """Page for settings configuration."""
    return render_template("settings.html")


@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Save file to uploads/
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Hash file to create unique result filename
        with open(filepath, "rb") as f:
            file_bytes = f.read()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # Run analysis
        try:
            # result_path = analyzer.run(filepath)  # should return path to results JSON
            result_path = ingest_file(filepath) 
            return jsonify({
                "filename": filename,
                "sha256": sha256_hash,
                "result_file": result_path
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Invalid file type"}), 400


@app.route("/results/<filename>")
def results_file(filename):
    """Serve raw JSON results if needed."""
    return send_from_directory(RESULTS_FOLDER, filename)


@app.route("/api/results")
def get_results():
    # TODO make this only once for each file combining each set of data
    results = []
    if os.path.exists(RESULTS_FOLDER):
        for fname in os.listdir(RESULTS_FOLDER):
            if fname.endswith(".json"): # or fname.endswith("_mitre.json"):
                path = os.path.join(RESULTS_FOLDER, fname)
                try:
                    with open(path, "r") as f:
                        data = json.load(f)
                        results.append(data)
                except Exception as e:
                    print(f"Error reading {fname}: {e}")
    return jsonify(results)


@app.route("/report")
def report_page():
    return send_from_directory("templates", "report.html")


# TODO: This is not using the right json field layout
@app.route("/api/report/<hash>")
def get_report(hash):
    # New integrated JSON path
    report_path = os.path.join(RESULTS_FOLDER, f"{hash}.json")

    # Legacy paths (for backwards compatibility)
    extracted_path = os.path.join(RESULTS_FOLDER, f"{hash}_extracted.json")
    mitre_path = os.path.join(RESULTS_FOLDER, f"{hash}_extracted_mitre.json")
    description_path = os.path.join(RESULTS_FOLDER, f"{hash}_description.json")

    merged_data = {}

    # Try loading new integrated JSON first
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            try:
                full_report = json.load(f)


                # Extract sections from integrated JSON
                merged_data["hash"] = full_report.get("hash", {})
                merged_data["file_info"] = full_report.get("file_info", {})
                merged_data["pe_structure"] = full_report.get("pe_structure", {})
                merged_data["disassembly"] = full_report.get("disassembly", {})
                merged_data["static_analysis"] = full_report.get("static_analysis", {})

                # Add legacy fields if they exist
                merged_data["extracted"] = full_report.get("extracted", {})
                merged_data["mitre"] = full_report.get("mitre", {})
                merged_data["description"] = full_report.get("description", {})

            except json.JSONDecodeError:
                merged_data["error"] = "Invalid JSON in report"

    # Fall back to legacy separate files if integrated JSON doesn't exist
    else:
        # Load raw report if it exists
        if os.path.exists(extracted_path):
            with open(extracted_path, "r") as f:
                try:
                    merged_data["extracted"] = json.load(f)
                except json.JSONDecodeError:
                    merged_data["extracted"] = {"error": "Invalid JSON in extracted report"}

        # Load extracted (MITRE mapping) if it exists
        if os.path.exists(mitre_path):
            with open(mitre_path, "r") as f:
                try:
                    merged_data["mitre"] = json.load(f)
                except json.JSONDecodeError:
                    merged_data["mitre"] = {"error": "Invalid JSON in raw report"}

        # Load extracted (description) if it exists
        if os.path.exists(description_path):
            with open(description_path, "r") as f:
                try:
                    merged_data["description"] = json.load(f)
                except json.JSONDecodeError:
                    merged_data["description"] = {"error": "Invalid JSON in raw report"}

    # If no data found, return 404
    if not merged_data or merged_data.get("error"):
        return jsonify({"error": "Report not found"}), 404

    return jsonify(merged_data)



import json
import os
from pathlib import Path
from flask import Blueprint, request, jsonify
import requests

# Create Blueprint
settings_bp = Blueprint('settings', __name__)

# Config file path
CONFIG_FILE = Path("config.json")

# Default configuration
DEFAULT_CONFIG = {
    "vt_api_key": "",
    "hybrid_api_key": "",
    "openai_api_key": "",
    "cape_enabled": False,
    "cape_url": "http://localhost:8000",
    "cape_api_key": "",
    "cape_timeout": 120,
    "upload_path": "./uploads",
    "results_path": "./results",
    "yara_path": "./yara_rules",
    "auto_analyze": True,
    "delete_after_analysis": False,
    "max_file_size": 50,
    "email_notifications": False,
    "smtp_server": "",
    "smtp_port": 587,
    "email_address": "",
    "email_password": "",
    "notify_high_risk": True
}


def load_config():
    """Load configuration from config.json"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Merge with defaults to ensure all keys exist
                return {**DEFAULT_CONFIG, **config}
        except Exception as e:
            print(f"Error loading config: {e}")
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(config):
    """Save configuration to config.json"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def create_directories(config):
    """Create necessary directories if they don't exist"""
    directories = [
        config.get('upload_path', './uploads'),
        config.get('results_path', './results'),
        config.get('yara_path', './yara_rules')
    ]
    
    for directory in directories:
        if directory:
            Path(directory).mkdir(parents=True, exist_ok=True)

# This is all currently just mocked out and not truly connected to the pipeline nor all of the correct fields present
@settings_bp.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current settings"""
    config = load_config()
    
    # Don't send sensitive data in plain text (mask passwords/keys)
    safe_config = config.copy()
    if safe_config.get('vt_api_key'):
        safe_config['vt_api_key'] = '***' + safe_config['vt_api_key'][-4:] if len(safe_config['vt_api_key']) > 4 else '***'
    if safe_config.get('hybrid_api_key'):
        safe_config['hybrid_api_key'] = '***' + safe_config['hybrid_api_key'][-4:] if len(safe_config['hybrid_api_key']) > 4 else '***'
    if safe_config.get('openai_api_key'):
        safe_config['openai_api_key'] = '***' + safe_config['openai_api_key'][-4:] if len(safe_config['openai_api_key']) > 4 else '***'
    if safe_config.get('cape_api_key'):
        safe_config['cape_api_key'] = '***' + safe_config['cape_api_key'][-4:] if len(safe_config['cape_api_key']) > 4 else '***'
    if safe_config.get('email_password'):
        safe_config['email_password'] = '***'
    
    return jsonify(safe_config)


@settings_bp.route('/api/settings', methods=['POST'])
def update_settings():
    """Update settings"""
    try:
        new_config = request.json
        
        # Validate required fields
        if not isinstance(new_config, dict):
            return jsonify({'error': 'Invalid configuration format'}), 400
        
        # Load current config
        current_config = load_config()
        
        # Only update masked passwords/keys if they've changed
        for key in ['vt_api_key', 'hybrid_api_key', 'openai_api_key', 'cape_api_key', 'email_password']:
            if key in new_config:
                value = new_config[key]
                # If value starts with ***, keep the old value
                if value and value.startswith('***'):
                    new_config[key] = current_config.get(key, '')
        
        # Merge with current config
        updated_config = {**current_config, **new_config}
        
        # Validate paths
        for path_key in ['upload_path', 'results_path', 'yara_path']:
            if path_key in updated_config and updated_config[path_key]:
                try:
                    Path(updated_config[path_key]).resolve()
                except Exception:
                    return jsonify({'error': f'Invalid path for {path_key}'}), 400
        
        # Save configuration
        if save_config(updated_config):
            # Create directories
            create_directories(updated_config)
            return jsonify({'message': 'Settings saved successfully', 'config': updated_config})
        else:
            return jsonify({'error': 'Failed to save configuration'}), 500
            
    except Exception as e:
        print(f"Error updating settings: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/test', methods=['POST'])
def test_connections():
    """Test various API connections"""
    config = load_config()
    results = {}
    
    # Test VirusTotal API
    if config.get('vt_api_key'):
        try:
            headers = {'x-apikey': config['vt_api_key']}
            response = requests.get(
                'https://www.virustotal.com/api/v3/users/current',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                results['VirusTotal'] = {'status': 'Success', 'message': 'API key is valid'}
            else:
                results['VirusTotal'] = {'status': 'Failed', 'message': f'HTTP {response.status_code}'}
        except Exception as e:
            results['VirusTotal'] = {'status': 'Failed', 'message': str(e)}
    else:
        results['VirusTotal'] = {'status': 'Skipped', 'message': 'No API key configured'}
    
    # Test CAPE API
    if config.get('cape_enabled') and config.get('cape_url'):
        try:
            cape_url = config['cape_url'].rstrip('/')
            headers = {}
            if config.get('cape_api_key'):
                headers['Authorization'] = f'Token {config["cape_api_key"]}'
            
            response = requests.get(
                f'{cape_url}/apiv2/cuckoo/status/',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                results['CAPEv2'] = {'status': 'Success', 'message': 'Connected to CAPE instance'}
            else:
                results['CAPEv2'] = {'status': 'Failed', 'message': f'HTTP {response.status_code}'}
        except Exception as e:
            results['CAPEv2'] = {'status': 'Failed', 'message': str(e)}
    else:
        results['CAPEv2'] = {'status': 'Skipped', 'message': 'CAPE not enabled'}
    
    # Test OpenAI API
    if config.get('openai_api_key'):
        try:
            headers = {'Authorization': f'Bearer {config["openai_api_key"]}'}
            response = requests.get(
                'https://api.openai.com/v1/models',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                results['OpenAI'] = {'status': 'Success', 'message': 'API key is valid'}
            else:
                results['OpenAI'] = {'status': 'Failed', 'message': f'HTTP {response.status_code}'}
        except Exception as e:
            results['OpenAI'] = {'status': 'Failed', 'message': str(e)}
    else:
        results['OpenAI'] = {'status': 'Skipped', 'message': 'No API key configured'}
    
    # Test SMTP
    if config.get('email_notifications') and config.get('smtp_server'):
        try:
            import smtplib
            server = smtplib.SMTP(config['smtp_server'], config.get('smtp_port', 587), timeout=10)
            server.starttls()
            if config.get('email_address') and config.get('email_password'):
                server.login(config['email_address'], config['email_password'])
            server.quit()
            results['Email'] = {'status': 'Success', 'message': 'SMTP connection successful'}
        except Exception as e:
            results['Email'] = {'status': 'Failed', 'message': str(e)}
    else:
        results['Email'] = {'status': 'Skipped', 'message': 'Email notifications not configured'}
    
    # Test directory access
    try:
        for key in ['upload_path', 'results_path', 'yara_path']:
            path = Path(config.get(key, ''))
            if path and not path.exists():
                path.mkdir(parents=True, exist_ok=True)
        results['Directories'] = {'status': 'Success', 'message': 'All directories accessible'}
    except Exception as e:
        results['Directories'] = {'status': 'Failed', 'message': str(e)}
    
    return jsonify({'results': results})


@settings_bp.route('/api/settings/reset', methods=['POST'])
def reset_settings():
    """Reset settings to defaults"""
    try:
        if save_config(DEFAULT_CONFIG.copy()):
            create_directories(DEFAULT_CONFIG)
            return jsonify({'message': 'Settings reset to defaults'})
        else:
            return jsonify({'error': 'Failed to reset configuration'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Helper function to get config (can be imported by other modules)
def get_config():
    """Get the current configuration"""
    return load_config()


# Initialize config file if it doesn't exist
if not CONFIG_FILE.exists():
    save_config(DEFAULT_CONFIG.copy())
    create_directories(DEFAULT_CONFIG)


from flask import Flask, send_file
import os

@app.route('/download/<filename>')
def download_file(filename):
    # Construct the full path to the file
    # It's recommended to use a dedicated directory for downloadable files
    # and join paths securely to prevent directory traversal vulnerabilities.
    downloads_folder = os.path.join(app.root_path, 'uploads')
    file_path = os.path.join(downloads_folder, filename)

    # Ensure the file exists before attempting to send it
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found!", 404 # Or render an error template


if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=5000, debug=True)
