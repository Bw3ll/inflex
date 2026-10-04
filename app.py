# I have disabled Windows Defender from checking the uploads folder, as a result live malware can sit there with no issues. 
# This is only for testing purposes and should be re-enabled in production or real use cases.
# 
# To disable go to Windows Security > Virus & threat protection > Manage settings > Exclusions 
# > Add or remove exclusions > Add an exclusion > Folder > Select the uploads folder in this project.

import datetime
from datetime import datetime, timezone
import hashlib
import threading
import json
import os
from pathlib import Path
import requests
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, Blueprint, send_file, abort
import uuid
from concurrent.futures import ProcessPoolExecutor
# from flask_socketio import SocketIO
# from static_analysis import analyzer
from ingest.ingest import ingest_file
from werkzeug.utils import secure_filename

import time
import subprocess
import requests
import zipfile
import shutil
import smtplib
from CAPE.cape_results_merge import extract_dynamic_features
from static_analysis.function_simularity import update_similarity_across_reports_folder

from elastic.elastic import MalwareAnalysisIndexer

UPLOAD_FOLDER = os.path.abspath("uploads")
RESULTS_FOLDER = os.path.abspath("results")
ALLOWED_EXTENSIONS = {"bat","exe", "dll", "elf", "bin", "txt", "vbs", "vbe", "wsf", "wsh", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "pdf", "zip", "7z", "gz", "tar"}

# Raw/non-document VBA project artifacts are not supported by the current OLE/VBA toolchain. Reject them before analysis rather than allowing them
# to enter the pipeline and fail later. Both .rvba and .rbva are included because samples have been encountered using those non-standard suffixes.
UNSUPPORTED_VBA_EXTENSIONS = {
    "rvba", "rbva", "vba", "bas", "cls", "frm", "frx", "vbp", "vbproj"
}

# Config file path
CONFIG_FILE = Path("config.json")

def _load_max_concurrent_processes():
    """Load the upload worker cap early, before the Flask settings helpers are defined."""
    default_cap = 5
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            cap = int(config.get("max_concurrent_processes", default_cap))
            # Avoid invalid values or accidental resource exhaustion.
            return max(1, min(cap, 64))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
        print(f"Unable to read max_concurrent_processes from config; using {default_cap}: {e}")
    return default_cap

# Module-level process pool for parallel file uploads.
# The configured cap is read at application startup; changing it requires an app restart.
MAX_CONCURRENT_PROCESSES = _load_max_concurrent_processes()
UPLOAD_EXECUTOR = ProcessPoolExecutor(max_workers=MAX_CONCURRENT_PROCESSES)

# Job tracking dictionary
JOB_TRACKER = {}

def start_elasticsearch_if_needed():
    """Start Elasticsearch if it's not already running."""
    try:
        # Try to connect to Elasticsearch
        response = requests.get("https://localhost:9200", verify=False, timeout=5)
        if response.status_code == 200:
            print("Elasticsearch is already running.")
            return
    except requests.exceptions.RequestException:
        pass  # Not running, start it

    print("Starting Elasticsearch...")
    try:
        # Start Elasticsearch in background
        subprocess.Popen(
            [r"C:\elasticsearch\elasticsearch-9.2.3\bin\elasticsearch.bat"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        # Wait a bit for it to start
        time.sleep(10)
        print("Elasticsearch started.")
    except Exception as e:
        print(f"Failed to start Elasticsearch: {e}")


# Create Blueprint
settings_bp = Blueprint('settings', __name__)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(RESULTS_FOLDER).mkdir(exist_ok=True)

# Initialize Socket.IO (threading mode works without eventlet/gevent)
# socketio = SocketIO(app, async_mode='threading')


@app.route("/")
def dashboard():
    """Dashboard: JS fetches data via /api/results — no server-side query needed."""
    return render_template("index.html")


def get_file_extension(filename):
    """Return a normalized extension without the leading period."""
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def is_unsupported_vba_file(filename):
    """Return True for raw/non-document VBA formats the OLE toolchain cannot analyze."""
    return get_file_extension(filename) in UNSUPPORTED_VBA_EXTENSIONS


def allowed_file(filename):
    return get_file_extension(filename) in ALLOWED_EXTENSIONS


# Analysis progress stages with percentages
ANALYSIS_STAGES = {
    "queued": {"label": "Queued", "percent": 0},
    "ingesting": {"label": "Ingesting file", "percent": 5},
    "static_analysis": {"label": "Static analysis", "percent": 10},
    "static_pe_parsing": {"label": "PE parsing", "percent": 20},
    "static_hashes": {"label": "Computing hashes", "percent": 25},
    "static_imports": {"label": "Extracting imports", "percent": 30},
    "static_strings": {"label": "Analyzing strings", "percent": 35},
    "static_yara": {"label": "YARA scanning", "percent": 40},
    "static_disassembly": {"label": "Disassembly", "percent": 45},
    "static_completed": {"label": "Static analysis complete", "percent": 50},
    "submitting_to_cape": {"label": "Submitting to CAPE", "percent": 60},
    "waiting_for_cape": {"label": "Waiting for CAPE results", "percent": 70},
    "processing_cape": {"label": "Processing CAPE results", "percent": 85},
    "completed": {"label": "Completed", "percent": 100},
    "failed": {"label": "Failed", "percent": 0}
}


def _update_job_progress(job_id, status, emit=True):
    """Update job progress and optionally emit socket event."""
    if job_id in JOB_TRACKER:
        JOB_TRACKER[job_id]["status"] = status
        JOB_TRACKER[job_id]["progress"] = ANALYSIS_STAGES.get(status, {}).get("percent", 0)
        JOB_TRACKER[job_id]["stage_label"] = ANALYSIS_STAGES.get(status, {}).get("label", status)
        JOB_TRACKER[job_id]["last_update"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        # if emit:
        #     try:
        #         # socketio.emit('job_update', JOB_TRACKER[job_id])
        #     except Exception:
        #         pass


def _any_jobs_still_running():
    for job in JOB_TRACKER.values():
        if job.get("status") not in ("completed", "failed"):
            return True
    return False


def _on_job_done(job_id, future):
    SIMILARITY_POSTPROCESS_LOCK = threading.Lock()
    try:
        result_path = future.result()
        
        # Store result path before updating progress
        JOB_TRACKER[job_id]["result_path"] = result_path
        _update_job_progress(job_id, "static_completed")

        fp = JOB_TRACKER[job_id].get("filepath")  # TODO: May need to make this an uploads folder instead of a file so that CAPE can handle all of the new samples instead of one at a time

        if fp and os.path.exists(fp):
            with open(fp, "rb") as f:
                JOB_TRACKER[job_id]["sha256"] = hashlib.sha256(f.read()).hexdigest()

        # ---- CAPE INTEGRATION ----
        config = load_config()

        if config.get("cape_enabled"):
            _update_job_progress(job_id, "submitting_to_cape")

            task_id = submit_to_cape(fp, config)

            _update_job_progress(job_id, "waiting_for_cape")

            wait_for_cape_completion(task_id, config)

            _update_job_progress(job_id, "processing_cape")

            cape_report = fetch_cape_report(task_id, config)

            merge_dynamic_into_existing_result(result_path, cape_report)

            _update_job_progress(job_id, "completed")
        else:
            _update_job_progress(job_id, "completed")

            # --- POSTPROCESS SIMILARITY AFTER ALL JOBS COMPLETE ---
        if not _any_jobs_still_running():
            if SIMILARITY_POSTPROCESS_LOCK.acquire(blocking=False):
                try:
                    print("[*] Batch complete: running similarity postprocessing...")
                    update_similarity_across_reports_folder(
                        reports_dir=RESULTS_FOLDER,
                        min_overlap=3,
                        overwrite=True
                    )
                    print("[+] Similarity postprocessing complete.")
                except Exception as e:
                    print(f"[!] Similarity postprocessing failed: {e}")
                finally:
                    SIMILARITY_POSTPROCESS_LOCK.release()

    except Exception as e:
        _update_job_progress(job_id, "failed")
        JOB_TRACKER[job_id]["error"] = str(e)

    # try:
    #     # socketio.emit('job_update', JOB_TRACKER[job_id])
    # except Exception:
    #     pass

def _create_job(filename, filepath):
    """Create a new tracking job for file upload/analysis."""
    job_id = str(uuid.uuid4())
    JOB_TRACKER[job_id] = {
        "job_id": job_id,
        "filename": filename,
        "filepath": filepath,
        "status": "ingesting",
        "progress": ANALYSIS_STAGES["ingesting"]["percent"],
        "stage_label": ANALYSIS_STAGES["ingesting"]["label"],
        "result_path": None,
        "sha256": None,
        "error": None,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    return job_id


@app.route("/uploads")
def uploads_page():
    """Page for uploading files."""
    config = get_config()
    return render_template("file_upload.html", config=config)


@app.route("/search")
def search_page():
    """Page for searching files."""
    return render_template("file_search.html")


@app.route("/graph")
def graph_page():
    """Page for graphing files."""
    samples = []
    functionSimilarity = {}
    results_dir = Path("results")

    for json_file in results_dir.glob("*_normalized.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            sha256 = data['ingest_analysis']['sha256']
            family = data.get('family', {}).get('identified_family', 'unknown')
            # Get date
            vt = data.get('threat_intelligence', {}).get('VirusTotal', {}).get(sha256, {})
            creation_date_ts = vt.get('creation_date')
            if creation_date_ts:
                date = datetime.fromtimestamp(creation_date_ts).strftime('%Y-%m-%d')
            else:
                mtime_str = data['ingest_analysis']['original_mtime']
                # Parse ISO format
                date = datetime.fromisoformat(mtime_str.replace('Z', '+00:00')).strftime('%Y-%m-%d')
            # For type, from verdict
            verdict = data.get('verdict', {}).get('verdict', 'unknown')
            if 'mal' in verdict.lower():
                type_ = 'malware'
            elif 'benign' in verdict.lower():
                type_ = 'benign'
            else:
                type_ = 'suspicious'
            confidence = data.get('verdict', {}).get('confidence', 0.5)
            samples.append({
                'id': sha256[:8],  # short id
                'hash': sha256,
                'family': family,
                'type': type_,
                'date': date,
                'confidence': confidence
            })
        except Exception as e:
            print(f"Error processing {json_file}: {e}")

    # For similarity
    shared_dir = results_dir / 'shared_functions'
    if shared_dir.exists():
        for sf_file in shared_dir.glob("*_shared_functions.json"):
            try:
                with open(sf_file, 'r') as f:
                    sf_data = json.load(f)
                source_hash = Path(sf_data['source_binary'].split()[0]).stem
                for match in sf_data['matches']:
                    match_hash = Path(match['binary_id'].split()[0]).stem
                    if match_hash != source_hash:
                        sim = match['similarity_jaccard']
                        if source_hash not in functionSimilarity:
                            functionSimilarity[source_hash] = {}
                        functionSimilarity[source_hash][match_hash] = sim
                        # bidirectional
                        if match_hash not in functionSimilarity:
                            functionSimilarity[match_hash] = {}
                        functionSimilarity[match_hash][source_hash] = sim
            except Exception as e:
                print(f"Error processing {sf_file}: {e}")

    return render_template("file_graph.html", samples=samples, functionSimilarity=functionSimilarity)


@app.route("/settings")
def settings_page():
    """Page for settings configuration."""
    return render_template("settings.html")


# TODO: This will need to go to the cape file and do the processing there depending on the options
def submit_to_cape(filepath, config):
    cape_url = config["cape_url"].rstrip("/")
    headers = {}
    if config.get("cape_api_key"):
        headers["Authorization"] = f"Token {config['cape_api_key']}"

    with open(filepath, "rb") as f:
        files = {"file": f}
        response = requests.post(
            f"{cape_url}/apiv2/tasks/create/file/",
            headers=headers,
            files=files,
            timeout=60
        )

    if response.status_code != 200:
        raise Exception(f"CAPE submission failed: {response.text}")

    return response.json()["task_id"]


def wait_for_cape_completion(task_id, config):
    cape_url = config["cape_url"].rstrip("/")
    headers = {}
    if config.get("cape_api_key"):
        headers["Authorization"] = f"Token {config['cape_api_key']}"

    timeout = config.get("cape_timeout", 120)
    start = time.time()

    while time.time() - start < timeout:
        response = requests.get(
            f"{cape_url}/apiv2/tasks/view/{task_id}/",
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            status = response.json()["task"]["status"]
            if status == "reported":
                return True

        time.sleep(5)

    raise TimeoutError("CAPE analysis timed out")


def fetch_cape_report(task_id, config):
    cape_url = config["cape_url"].rstrip("/")
    headers = {}
    if config.get("cape_api_key"):
        headers["Authorization"] = f"Token {config['cape_api_key']}"

    response = requests.get(
        f"{cape_url}/apiv2/tasks/report/{task_id}/",
        headers=headers,
        timeout=60
    )

    if response.status_code != 200:
        raise Exception("Failed to fetch CAPE report")

    return response.json()


def merge_dynamic_into_existing_result(result_path, cape_json):
    with open(result_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    dynamic_features = extract_dynamic_features(cape_json)

    data["dynamic_analysis"] = {
        "raw_cape_report": cape_json,
        "dynamic_features": dynamic_features
    }

    data.setdefault("analysis_timestamps", {})
    data["analysis_timestamps"]["dynamic_analysis"] = (
        datetime.utcnow().isoformat() + "Z"
    )

    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Also update the normalized JSON file if it exists
    normalized_path = result_path.replace(".json", "_normalized.json")
    if os.path.exists(normalized_path):
        with open(normalized_path, "r", encoding="utf-8") as f:
            normalized_data = json.load(f)
        
        normalized_data["dynamic_analysis"] = data["dynamic_analysis"]
        normalized_data.setdefault("analysis_timestamps", {})
        normalized_data["analysis_timestamps"]["dynamic_analysis"] = data["analysis_timestamps"]["dynamic_analysis"]
        
        with open(normalized_path, "w", encoding="utf-8") as f:
            json.dump(normalized_data, f, indent=2)
        
        print(f"[+] Updated normalized report with dynamic analysis: {normalized_path}")


def extract_zip_with_7z(filepath, extract_to, password=None):
    """Extract ZIP file using 7z command line tool."""
    # Find 7z executable
    possible_paths = [
        r"C:\\Program Files\\7-Zip\\7z.exe",
        r"C:\\Program Files (x86)\\7-Zip\\7z.exe"
    ]
    seven_z_path = None
    for path in possible_paths:
        if os.path.exists(path):
            seven_z_path = path
            break
    
    if not seven_z_path:
        raise Exception("7z is not installed. Please install 7-Zip from https://www.7-zip.org/")
    
    # First, list the contents to get namelist
    cmd = [seven_z_path, 'l', '-slt']
    if password:
        cmd.append('-p' + password)
    cmd.append(filepath)
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Failed to list archive contents: {result.stderr}")
    
    # Parse the output to get file list
    lines = result.stdout.split('\n')
    namelist = []
    for line in lines:
        if line.startswith('Path = '):
            path = line[7:].strip()
            if path and not path.endswith('/') and path != os.path.basename(filepath):
                namelist.append(path)
    
    # Now extract
    cmd = [seven_z_path, 'x', '-y']
    if password:
        cmd.append('-p' + password)
    cmd.extend([filepath, '-o' + extract_to])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Failed to extract archive: {result.stderr}")
    
    return namelist


@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if is_unsupported_vba_file(file.filename):
        ext = get_file_extension(file.filename)
        return jsonify({
            "error": (
                f"Unsupported VBA file type '.{ext}'. "
                "INFLEX currently supports VBA analysis only through supported "
                "document/script formats; raw or non-document VBA project artifacts "
                "are not supported by the underlying analysis tools."
            )
        }), 415

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Save file to uploads/
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        config = load_config()

        if filename.lower().endswith(('.zip', '.7z')):
            # Handle archive extraction
            password = request.form.get('password')
            try:
                namelist = extract_zip_with_7z(filepath, app.config["UPLOAD_FOLDER"], password)
                job_ids = []
                rejected_files = []
                for member in namelist:
                    extracted_path = os.path.join(app.config["UPLOAD_FOLDER"], member)
                    if not os.path.isfile(extracted_path):
                        continue

                    if is_unsupported_vba_file(member):
                        rejected_files.append({
                            "filename": member,
                            "reason": "Unsupported raw/non-document VBA file type"
                        })
                        continue

                    job_id = _create_job(member, extracted_path)
                    future = UPLOAD_EXECUTOR.submit(ingest_file, extracted_path, config.get('stego_enabled'))
                    future.add_done_callback(lambda fut, jid=job_id: _on_job_done(jid, fut))
                    job_ids.append(job_id)

                if not job_ids and rejected_files:
                    return jsonify({
                        "error": "Archive contains only unsupported VBA file types",
                        "rejected_files": rejected_files
                    }), 415

                return jsonify({
                    "job_ids": job_ids,
                    "rejected_files": rejected_files,
                    "message": (
                        "Archive extracted and supported files queued for analysis"
                        if rejected_files else
                        "Archive extracted and files queued for analysis"
                    )
                }), 202
            except Exception as e:
                return jsonify({"error": f"Failed to extract archive: {str(e)}"}), 400
        else:
            # Normal file
            job_id = _create_job(filename, filepath)
            future = UPLOAD_EXECUTOR.submit(ingest_file, filepath, config.get('stego_enabled'))
            future.add_done_callback(lambda fut, jid=job_id: _on_job_done(jid, fut))
            
            return jsonify({
                "job_ids": [job_id],
                "filename": filename,
                "status": "processing",
                "message": "File queued for analysis"
            }), 202  # 202 Accepted

    return jsonify({"error": "Invalid file type"}), 400


# @app.route("/results/<filename>")
# def results_file(filename):
#     """Serve raw JSON results if needed."""
#     return send_from_directory(RESULTS_FOLDER, filename)
@app.route("/results/<path:filename>")
def serve_results(filename):
    normalized = filename.replace("\\", "/").lstrip("/")
    # if any(part in ("..", "") for part in normalized.split("/")):
    #     abort(404)

    return send_from_directory(RESULTS_FOLDER, normalized)

@app.route("/api/job/<job_id>", methods=["GET"])
def get_job_status(job_id): 
    """Check the status of an uploaded file analysis job."""
    if job_id not in JOB_TRACKER:
        return jsonify({"error": "Job not found"}), 404
    
    job = JOB_TRACKER[job_id]
    return jsonify({
        "job_id": job_id,
        "filename": job["filename"],
        "status": job["status"],
        "progress": job.get("progress", 0),
        "stage_label": job.get("stage_label", ""),
        "result_path": job["result_path"],
        "sha256": job["sha256"],
        "error": job["error"]
    })


@app.route("/api/jobs/active", methods=["GET"])
def get_active_jobs():
    """Get all active (non-completed) jobs with time-based progress estimation."""
    active_jobs = []
    now = datetime.now(timezone.utc)
    
    for job_id, job in JOB_TRACKER.items():
        if job.get("status") not in ["completed", "failed"]:
            job_data = {
                "job_id": job_id,
                "filename": job["filename"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "stage_label": job.get("stage_label", ""),
                "created_at": job.get("created_at", ""),
                "error": job.get("error")
            }
            
            # Show 'Analyzing...' as the stage label during static analysis
            if job.get("status") in ("ingesting", "static_analysis"):
                job_data["stage_label"] = "Analyzing..."
            
            active_jobs.append(job_data)
    
    # Sort by creation time, newest first
    active_jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(active_jobs)


@app.route("/api/results")
def get_results():
    results = []
    try:
        indexer = MalwareAnalysisIndexer(
            es_host="localhost",
            es_port=9200,
            index_name="malware-analysis",
            username="elastic",
            password="aPxO=wlWoOnnyWCflf=6"
        )
        # Only fetch the fields the dashboard needs — avoids pulling full
        # raw_data blobs (disassembly, strings, CAPE dumps, etc.) for all 212 docs.
        query = {
            "query": {"match_all": {}},
            "size": 10000,
            "_source": [
                "raw_data.ingest_analysis.sha256",
                "raw_data.ingest_analysis.original_path",
                "raw_data.ingest_analysis.ingest_timestamp",
                "raw_data.static_analysis",
                "raw_data.threat_intelligence.VirusTotal",
                "raw_data.threat_intelligence.family.identified_family",
                "raw_data.threat_intelligence.verdict.family",
                "raw_data.family.identified_family",
            ]
        }
        es_results = indexer.search(query)
        results = [hit["_source"]["raw_data"] for hit in es_results.get("hits", {}).get("hits", [])]
    except Exception as e:
        print(f"Elasticsearch not available, falling back to local files: {e}")
        seen_base = set()
        if os.path.exists(RESULTS_FOLDER):
            for fname in os.listdir(RESULTS_FOLDER):
                # prefer normalized files, skip duplicates
                if fname.endswith("_normalized.json"):
                    base = fname.replace("_normalized.json", "")
                    seen_base.add(base)
                elif fname.endswith(".json"):
                    base = fname[:-5]
                    if base in seen_base:
                        # already have normalized version
                        continue
                else:
                    continue

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
    # First check normalized json (new ingest path produces these)
    normalized_path = os.path.join(RESULTS_FOLDER, f"{hash}_normalized.json")
    if os.path.exists(normalized_path):
        try:
            with open(normalized_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # normalized files are already in the final schema so just return them directly
            return jsonify(data)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON in normalized report"}), 500

    # Try Elasticsearch
    try:
        indexer = MalwareAnalysisIndexer(
            es_host="localhost",
            es_port=9200,
            index_name="malware-analysis",
            username="elastic",
            password="aPxO=wlWoOnnyWCflf=6"
        )
        doc = indexer.get_by_hash(hash)
        if doc:
            print("RETURNING FROM ELASTICSEARCH")
            return jsonify(doc["raw_data"])
    except Exception as e:
        print(f"Elasticsearch not available for report {hash}: {e}")

    # Fall back to local files

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
                # Check if this is a normalized format file
                if "format_type" in full_report:
                    return jsonify(full_report)
                # Extract sections from integrated JSON
                merged_data["hash"] = full_report.get("hash", {})
                merged_data["file_info"] = full_report.get("file_info", {})
                merged_data["pe_structure"] = full_report.get("pe_structure", {})
                merged_data["disassembly"] = full_report.get("disassembly", {})
                merged_data["static_analysis"] = full_report.get("static_analysis", {})

                merged_data["threat_intelligence"] = full_report.get("threat_intelligence", {})

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

    # return jsonify(merged_data)
    print(full_report)
    return jsonify(full_report)

# Default configuration
DEFAULT_CONFIG = {
    "vt_api_key": "",
    "vt_paid_key": False,
    "abuseipdb_paid_key": False,
    "abusech_paid_key": False,
    "hybrid_api_key": "",
    "openai_api_key": "",
    "cape_enabled": False,
    "stego_enabled": True,
    "cape_url": "http://localhost:8000",
    "cape_api_key": "",  # TODO ADD THIS KEY ONCE ACCOUNTS HAVE BEEN GRANTED
    "cape_timeout": 120,
    "upload_path": "./uploads",
    "results_path": "./results",
    "yara_path": "./yara_rules",
    "auto_analyze": True,
    "delete_after_analysis": False,
    "max_file_size": 50,
    "max_concurrent_processes": 5,
    "email_notifications": False,
    "smtp_server": "",
    "smtp_port": 587,
    "email_address": "",
    "email_password": "",
    "notify_high_risk": True,
    "default_zip_password": "infected"
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
        
        # Validate concurrent process cap. Changed value will take effect after the application is restarted.
        try:
            process_cap = int(updated_config.get('max_concurrent_processes', 5))
        except (TypeError, ValueError):
            return jsonify({'error': 'max_concurrent_processes must be an integer'}), 400
        if not 1 <= process_cap <= 64:
            return jsonify({'error': 'max_concurrent_processes must be between 1 and 64'}), 400
        updated_config['max_concurrent_processes'] = process_cap

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
            restart_required = process_cap != MAX_CONCURRENT_PROCESSES
            return jsonify({
                'message': 'Settings saved successfully' + ('; restart required for process cap change' if restart_required else ''),
                'config': updated_config,
                'restart_required': restart_required
            })
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


app.register_blueprint(settings_bp)

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
    start_elasticsearch_if_needed()
    # Use Socket.IO runner so we can emit real-time events
    app.run(port=9000, debug=True)
    # socketio.run(app, host='0.0.0.0', port=5000, debug=True)
