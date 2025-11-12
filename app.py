# This is the main API for the FLASK server
import hashlib

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from pathlib import Path
import os
import json
from static_analysis import analyzer
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = "uploads"
RESULTS_FOLDER = "results"
ALLOWED_EXTENSIONS = {"exe"}

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
            result_path = analyzer.run(filepath)  # should return path to results JSON
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
            if fname.endswith("_extracted.json"): # or fname.endswith("_mitre.json"):
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


@app.route("/api/report/<hash>")
def get_report(hash):
    extracted_path = os.path.join(RESULTS_FOLDER, f"{hash}_extracted.json")
    mitre_path = os.path.join(RESULTS_FOLDER, f"{hash}_extracted_mitre.json")
    description_path = os.path.join(RESULTS_FOLDER, f"{hash}_description.json")

    merged_data = {}

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

    # If neither exists, return 404
    if not merged_data:
        return jsonify({"error": "Report not found"}), 404

    # print(merged_data)
    return jsonify(merged_data)


if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=5000, debug=True)  # If you want to bind all IP's to this server so other devices on the same network connect run the app using this configuration

