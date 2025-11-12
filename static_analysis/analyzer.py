# TODO: Be the main driver for the static analysis component, my current file has some personal API keys and we need to create a keys file that is blocked by the Git pulls/pushes
# TODO: Have a config file that sets the IP, API_keys, etc so that way we do not push it to git and can block it
# TODO: Currently this file is doing all of the currently mentioned static analysis and needs to be split for modularity
# TODO: Ensure all the modules are dumping the data to the same places and then we need to consolidate each one into one
#       output file

import hashlib
import os
import re
import pefile
import requests
from pathlib import Path
import sys
import json

from static_analysis import map_to_mitre_i
from AI_integration import writeup_generator


VT_API_KEY = ""  # Put your API key here
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
YARA_RULES_DIR = "./yara_rules"  # Put the YARA rules here

# Try importing yara, but don't crash if it's missing
try:
    import yara
    YARA_AVAILABLE = True
except Exception as e:
    print(f"[!] YARA not available: {e}")
    YARA_AVAILABLE = False


def get_hashes(filepath):
    """Return MD5, SHA1, SHA256 hashes of a file."""
    hashes = {"md5": None, "sha1": None, "sha256": None}
    h_md5, h_sha1, h_sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)

    hashes["md5"] = h_md5.hexdigest()
    hashes["sha1"] = h_sha1.hexdigest()
    hashes["sha256"] = h_sha256.hexdigest()
    return hashes


def get_strings(filepath, min_len=5):
    """Extract printable ASCII strings."""
    pattern = rb"[ -~]{%d,}" % min_len
    with open(filepath, "rb") as f:
        data = f.read()
    return [s.decode("utf-8", errors="ignore") for s in re.findall(pattern, data)]


def get_pe_info(filepath):
    """Extract PE metadata and imports."""
    info = {"imports": [], "sections": []}
    try:
        pe = pefile.PE(filepath)
        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8")
                funcs = [imp.name.decode("utf-8") if imp.name else "ordinal_%s" % imp.ordinal
                         for imp in entry.imports]
                info["imports"].append({"dll": dll, "functions": funcs})

        # Sections
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            size = section.SizeOfRawData
            entropy = section.get_entropy()
            info["sections"].append({"name": name, "size": size, "entropy": entropy})

    except Exception as e:
        info["error"] = str(e)
    return info


def run_yara_scan(file_path: str):
    """
    Run YARA scan if available.
    Otherwise, just print a warning and skip.
    """
    if not YARA_AVAILABLE:
        print(f"[SKIP] Would scan {file_path} with YARA (DLL missing).")
        return None

    try:
        rules = yara.compile(filepath="rules/index.yar")  # adjust the rule path
        matches = rules.match(file_path)
        return matches
    except Exception as e:
        print(f"[!] YARA scan failed: {e}")
        return None


def query_virustotal(sha256_hash):
    """Query VirusTotal for a file hash."""
    if not VT_API_KEY:
        return {"error": "No API key provided"}

    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL.format(sha256_hash)
    resp = requests.get(url, headers=headers)

    if resp.status_code == 200:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {"status": stats, "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}"}
    else:
        return {"error": f"VT query failed: {resp.status_code}"}


def analyze_file(filepath):
    # print(f"[*] Analyzing {filepath}")
    results = {}

    # results["filename"] = os.path.basename(filepath)

    # Hashes
    results["hashes"] = get_hashes(filepath)

    # PE info
    results["pe_info"] = get_pe_info(filepath)

    # Strings
    results["strings"] = get_strings(filepath, min_len=8)[:50]  # show first 50

    # YARA
    results["yara"] = run_yara_scan(filepath)

    # VirusTotal
    results["virustotal"] = query_virustotal(results["hashes"]["sha256"])

    return results


def save_results_to_file(results: dict, out_dir: str = "results"):
    """
    Save analyzer results dict to a JSON file named <sha256>_extracted.json
    in the given out_dir. Creates out_dir if needed.
    Returns the full path to the written file (str).
    """
    # Ensure we have hashes
    hashes = results.get("hashes") or {}
    sha256 = hashes.get("sha256")
    if not sha256:
        # Fallback: build a filename using md5, timestamp, or a safe name
        fallback = hashes.get("md5") or "unknownhash"
        filename = f"{fallback}_extracted.json"
    else:
        # sanitize if needed (sha256 is safe)
        filename = f"{sha256}_extracted.json"

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    file_path = out_path / filename
    # Write JSON pretty-printed
    file_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return str(file_path)


def run(filepath):

    if not os.path.isfile(filepath):
        print("File not found!")
        sys.exit(1)

    results = analyze_file(filepath)
    saved = save_results_to_file(results, out_dir="results")

    # print(json.dumps(results, indent=2))

    filename_without_ext = os.path.splitext(os.path.basename(saved))[0]
    map_to_mitre_i.analyze_file_json(saved, f"results\{filename_without_ext}_mitre.json")

    file_hash = filename_without_ext.split("_")[0]
    # print(file_hash)
    writeup_generator.generate_description(file_hash)
