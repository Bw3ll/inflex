# TODO: This will verify the files are the filetypes by looking at magic bytes etc, be able to handle folders, setting
#       up the output file for each sample, getting the file hash, ETC.

import os
import json
import shutil
import hashlib
import time
import tempfile
import mimetypes

import re
from datetime import datetime, timezone
from typing import Any

from parsers.PE_parser import PEStaticAnalyzer
from parsers.ELF_parser import ELFStaticAnalyzer
from parsers.OLE_parser import OLEStaticAnalyzer
from static_analysis.disassembly import process_disassembly
from threat_intelligence.threat_intel import enrich_threat_data
from elastic.elastic import add_file_to_index

# TODO : Expand this mapping as needed and reduce for non-ingestable files

EXTENSION_MAP = {
    "exe": "Portable Executable (EXE)",
    "dll": "Portable Executable (DLL)",
    "pdf": "PDF Document",
    "zip": "ZIP Archive",
    "png": "PNG Image",
    "jpg": "JPEG Image",
    "jpeg": "JPEG Image",
    "gif": "GIF Image",
    "bmp": "Bitmap Image",
    "mp3": "MP3 Audio",
    "mp4": "MP4 Video",
    "elf": "ELF Executable",
    "docx": "Microsoft Office DOCX (VBA Macro Capable)",
    "xlsx": "Microsoft Excel XLSX (VBA Macro Capable)",
    "pptx": "Microsoft PowerPoint PPTX (VBA Macro Capable)",
    "doc": "Microsoft Office DOC (VBA Macro Capable)",
    "xls": "Microsoft Excel XLS (VBA Macro Capable)",
    "ppt": "Microsoft PowerPoint PPT (VBA Macro Capable)",
    "docm": "Microsoft Office DOCM (VBA Macro Enabled)",
    "xlsm": "Microsoft Excel XLSM (VBA Macro Enabled)",
    "pptm": "Microsoft PowerPoint PPTM (VBA Macro Enabled)",
    "7z": "7-Zip Archive",
    "rar": "RAR Archive",
    "tar": "TAR Archive",
    "iso": "ISO Image",
}

MAGIC_SIGNATURES = {
    b"\x4D\x5A": "Portable Executable (EXE)",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\x50\x4B\x03\x04": "ZIP Archive / OOXML Document (VBA Macro Capable)",
    b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": "PNG Image",
    b"\xFF\xD8\xFF": "JPEG Image",
    b"\x47\x49\x46\x38": "GIF Image",
    b"\x42\x4D": "Bitmap Image (BMP)",
    b"\x7F\x45\x4C\x46": "ELF Executable",
    b"\x49\x44\x33": "MP3 Audio (ID3v2)",
    b"\x00\x00\x00\x18\x66\x74\x79\x70": "MP4 (ftyp box)",
    b"\x1F\x8B\x08": "GZIP Archive",
    b"\x52\x61\x72\x21\x1A\x07\x00": "RAR Archive",
    b"\x37\x7A\xBC\xAF\x27\x1C": "7-Zip Archive",
    b"\x75\x73\x74\x61\x72": "TAR Archive",
    b"\x43\x44\x30\x30\x31": "ISO 9660 (CD-ROM)",
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "OLE Compound Document (VBA Macro Capable)",
}

MAGIC_READ_LEN = 64


def compute_sha256(filepath, chunk_size=8192):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def detect_magic(header_bytes):
    if not header_bytes:
        return None, None

    matches = []
    for sig, desc in MAGIC_SIGNATURES.items():
        if header_bytes.startswith(sig):
            matches.append((len(sig), sig, desc))

    if not matches:
        return None, None

    matches.sort(reverse=True)
    _, sig, desc = matches[0]
    return desc, sig.hex().upper()


def get_claimed_type_by_extension(filepath):
    ext = os.path.splitext(filepath)[1].lower().lstrip(".")
    return EXTENSION_MAP.get(ext, "Unknown extension type"), ext


def can_contain_vba_macros(detected_type, claimed_type, extension):
    """
    Determine if a file can contain VBA macros based on:
    - Detected file type (magic bytes)
    - Claimed type (extension)
    - File extension
    
    Returns True if file is a VBA macro-capable format.
    """
    # VBA macro-capable extensions
    vba_extensions = {"doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "xla", "xlam", "ppa", "ppam"}
    
    if extension.lower() in vba_extensions:
        return True
    
    # Check detected type (from magic bytes)
    if detected_type:
        vba_types = {
            "ZIP Archive / OOXML Document (VBA Macro Capable)",
            "OLE Compound Document (VBA Macro Capable)",
            "Microsoft Office DOCX (VBA Macro Capable)",
            "Microsoft Excel XLSX (VBA Macro Capable)",
            "Microsoft PowerPoint PPTX (VBA Macro Capable)",
            "Microsoft Office DOC (VBA Macro Capable)",
            "Microsoft Excel XLS (VBA Macro Capable)",
            "Microsoft PowerPoint PPT (VBA Macro Capable)",
            "Microsoft Office DOCM (VBA Macro Enabled)",
            "Microsoft Excel XLSM (VBA Macro Enabled)",
            "Microsoft PowerPoint PPTM (VBA Macro Enabled)",
        }
        if detected_type in vba_types:
            return True
    
    # Check claimed type
    if claimed_type:
        if "VBA Macro" in claimed_type or "OLE Compound" in claimed_type:
            return True
    
    return False



# Common date formats seen in malware tooling
DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y",
]

ISO_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
)

def normalize_datetime_value(value: Any):
    """
    Normalize a single value into ISO-8601 UTC if it looks like a date.
    Otherwise return value unchanged.
    """
    # Already a datetime
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    # Epoch timestamps
    if isinstance(value, (int, float)):
        # seconds or millis
        try:
            if value > 1e12:  # millis
                dt = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
            elif value > 1e9:  # seconds
                dt = datetime.fromtimestamp(value, tz=timezone.utc)
            else:
                return value
            return dt.isoformat()
        except Exception:
            return value

    # Strings
    if isinstance(value, str):
        s = value.strip()

        # Already ISO
        if ISO_REGEX.match(s):
            return s if s.endswith("Z") else s + "Z"

        # Try known formats
        for fmt in DATE_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue

    return value


def normalize_json(obj: Any):
    """
    Recursively normalize JSON:
    - Dates → ISO-8601 UTC
    - Dicts / Lists walked fully
    """
    if isinstance(obj, dict):
        return {
            k: normalize_json(v)
            for k, v in obj.items()
        }

    if isinstance(obj, list):
        return [normalize_json(v) for v in obj]

    return normalize_datetime_value(obj)


def safe_makedirs(path):
    os.makedirs(path, exist_ok=True)


def atomic_write_json(path, data):
    dirname = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirname, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def process_file(src_path, claimed_type, detected_type):
    """
    Run static analysis and return the analysis data.
    Returns dict with static analysis results, or None if unsupported.
    """
    # Normalize types
    claimed_type = claimed_type or "Unknown"
    detected_type = detected_type or "Unknown"

    # Trust detected_type (magic bytes) more when available
    final_type = detected_type if detected_type != "Unknown" else claimed_type

    if claimed_type != detected_type:
        print(f"[!] Type mismatch: Claimed '{claimed_type}' vs Detected '{detected_type}'")
    else:
        print(f"[+] Type verified: {final_type}")

    # Route to appropriate analyzer
    if final_type == "Portable Executable (EXE)":
        analyzer = PEStaticAnalyzer(src_path)
    elif final_type == "ELF Executable":
        analyzer = ELFStaticAnalyzer(src_path)
    elif final_type == "OLE Compound Document (VBA Macro Capable)" or any(vba_type in final_type for vba_type in ["Microsoft Office", "Microsoft Excel", "Microsoft PowerPoint"]):
        analyzer = OLEStaticAnalyzer(src_path)
    else:
        print(f"[x] Unsupported file type: {final_type}")
        return None
    
    analyzer.analyze()
    # Return the analysis data instead of saving to file
    report = analyzer.get_report() if hasattr(analyzer, 'get_report') else None
    return report

    # TODO: Run regular expressions here, already have this in PE but need to make it general


def ingest_file(src_path, rename_with_hash=True, overwrite=True):
    _, extension = os.path.splitext(src_path)

    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

    uploads_dir = os.path.join(PROJECT_ROOT, "uploads")
    reports_dir = os.path.join(PROJECT_ROOT, "results")

    safe_makedirs(uploads_dir)
    safe_makedirs(reports_dir)

    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Source file not found: {src_path}")

    size_bytes = os.path.getsize(src_path)
    mtime = os.path.getmtime(src_path)

    claimed_type, ext = get_claimed_type_by_extension(src_path)

    with open(src_path, "rb") as f:
        header = f.read(MAGIC_READ_LEN)

    detected_type, matched_signature = detect_magic(header)
    sha256 = compute_sha256(src_path)

    base_name = os.path.basename(src_path)
    dest_name_with_extension = f"{sha256}{extension}" if rename_with_hash else base_name
    dest_name = f"{sha256}" if rename_with_hash else base_name
    dest_path = os.path.join(uploads_dir, dest_name_with_extension)

    if os.path.exists(dest_path) and not overwrite:
        raise ValueError(f"Destination exists: {dest_path}")

    shutil.copy2(src_path, dest_path)

    iso_ts = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    mime_guess, _ = mimetypes.guess_type(src_path)

    can_vba = can_contain_vba_macros(detected_type, claimed_type, ext)

    metadata = {
        "original_path": os.path.abspath(src_path),
        "ingested_path": os.path.abspath(dest_path),
        "filename": dest_name_with_extension,
        "size_bytes": size_bytes,
        "original_mtime": datetime.utcfromtimestamp(mtime).replace(microsecond=0).isoformat() + "Z",
        "ingest_timestamp": iso_ts,
        "extension": ext,
        "claimed_type": claimed_type,
        "detected_type": detected_type or "Unknown",
        "matched_signature_hex": matched_signature,
        "magic_header_hex": header.hex().upper(),
        "sha256": sha256,
        "mime_type_guess": mime_guess,
        "types_match": (claimed_type == detected_type) if detected_type else False,
        "can_contain_vba_macros": can_vba,
    }

    final_json = {
        "ingest_analysis": metadata
    }

    # Normalize everything before writing
    # TODO: Put the normalization in standalone file 
    final_json = normalize_json(final_json)

    json_path = os.path.join(reports_dir, dest_name + ".json")

    # TODO: This is where we need to call the process manager to allow for the threading and multiprocessing
    # All functions now return JSON data instead of modifying files directly

    # Collect results from analysis functions (these can be run in parallel)
    static_analysis_data = process_file(src_path, claimed_type, detected_type)
    if static_analysis_data:
        final_json["static_analysis"] = static_analysis_data

    # run the disassembly and perfile hash code - returns data instead of modifying file
    disassembly_data = process_disassembly(src_path, "results")
    if disassembly_data:
        final_json["disassembly"] = disassembly_data

    # run the dynamic analysis and emulation here
    # TODO: Add dynamic analysis function that returns data

    # run the full normalization with all collected data
    final_json = normalize_json(final_json)

    # run the threat intelligence and get enriched data
    threat_intel_data = enrich_threat_data(sample_data=final_json)
    if threat_intel_data:
        final_json["threat_intelligence"] = threat_intel_data

    # Write the complete normalized JSON once
    atomic_write_json(json_path, final_json)

    # run the DB indexing with the complete data
    add_file_to_index(json_path)

    return json_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest a file and extract metadata.")
    parser.add_argument("file", help="Input file to ingest")
    parser.add_argument("--no-hash-rename", action="store_true", help="Do not prefix filename with SHA-256")
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting files")

    args = parser.parse_args()

    result = ingest_file(
        args.file,
        rename_with_hash=(not args.no_hash_rename),
        overwrite=args.overwrite
    )

    print(json.dumps(result, indent=2))

