# TODO: This will verify the files are the filetypes by looking at magic bytes etc, be able to handle folders, setting
#       up the output file for each sample, getting the file hash, ETC.


# This is the resulting format for each ingested file. 
# format_type: "PE"

# ingest_analysis:
#   original_path, filename, size_bytes, extension, mime_type_guess,
#   sha256, sha512, ssdeep, tlsh, crc32, sha3_384, rh_hash
#   submitted_filename, cape_type, clamav, extracted_files_tool

# static_analysis:
#   hashes              (all hashes, deduplicated)
#   basic_info          (filename, file_size, file_type)
#   sections[]          (norm entropy+permissions + CAPE raw_address+characteristics)
#   imports[], symbols, metadata, format_specific
#   security_features   (ASLR, DEP, SEH, CFG, Signed…)
#   strings             (ascii, unicode, interesting{urls,ips,…})
#   yara_matches, mitre_mapping, cape_yara
#   pe_header           (imagebase, entrypoint, dirents, resources, signers…)
#   dotnet              (typerefs, assemblyrefs, assemblyinfo)
#   disassembly         (functions, function_count, similar_binaries…)

# dynamic_analysis:
#   sandbox             (id, machine, platform, duration, malscore, malstatus)
#   behavior            (summary, processes, processtree, anomaly, encryptedbuffers)
#   signatures[]        (CAPE behavioural signatures)
#   ttps[]              (MITRE ATT&CK from CAPE)
#   network             (hosts, domains, dns, http, tcp, udp, icmp…)
#   suricata            (alerts, tls, ssh, fileinfo…)
#   cape_payloads[]     (unpacked payloads)
#   cape_configs[]      (extracted malware configs)
#   extracted_files[]   (de4dot .NET extractions)

# threat_intelligence:
#   VirusTotal, AbuseCH, AbuseIPDB, GoogleSearch, MITRE_ATTACK
#   verdict             (verdict, confidence, override, scores, reasoning)
#   family              (identified_family, confidence, tokens, corpus_matches)

# label: "msil"

import os
import json
import shutil
import hashlib
import time
import tempfile
import mimetypes
from pathlib import Path

import re
from datetime import datetime, timezone
from typing import Any
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor

from parsers.PE_parser import PEStaticAnalyzer
from parsers.ELF_parser import run
from parsers.OLE_analysis.OLE_driver import analyze_file
from parsers.sharem_headless import SharemAnalyzer
from static_analysis.disassembly import process_disassembly
from static_analysis.stegoscan_integration import (  # TODO This will still need to likely be changed to point to the "\extracted_resources" dir and we also need to make that unique to each sample
    ensure_git_installed,
    # ensure_python_installed,
    clone_or_update_repo,
    install_dependencies,
    patch_missing_stegoscan_tools,
    run_stegoscan,
)
from threat_intelligence.threat_intel import enrich_threat_data
from elastic.elastic import add_file_to_index
from postprocessing.postprocessor import normalize 

# TODO : Expand this mapping as needed and reduce for non-ingestable files


# Raw/non-document VBA project artifacts that are not supported by the current
# OLE/VBA analysis toolchain. The web upload layer rejects these first, and
# ingest_file() repeats the check so alternate ingestion paths fail cleanly.
UNSUPPORTED_VBA_EXTENSIONS = {
    "rvba", "rbva", "vba", "bas", "cls", "frm", "frx", "vbp", "vbproj"
}

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
    "vbs": "VBScript",
    "vbe": "VBScript Encoded",
    "hta": "HTML Application (HTA)",
    "7z": "7-Zip Archive",
    "rar": "RAR Archive",
    "tar": "TAR Archive",
    "iso": "ISO Image",
    "bin": "Shellcode Binary",
    "shc": "Shellcode Object",
    "obj": "Object File / Shellcode",
    "o": "Object File / Shellcode",
    "sh": "Shell Script (may contain encoded shellcode)",
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

# Shellcode indicators
SHELLCODE_INDICATORS = [
    # x86/x64 common shellcode patterns
    b"\x55\x89\xe5",  # push rbp; mov rbp, rsp (function prologue)
    b"\x48\x89\xe5",  # push rbp; mov rbp, rsp (x64)
    b"\xeb",  # jmp short (common jump)
    b"\x90",  # nop (common in shellcode)
]

def detect_shellcode(filepath):
    """
    Detect if a file is likely pure shellcode.
    Handles both raw binary shellcode and text files containing hex escape sequences.
    Returns True if likely shellcode, False otherwise.
    
    Strategy:
    1. Check if file has no known binary headers
    2. If text file with hex escapes, extract binary data
    3. Validate x86/x64 instructions using capstone
    4. Check for shellcode patterns and entropy
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        
        if not data or len(data) < 16:
            return False
        
        # Already detected as a known binary type - not shellcode
        detected_type, _ = detect_magic(data[:MAGIC_READ_LEN])
        if detected_type and detected_type != "Unknown":
            return False
        
        # Check if it's a text file with hex escapes
        binary_to_check = data
        try:
            text = data.decode('utf-8', errors='strict')
            hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
            matches = hex_pattern.findall(text)
            if matches:
                extracted = bytes(int(m, 16) for m in matches)
                if len(extracted) >= 16:
                    binary_to_check = extracted
        except UnicodeDecodeError:
            pass  # Not text, use original data
        
        # Now detect on the binary data
        return _detect_shellcode_binary(binary_to_check)
    
    except Exception as e:
        print(f"[!] Error detecting shellcode: {e}")
        return False


def _detect_shellcode_binary(data):
    """Helper function to detect shellcode in binary data."""
    # Try capstone disassembly validation
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        
        # Try both x86 and x64
        for mode in [CS_MODE_32, CS_MODE_64]:
            cs = Cs(CS_ARCH_X86, mode)
            instructions = list(cs.disasm(data[:256], 0))
            
            # If we can disassemble meaningful instructions, likely shellcode
            if len(instructions) > 3:
                # Check for valid instruction patterns
                valid_instructions = 0
                for instr in instructions:
                    # Check if these look like real shellcode instructions
                    if instr.mnemonic in ['mov', 'push', 'pop', 'call', 'jmp', 'xor', 
                                          'add', 'sub', 'lea', 'nop', 'ret', 'int', 'syscall']:
                        valid_instructions += 1
                
                if valid_instructions > len(instructions) * 0.7:  # 70% valid instructions
                    return True
    except ImportError:
        print("[!] Capstone not installed, using fallback shellcode detection")
    except Exception as e:
        print(f"[!] Capstone detection failed: {e}")
    
    # Fallback: Check for shellcode patterns
    data_sample = data[:512]
    pattern_matches = sum(1 for pattern in SHELLCODE_INDICATORS if pattern in data_sample)
    
    # Check entropy (shellcode typically has high entropy)
    entropy = calculate_entropy(data[:256])
    
    # If multiple indicators present or high entropy with patterns
    return pattern_matches >= 2 or (entropy > 7.0 and pattern_matches >= 1)


def extract_shellcode_from_text(filepath):
    r"""Extract raw shellcode bytes from escaped text (\\xHH sequences)."""
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", errors="ignore")
        hex_pattern = re.compile(r"\\x([0-9a-fA-F]{2})")
        bytes_list = hex_pattern.findall(text)
        if len(bytes_list) < 8:
            return None
        extracted = bytes(int(h, 16) for h in bytes_list)
        if len(extracted) < 16:
            return None
        return extracted
    except Exception:
        return None


def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    import math
    if not data:
        return 0
    entropy = 0
    for byte in set(data):
        p = data.count(byte) / len(data)
        entropy -= p * math.log2(p)
    return entropy


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
    return EXTENSION_MAP.get(ext, "Unknown"), ext


def can_contain_vba_macros(detected_type, claimed_type, extension):
    """
    Determine if a file can contain VBA macros based on:
    - Detected file type (magic bytes)
    - Claimed type (extension)
    - File extension
    
    Returns True if file is a VBA macro-capable format.
    """
    # VBA macro-capable extensions
    vba_extensions = {"doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "xla", "xlam", "ppa", "ppam", "vbs"}
    
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


def _run_static_analysis(args):
    """Wrapper for static analysis to be run in process pool."""
    src_path, claimed_type, detected_type, resources_dir, sha256_hash = args
    return process_file(src_path, claimed_type, detected_type, resources_dir, sha256_hash)


def _run_disassembly(args):
    """
    Wrapper for disassembly to be run in thread pool.
    Includes comprehensive error handling and logging.

    Args:
        args: Tuple of (src_path, output_dir, full_report)
              full_report is the in-progress report dict (must contain
              ingest_analysis at minimum) so the similarity check can
              identify this binary when comparing against existing reports.

    Returns:
        Dictionary with disassembly data (including similar_binaries), or None on failure
    """
    src_path, output_dir, full_report = args

    try:
        # TODO: Get it to ontop of strings highlight suspicous code sections by imports 
        print(f"\n[DISASSEMBLY] Starting disassembly for: {src_path}")
        result = process_disassembly(
            src_path,
            results_dir=output_dir,
            full_report=full_report,
        )

        if result is None:
            print(f"[DISASSEMBLY] No disassembly data returned for: {src_path}")
            print(f"[DISASSEMBLY] Possible reasons:")
            print(f"              - File is not an executable")
            print(f"              - radare2 is not installed")
            print(f"              - Analysis failed or timed out")
            return None

        if result.get("function_count", 0) == 0:
            print(f"[DISASSEMBLY] Warning: No functions extracted from: {src_path}")
            return result

        similar = result.get("similar_binaries", [])
        print(f"[DISASSEMBLY] Successfully extracted {result['function_count']} functions")
        if similar:
            print(f"[DISASSEMBLY] {len(similar)} similar binary match(es) found")
        else:
            print(f"[DISASSEMBLY] No similar binaries found in existing reports")
        return result

    except Exception as e:
        print(f"[DISASSEMBLY] ERROR processing {src_path}: {e}")
        import traceback
        traceback.print_exc()
        return None


# File types for which StegoScan is worth running.
# PEs are included because they often carry embedded image resources.
_STEGO_ELIGIBLE_TYPES = {
    "PNG Image",
    "JPEG Image",
    "GIF Image",
    "Bitmap Image (BMP)",
    "Bitmap Image",
    "MP3 Audio (ID3v2)",
    "MP4 (ftyp box)",
    "Portable Executable (EXE)",
    "Portable Executable (DLL)",
}


def _run_stegoscan(args):
    src_path, detected_type, output_json_path, resources_dir, sha256 = args

    resources_dir = Path(resources_dir)
    if not resources_dir.exists():
        print(f"[STEGOSCAN] Skipping — extracted resources directory not found: {resources_dir}")
        return None

    extracted_files = list(resources_dir.rglob("*"))
    extracted_files = [f for f in extracted_files if f.is_file()]

    if not extracted_files:
        print("[STEGOSCAN] Skipping — extracted_resources is empty.")
        return None

    print(f"[STEGOSCAN] Starting scan on extracted resources ({len(extracted_files)} files) in: {resources_dir}")

    #  WSL pre-checks 
    if not ensure_git_installed():
        print("[STEGOSCAN] git not found in WSL — skipping StegoScan.")
        return None

    # if not ensure_python_installed():
    #     print("[STEGOSCAN] python3 not found in WSL — skipping StegoScan.")
    #     return None

    if not clone_or_update_repo():
        print("[STEGOSCAN] Failed to clone/update StegoScan repo — skipping.")
        return None

    if not install_dependencies():
        print("[STEGOSCAN] Dependency installation failed — skipping.")
        return None

    # result = run_stegoscan(str(resources_dir), str(output_json_path))
    out_dir = Path(output_json_path).with_suffix("")  # remove .json
    out_dir.mkdir(parents=True, exist_ok=True)

    if not patch_missing_stegoscan_tools():
        print("[STEGOSCAN] Tool patching failed — skipping.")
        return None

    result = run_stegoscan(str(resources_dir), str(out_dir), sha256)

    if result is None:
        print(f"[STEGOSCAN] Scan returned no results.")
        return None

    print(f"[STEGOSCAN] Scan complete — {len(result)} top-level result key(s) returned.")
    return result


def process_file(src_path, claimed_type, detected_type, resource_dir=None, sha256_hash=None):
    """Run static analysis and return the analysis data."""
    claimed_type = claimed_type or "Unknown"
    detected_type = detected_type or "Unknown"
    analyzer = None
    report = None

    extension = os.path.splitext(src_path)[1].lower().lstrip('.')
    ole_script_extensions = {"vbe", "hta"}

    if extension in ole_script_extensions:
        final_type = "OLE Compound Document (VBA Macro Capable)"
    else:
        final_type = detected_type if detected_type != "Unknown" else claimed_type

    if claimed_type != detected_type:
        print(f"[!] Type mismatch: Claimed '{claimed_type}' vs Detected '{detected_type}'")
    else:
        print(f"[+] Type verified: {final_type}")

    # Check for shellcode if type is unknown/generic (including shell script embedding in .sh)
    if final_type in ["Unknown", "Shellcode Binary", "Shellcode Object", "Object File / Shellcode", "Shell Script (may contain encoded shellcode)"]:
        if detect_shellcode(src_path):
            print(f"[+] Detected as SHELLCODE")
            # Route to shellcode parser
            # # Initialize analyzer
            analyzer = SharemAnalyzer(auto_setup=True)

            # Analyze your shellcode
            # TODO: maybe add a way for it to auto test 32 bit and 64 bit if the user does not know? or just run 64 bit due to backwards compatibility? or add a quick "mode" that runs both and gives you the better result?
            report = analyzer.analyze_shellcode(
                src_path,
                architecture="32", # options: 32 or 64
                analysis_mode="full",  # options: full, emulate, disassemble, quick, strings, info
                known_sha256=sha256_hash,  # Use ingest hash to maintain consistency
            )
            return report

    # Route to appropriate analyzer (existing code)
    if final_type == "Portable Executable (EXE)":
        analyzer = PEStaticAnalyzer(src_path, output_dir=resource_dir or "extracted_resources")
    elif final_type == "ELF Executable":
        report = run(src_path, output_dir=resource_dir)
    elif final_type == "OLE Compound Document (VBA Macro Capable)" or final_type == "VBScript" or final_type == "VBScript Encoded" or final_type == "HTML Application (HTA)" or any(vba_type in final_type for vba_type in ["Microsoft Office", "Microsoft Excel", "Microsoft PowerPoint"]):
        # analyze_file() runs the full OLE pipeline and returns a PE-schema-mirrored
        # dict directly — it is NOT an analyzer object with .analyze()/.get_report().
        return analyze_file(src_path, verbose=False, save_results=False)
    else:
        print(f"[x] Unsupported file type: {final_type}")
        return None

    if analyzer is not None:
        analyzer.analyze()
        report = analyzer.get_report() if hasattr(analyzer, 'get_report') else None

    return report

    # TODO: Run regular expressions here, already have this in PE but need to make it general


def ingest_file(src_path, stego_enabled, rename_with_hash=True, overwrite=True):
    _, extension = os.path.splitext(src_path)
    normalized_extension = extension.lower().lstrip('.')

    if normalized_extension in UNSUPPORTED_VBA_EXTENSIONS:
        raise ValueError(
            f"Unsupported VBA file type '.{normalized_extension}'. "
            "Raw/non-document VBA project artifacts are not supported by the "
            "current OLE/VBA analysis toolchain."
        )
 
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

    print("[*] Claimed type based on extension:", claimed_type)
 
    with open(src_path, "rb") as f:
        header = f.read(MAGIC_READ_LEN)
 
    detected_type, matched_signature = detect_magic(header)
    sha256 = compute_sha256(src_path)
 
    resources_dir = os.path.join(PROJECT_ROOT, f"extracted_resources_{sha256}")
    if os.path.exists(resources_dir):
        print(f"[+] Recreating extracted resources directory: {resources_dir}")
        shutil.rmtree(resources_dir)
    safe_makedirs(resources_dir)
 
    # base_name = os.path.basename(src_path)
    # dest_name_with_extension = f"{sha256}{extension}" if rename_with_hash else base_name
    # dest_name = f"{sha256}" if rename_with_hash else base_name
    # dest_path = os.path.join(uploads_dir, dest_name_with_extension)
    base_name = os.path.basename(src_path)
    dest_name_with_extension = f"{sha256}.bin" if rename_with_hash else base_name
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
        "extracted_resources_path": os.path.abspath(resources_dir),
    }
 
    final_json = {
        "ingest_analysis": metadata
    }
 
    # Normalize everything before writing
    # TODO: Put the normalization in standalone file
    final_json = normalize_json(final_json)
 
    json_path = os.path.join(reports_dir, dest_name + ".json")

    # Dedicated output file for the raw StegoScan JSON so it doesn't
    # collide with the main report.  Written by StegoScan itself, then
    # read back and merged under final_json["stegoscan"].
    if stego_enabled:
        stegoscan_json_path = os.path.join(reports_dir, dest_name + "_stegoscan.json")

    # TODO: This is where we need to call the process manager to allow for the threading and multiprocessing
    # All functions now return JSON data instead of modifying files directly

    with ThreadPoolExecutor(max_workers=3) as executor:
        # TODO: We need to also do a packing check here
        static_future = executor.submit(_run_static_analysis, (src_path, claimed_type, detected_type, resources_dir, sha256))
        
        # Wait for static analysis to complete before starting stegoscan
        static_analysis_data = static_future.result()
        
        # Pass final_json (already contains ingest_analysis) so the similarity
        # check inside process_disassembly can identify this binary correctly.
        disassembly_future = executor.submit(_run_disassembly, (src_path, reports_dir, final_json))
        disassembly_data = disassembly_future.result()

        # StegoScan: only does meaningful work for image/media/PE types;
        # _run_stegoscan skips silently for everything else.
        stegoscan_data = None
        if stego_enabled:
            stegoscan_future = executor.submit(  # Now runs after static analysis completes, TODO Will need to make this run after the CAPE to get full sets of IP/Domains
                _run_stegoscan, (dest_path, detected_type or "Unknown", stegoscan_json_path, resources_dir, sha256)
            )
            stegoscan_data = stegoscan_future.result()
        

    print("\033[0m")

    if static_analysis_data:
        # OLE pipeline returns a fully PE-schema-mirrored dict with its own
        # top-level keys (format_type, ingest_analysis, static_analysis,
        # disassembly, dynamic_analysis, verdict, ...).  Hoist those keys
        # directly into final_json instead of nesting the whole dict under
        # final_json['static_analysis'], which would bury everything one
        # level too deep and cause all downstream patch-back / normalization
        # steps to read from the wrong location.
        if isinstance(static_analysis_data, dict) and static_analysis_data.get('format_type') == 'OLE':
            _ole = static_analysis_data
            final_json['format_type']        = 'OLE'
            # ingest.py's own ingest_analysis is richer (magic bytes, mime, etc.);
            # merge OLE-only fields that ingest.py doesn't populate.
            for _k, _v in _ole.get('ingest_analysis', {}).items():
                final_json['ingest_analysis'].setdefault(_k, _v)
            final_json['analysis_timestamps'] = _ole.get('analysis_timestamps', {})
            final_json['static_analysis']     = _ole.get('static_analysis', {})
            final_json['disassembly']          = _ole.get('disassembly', {})
            final_json['dynamic_analysis']     = _ole.get('dynamic_analysis', {})
            final_json['behavioral_analysis']  = _ole.get('behavioral_analysis', {})
            final_json['verdict']              = _ole.get('verdict', {})
            final_json['pipeline_metadata']    = _ole.get('pipeline_metadata', {})
        else:
            final_json["static_analysis"] = static_analysis_data

    if disassembly_data:
        # For OLE files disassembly is already hoisted above; only set for PE/ELF.
        if not final_json.get('disassembly'):
            final_json["disassembly"] = disassembly_data
    
    if stegoscan_data:
        final_json["stegoscan"] = stegoscan_data
 
    # run the dynamic analysis and emulation here
    # TODO: Add dynamic analysis function that returns data
 
    # run the full normalization with all collected data
    final_json = normalize_json(final_json)
 
    # run the threat intelligence and get enriched data
    threat_intel_data = enrich_threat_data(sample_data=final_json, sample_path=src_path)
    if threat_intel_data:
        final_json["threat_intelligence"] = threat_intel_data
 
    # Write the complete normalized JSON once
    atomic_write_json(json_path, final_json)
 
    normalized_json_path = os.path.splitext(json_path)[0] + '_normalized.json'
    normalize(json_path, normalized_json_path)

    #  Load the fully normalized report for all downstream analysis 
    with open(normalized_json_path, "r", encoding="utf-8") as f:
        loaded_report = json.load(f)

    #  OLE patch-back: the PE postprocessor strips keys it does not know 
    # about.  For OLE files, restore every top-level field that the normalizer
    # dropped by merging from the pre-normalization final_json.  Keys that the
    # postprocessor already wrote correctly are NOT overwritten.
    if final_json.get("format_type") == "OLE":
        OLE_PRESERVE_KEYS = [
            "format_type", "dynamic_analysis", "behavioral_analysis",
            "disassembly", "pipeline_metadata", "verdict",
        ]
        _patched = False
        for _key in OLE_PRESERVE_KEYS:
            if _key in final_json:
                # Always restore verdict unconditionally — the PE normalizer or a
                # prior score_verdict call may have written an incorrect one.
                if _key == "verdict" or _key not in loaded_report or not loaded_report[_key]:
                    loaded_report[_key] = final_json[_key]
                    _patched = True
        # Also patch back richer sub-keys inside static_analysis that the
        # normalizer may have emptied (security_features, imports, format_specific)
        _sa_src  = final_json.get("static_analysis", {})
        _sa_dst  = loaded_report.setdefault("static_analysis", {})
        for _sk in ("security_features", "imports", "format_specific"):
            if _sa_src.get(_sk) and not _sa_dst.get(_sk):
                _sa_dst[_sk] = _sa_src[_sk]
                _patched = True
        if _patched:
            print("[+] OLE patch-back: restored fields stripped by PE normalizer")
            atomic_write_json(normalized_json_path, loaded_report)
 
    results_dir = Path(__file__).resolve().parent.parent / "results"
 
    #  String similarity 
    try:
        from static_analysis.string_simularity import compare_strings_single_report
    except ImportError:
        print("[!] string_simularity.py not found — skipping string similarity check.")
        compare_strings_single_report = None
 
    string_matches = []
    if compare_strings_single_report:
        print(f"[+] Running STRING similarity check against: {results_dir}")
        string_matches = compare_strings_single_report(
            loaded_report,
            results_dir,
            min_overlap=5
        )
 
    #  Threat label similarity 
    try:
        from static_analysis.threat_simularity import compare_threat_labels_single_report
    except ImportError:
        print("[!] threat_simularity.py not found — skipping threat similarity check.")
        compare_threat_labels_single_report = None
 
    threat_matches = []
    if compare_threat_labels_single_report:
        print(f"[+] Running THREAT label similarity check against: {results_dir}")
        threat_matches = compare_threat_labels_single_report(
            loaded_report,
            results_dir,
            min_shared=1
        )

    #  Function similarity 
    # try:
    #     from static_analysis.function_simularity import compare_single_report
    # except ImportError:
    #     print("[!] function_simularity.py not found — skipping function similarity check.")
    #     compare_single_report = None

    # function_matches = []
    # if compare_single_report:
    #     print(f"[+] Running FUNCTION similarity check against: {results_dir}")

    #     shared_report_dir = results_dir / "shared_functions"
    #     shared_report_dir.mkdir(parents=True, exist_ok=True)

    #     function_matches = compare_single_report(
    #         loaded_report,
    #         results_dir,
    #         min_overlap=1,
    #         shared_functions_report_dir=shared_report_dir
    #     )

    #     # Store directly in main report JSON
    #     loaded_report.setdefault("disassembly", {})["similar_binaries"] = function_matches
 
    #  Function scorer 
    try:
        from static_analysis.function_scorer import score_functions
        score_functions(loaded_report, top_n=20)
    except ImportError:
        print("[!] function_scorer.py not found — skipping function scoring.")
 
    #  Advanced composite similarity (ssdeep + func hash + string + label + MITRE)
    from static_analysis.advanced_simularity import compare_advanced
    corpus_matches = compare_advanced(loaded_report, results_dir)
 
    #  Build corpus_reports for family identification 
    # Load the normalized report for each corpus match so family_identifier
    # can extract family tokens from those files too.
    # We only load files that actually matched to avoid unnecessary I/O.
    import re as _re
    corpus_reports: dict[str, dict] = {}
 
    for match in corpus_matches:
        binary_id = match.get("binary_id", "")
 
        # binary_id format: "8d855c28...b7.elf [8d855c28744d]"
        # Strip the short-hash bracket suffix to get the filename
        clean_id = _re.sub(r'\s*\[[^\]]+\]$', '', binary_id).strip()
 
        # The sha256 stem is everything before the final extension
        sha256_stem = clean_id.rsplit(".", 1)[0] if "." in clean_id else clean_id
 
        # The normalized report lives at results/<sha256>_normalized.json
        norm_path = results_dir / f"{sha256_stem}_normalized.json"
        if norm_path.exists() and binary_id not in corpus_reports:
            try:
                with open(norm_path, "r", encoding="utf-8") as f:
                    corpus_reports[binary_id] = json.load(f)
            except Exception:
                pass  # skip unreadable reports
 
    #  Family identification 
    try:
        from ingest.family_identifier import identify_family, print_family_report
        family_result = identify_family(loaded_report, corpus_matches, corpus_reports)
        print_family_report(family_result)
    except ImportError:
        print("[!] family_identifier.py not found — skipping family identification.")
        family_result = {
            "identified_family":  None,
            "family_confidence":  0.0,
            "family_source":      "unknown",
            "family_tokens":      [],
            "top_corpus_matches": [],
            "cluster_verdict":    "unknown",
        }
 
    #  Extract inputs for verdict scoring from the normalized report 
    mitre_block = loaded_report.get("threat_intelligence", {}).get("MITRE_ATTACK", {})
    hits        = mitre_block.get("hits", {})
    capa_hits   = hits.get("capa", [])
    yara_hits   = hits.get("yara", [])
    vt_data     = loaded_report.get("threat_intelligence", {}).get("VirusTotal", {})
 
    # Abuse.ch score: 0.5 if the hash was found in the database, 0.0 if not.
    # A found entry has 'sha256_hash'; a not-found entry has 'error'.
    abuse_score = 0.0
    ab_data = loaded_report.get("threat_intelligence", {}).get("AbuseCH", {})
    for ab_entry in ab_data.values():
        if isinstance(ab_entry, dict) and "sha256_hash" in ab_entry and "error" not in ab_entry:
            abuse_score = 0.5
            break
 
    # Corpus signal: pass family confidence to verdict scorer only when the
    # family identifier has matched a confirmed malicious family. This acts
    # as weak corroborating evidence, not a primary driver.
    corpus_signal = (
        family_result["family_confidence"]
        if family_result.get("cluster_verdict") == "known_malicious_family"
        else 0.0
    )

    def compute_emerging_threat_score(report: dict) -> float:
        score = 0.0
        stego = report.get("stegoscan", {}) or {}

        if stego.get("verdict") == "STEGO_DETECTED":
            score += 0.60
        elif stego.get("risk_score", 0) >= 50:
            score += 0.35
        elif stego.get("risk_score", 0) >= 30:
            score += 0.20

        section_entropy = any(
            isinstance(sec, dict) and sec.get("entropy", 0) >= 7.5
            for sec in report.get("static_analysis", {}).get("sections", [])
        )
        if section_entropy:
            score += 0.10

        if report.get("static_analysis", {}).get("security_features", {}).get("HighEntropyVA"):
            score += 0.05

        return min(score, 0.90)

    section_entropy = any(
        isinstance(sec, dict) and sec.get("entropy", 0) >= 7.5
        for sec in loaded_report.get("static_analysis", {}).get("sections", [])
    )

    emerging_score = compute_emerging_threat_score(loaded_report)
    loaded_report.setdefault("threat_intelligence", {})["emerging_threat"] = {
        "score": round(emerging_score, 4),
        "stego_detected": bool(loaded_report.get("stegoscan", {}).get("verdict") == "STEGO_DETECTED"),
        "high_entropy_section": section_entropy,
        "high_entropy_va": loaded_report.get("static_analysis", {}).get("security_features", {}).get("HighEntropyVA", False),
    }

    #  Verdict scoring 
    # OLE files skip the PE verdict_scorer (which is capa/yara-centric and
    # would produce a near-zero score for any OLE file).  The OLE pipeline
    # already ran _generate_verdict() which accounts for oleid risk, VBA
    # auto-exec, dynamic behaviour, and IOCs.  Preserve that verdict and only
    # supplement it with the VT / corpus signals via a lightweight merge.
    if loaded_report.get("format_type") == "OLE":
        # Start from the OLE verdict already in the report
        ole_verdict = loaded_report.get("verdict", {})
        # Supplement scores with VT data if available
        if isinstance(vt_data, dict):
            _vt_entry = next(
                (v for v in vt_data.values() if isinstance(v, dict) and "analysis_stats" in v),
                {}
            )
            _stats = _vt_entry.get("analysis_stats", {})
            _mal   = _stats.get("malicious", 0)
            _total = sum(_stats.get(k, 0) for k in ("malicious","suspicious","undetected","harmless"))
            if _total > 0:
                _vt_score = round(_mal / _total, 4)
                ole_verdict.setdefault("scores", {})["virustotal"] = _vt_score
                if _vt_score >= 0.5 and ole_verdict.get("verdict") not in ("malicious", "likely_malicious"):
                    ole_verdict["verdict"] = "likely_malicious"
                    ole_verdict.setdefault("reasoning", []).append(
                        f"VirusTotal: {_mal}/{_total} engines flagged as malicious"
                    )
        ole_verdict.setdefault("scores", {})["corpus"] = corpus_signal
        verdict_result = ole_verdict
        print(
            f"[+] OLE Verdict (preserved): {verdict_result['verdict']} "
            f"(confidence {verdict_result.get('confidence', 0):.0%}"
            + (f", override={verdict_result['override']}" if verdict_result.get("override") else "")
            + ")"
        )
    else:
        try:
            from ingest.verdict_scorer import score_verdict
            verdict_result = score_verdict(
                capa_hits       = capa_hits,
                yara_hits       = yara_hits,
                vt_result       = vt_data,
                abuse_result    = abuse_score,
                emerging_result = emerging_score,
                corpus_signal   = corpus_signal,
            )
            print(
                f"[+] Verdict: {verdict_result['verdict']} "
                f"(confidence {verdict_result['confidence']:.0%}"
                + (f", override={verdict_result['override']}" if verdict_result.get("override") else "")
                + ")"
            )
        except ImportError:
            print("[!] verdict_scorer.py not found — skipping verdict scoring.")
            verdict_result = {
                "verdict":    "Unknown",
                "confidence": 0.0,
                "override":   None,
                "scores":     {},
                "reasoning":  ["verdict_scorer.py not available"],
                "hits":       {"capa": capa_hits, "yara": yara_hits},
            }
 
    #  Persist verdict and family results back into the normalized report 
    # This ensures downstream consumers (Elasticsearch, UI) can query both.
    loaded_report["verdict"]        = verdict_result
    loaded_report["family"]         = family_result
    # Overwrite the normalized JSON with the enriched data
    atomic_write_json(normalized_json_path, loaded_report)
 
    #  Similarity score for external callers (0–100) 
    # Use the top corpus match final_score scaled to 0–100.
    similarity_score = 0
    if corpus_matches:
        similarity_score = round(corpus_matches[0]["final_score"] * 100)
    print(f"Similarity score: {similarity_score}/100")
 
    #  DB indexing 
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
