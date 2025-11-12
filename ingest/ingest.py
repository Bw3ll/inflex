# TODO: This will verify the files are the filetypes by looking at magic bytes etc, be able to handle folders, setting
#       up the output file for each sample, getting the file hash, ETC.

import os
import json
import shutil
import hashlib
import time
import tempfile
import mimetypes
from datetime import datetime

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
    "docx": "Microsoft Office DOCX",
    "xlsx": "Microsoft Excel XLSX",
    "pptx": "Microsoft PowerPoint PPTX",
    "7z": "7-Zip Archive",
    "rar": "RAR Archive",
    "tar": "TAR Archive",
    "iso": "ISO Image",
}

MAGIC_SIGNATURES = {
    b"\x4D\x5A": "Portable Executable (EXE)",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\x50\x4B\x03\x04": "ZIP Archive / OOXML Document",
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
    }

    final_json = {
        "ingest_analysis": metadata
    }

    json_path = os.path.join(reports_dir, dest_name + ".json")
    atomic_write_json(json_path, final_json)

    return final_json


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

