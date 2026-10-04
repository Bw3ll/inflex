"""
Structured ELF extractor using pyelftools.
"""

import sys
import json
import math
import hashlib
import re
from collections import Counter
from pathlib import Path
from datetime import datetime

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection


#  Entropy 

def calc_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    Returns a value in [0.0, 8.0]:
      0.0 = perfectly uniform (e.g. all-zero padding)
      8.0 = perfectly random (e.g. encrypted or compressed data)

    A section with entropy >= 7.0 is considered high-entropy and warrants
    attention — it may contain packed, encrypted, or compressed content.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return round(entropy, 6)


def entropy_label(entropy: float) -> str:
    """
    Human-readable label for an entropy value.

      < 1.0  — near-zero (padding, null bytes)
      1.0–3.5 — low (plain text, simple data)
      3.5–6.0 — medium (compiled code, mixed data)
      6.0–7.0 — elevated (compressed headers, dense binary data)
      7.0–7.5 — high (likely compressed or partially encrypted)
      7.5–8.0 — very high (likely encrypted or random — strong packing signal)
    """
    if entropy < 1.0:
        return "near-zero"
    if entropy < 3.5:
        return "low"
    if entropy < 6.0:
        return "medium"
    if entropy < 7.0:
        return "elevated"
    if entropy < 7.5:
        return "high"
    return "very-high"


#  JSON safety 

def json_safe(obj):
    """Recursively convert pyelftools objects into JSON-serializable types."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    if hasattr(obj, 'items'):
        try:
            return {str(k): json_safe(v) for k, v in obj.items()}
        except Exception:
            pass
    return str(obj)


#  File hashes 

def get_file_hashes(path: str) -> dict:
    hashes = {"md5": None, "sha1": None, "sha256": None}
    try:
        h_md5    = hashlib.md5()
        h_sha1   = hashlib.sha1()
        h_sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
        hashes["md5"]    = h_md5.hexdigest()
        hashes["sha1"]   = h_sha1.hexdigest()
        hashes["sha256"] = h_sha256.hexdigest()
    except Exception as e:
        print(f"[!] Error computing file hashes: {e}")
    return hashes


#  ELF header 

def elf_header(elf: ELFFile) -> dict:
    return dict(elf.header)


#  Program headers (segments) 

def program_headers(elf: ELFFile) -> list[dict]:
    """
    Extract all program headers (PT_LOAD, PT_DYNAMIC, PT_INTERP, etc.)
    and compute per-segment entropy from the raw segment data.
    """
    segments = []
    for idx, seg in enumerate(elf.iter_segments()):
        hdr = dict(seg.header)

        # Compute entropy on the raw segment bytes
        try:
            seg_data = seg.data()
            seg_entropy = calc_entropy(seg_data)
        except Exception:
            seg_data    = b""
            seg_entropy = None

        segments.append({
            "index":         idx,
            "header":        hdr,
            "entropy":       seg_entropy,
            "entropy_label": entropy_label(seg_entropy) if seg_entropy is not None else None,
        })

    return segments


#  Section headers 

def section_headers(elf: ELFFile) -> list[dict]:
    """
    Extract all section headers and compute per-section Shannon entropy.

    The entropy value and label are attached directly to each section record
    so downstream scorers can flag high-entropy .text (packing) or
    high-entropy data sections (encrypted payloads) without re-reading the
    binary.
    """
    sections = []
    for sec in elf.iter_sections():
        hdr = dict(sec.header)

        try:
            sec_data    = sec.data()
            sec_entropy = calc_entropy(sec_data)
            sec_size    = len(sec_data)
        except Exception:
            sec_data    = b""
            sec_entropy = None
            sec_size    = hdr.get("sh_size", 0)

        sections.append({
            "name":          sec.name,
            "header":        hdr,
            "size":          sec_size,
            "entropy":       sec_entropy,
            "entropy_label": entropy_label(sec_entropy) if sec_entropy is not None else None,
        })

    return sections


#  Symbols 

def symbols(elf: ELFFile) -> list[dict]:
    tables = []
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            table = {"name": sec.name, "symbols": []}
            for sym in sec.iter_symbols():
                table["symbols"].append({
                    "name":          sym.name,
                    "value":         sym["st_value"],
                    "size":          sym["st_size"],
                    "type":          sym["st_info"]["type"],
                    "bind":          sym["st_info"]["bind"],
                    "visibility":    sym["st_other"]["visibility"],
                    "section_index": sym["st_shndx"],
                })
            tables.append(table)
    return tables


#  Relocations 

def relocations(elf: ELFFile) -> list[dict]:
    relocs = []
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection):
            symtab  = elf.get_section(sec["sh_link"])
            entries = []
            for rel in sec.iter_relocations():
                symbol = None
                if symtab and rel["r_info_sym"] != 0:
                    symbol = symtab.get_symbol(rel["r_info_sym"]).name
                entries.append({
                    "offset": rel["r_offset"],
                    "type":   rel["r_info_type"],
                    "symbol": symbol,
                    "addend": rel["r_addend"] if rel.is_RELA() else None,
                })
            relocs.append({"section": sec.name, "entries": entries})
    return relocs


#  Dynamic section 

def dynamic_section(elf: ELFFile):
    dyn = elf.get_section_by_name(".dynamic")
    if not dyn:
        return None

    entries = []
    for tag in dyn.iter_tags():
        entry = {"tag": tag.entry.d_tag}
        for k, v in tag.entry.items():
            if k != "d_tag":
                entry[k] = v
        if hasattr(tag, "needed"):
            entry["needed"] = tag.needed
        entries.append(entry)

    return entries


#  Interpreter 

def interpreter(elf: ELFFile):
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_INTERP":
            return seg.data().rstrip(b"\x00").decode(errors="ignore")
    return None


#  Notes 

def notes(elf: ELFFile) -> list[dict]:
    result = []
    for sec in elf.iter_sections():
        if sec.name.startswith(".note"):
            result.append({
                "section": sec.name,
                "raw":     sec.data().hex(),
            })
    return result


def _sanitize_section_name(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', name.strip('.'))


class ELFDataSectionCarver:
    """
    Carve common embedded file formats from ELF .data section blobs.
    """

    def __init__(self, max_size=50_000_000):
        self.max_size = max_size

    def carve_all(self, data: bytes, out_dir: str, section_name: str) -> list[str]:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        results = []
        results += self._carve_png(data, out_dir, section_name)
        results += self._carve_jpeg(data, out_dir, section_name)
        results += self._carve_gif(data, out_dir, section_name)
        results += self._carve_pdf(data, out_dir, section_name)
        results += self._carve_zip(data, out_dir, section_name)
        return list(dict.fromkeys(results))

    def _write_blob(self, blob: bytes, out_dir: Path, section_name: str, offset: int, ext: str) -> str:
        md5 = hashlib.md5(blob).hexdigest()
        out_path = out_dir / f"{section_name}_{offset:08x}_{md5}.{ext}"
        out_path.write_bytes(blob)
        return str(out_path)

    def _carve_png(self, data, out_dir, section_name):
        sig = b"\x89PNG\r\n\x1a\n"
        results = []
        pos = 0
        while True:
            start = data.find(sig, pos)
            if start == -1:
                break
            end = self._parse_png_end(data, start)
            if end:
                blob = data[start:end]
                results.append(self._write_blob(blob, out_dir, section_name, start, "png"))
            pos = start + len(sig)
        return results

    def _parse_png_end(self, data, start):
        pos = start + 8
        while pos + 12 <= len(data):
            if pos - start > self.max_size:
                return None
            length = int.from_bytes(data[pos:pos+4], "big")
            chunk_type = data[pos+4:pos+8]
            pos += 8 + length + 4
            if chunk_type == b"IEND":
                return pos
        return None

    def _carve_jpeg(self, data, out_dir, section_name):
        sig = b"\xff\xd8\xff"
        results = []
        pos = 0
        while True:
            start = data.find(sig, pos)
            if start == -1:
                break
            end = data.find(b"\xff\xd9", start + 2)
            if end != -1 and (end + 2 - start) <= self.max_size:
                blob = data[start:end+2]
                results.append(self._write_blob(blob, out_dir, section_name, start, "jpg"))
            pos = start + len(sig)
        return results

    def _carve_gif(self, data, out_dir, section_name):
        results = []
        pos = 0
        while True:
            s1 = data.find(b"GIF89a", pos)
            s2 = data.find(b"GIF87a", pos)
            candidates = [x for x in [s1, s2] if x != -1]
            if not candidates:
                break
            start = min(candidates)
            trailer = data.find(b"\x3B", start + 6)
            if trailer != -1 and (trailer + 1 - start) <= self.max_size:
                blob = data[start:trailer+1]
                results.append(self._write_blob(blob, out_dir, section_name, start, "gif"))
            pos = start + 6
        return results

    def _carve_pdf(self, data, out_dir, section_name):
        sig = b"%PDF"
        results = []
        pos = 0
        while True:
            start = data.find(sig, pos)
            if start == -1:
                break
            end = data.find(b"%%EOF", start)
            if end != -1:
                end += len(b"%%EOF")
                if (end - start) <= self.max_size:
                    blob = data[start:end]
                    results.append(self._write_blob(blob, out_dir, section_name, start, "pdf"))
            pos = start + len(sig)
        return results

    def _carve_zip(self, data, out_dir, section_name):
        sig = b"PK\x03\x04"
        results = []
        pos = 0
        while True:
            start = data.find(sig, pos)
            if start == -1:
                break
            eocd = data.find(b"PK\x05\x06", start)
            if eocd != -1:
                end = eocd + 22
                if (end - start) <= self.max_size:
                    blob = data[start:end]
                    results.append(self._write_blob(blob, out_dir, section_name, start, "zip"))
            pos = start + len(sig)
        return results


def extract_data_section_files(elf: ELFFile, output_dir: str = None) -> list[dict]:
    if not output_dir:
        return []

    output_path = Path(output_dir) / "elf_data_section"
    output_path.mkdir(parents=True, exist_ok=True)
    results = []
    carver = ELFDataSectionCarver()

    for sec in elf.iter_sections():
        if sec.name != ".data" and not sec.name.startswith(".data"):
            continue

        try:
            section_data = sec.data()
        except Exception as e:
            results.append({
                "section": sec.name,
                "error": str(e),
            })
            continue

        if section_data is None or len(section_data) == 0:
            continue

        safe_name = _sanitize_section_name(sec.name)
        raw_md5 = hashlib.md5(section_data).hexdigest()
        raw_path = output_path / f"{safe_name}_raw_{raw_md5}.bin"
        raw_path.write_bytes(section_data)

        results.append({
            "section":      sec.name,
            "type":         "raw",
            "size":         len(section_data),
            "md5":          raw_md5,
            "saved_to":     str(raw_path),
        })

        carved_files = carver.carve_all(section_data, str(output_path), safe_name)
        for carved_path in carved_files:
            results.append({
                "section":  sec.name,
                "type":     "carved",
                "saved_to": carved_path,
            })

    return results


#  DWARF 

def dwarf_info(elf: ELFFile):
    if not elf.has_dwarf_info():
        return None

    dwarf = elf.get_dwarf_info()
    cus = []
    for cu in dwarf.iter_CUs():
        cus.append({
            "unit_length": cu["unit_length"],
            "version":     cu["version"],
            "addr_size":   cu["address_size"],
        })

    return {"compilation_units": cus}


#  Security features 

def security_features(elf: ELFFile) -> dict:
    features = {}

    # NX (non-executable stack)
    nx = True
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            nx = not (seg.header.p_flags & 0x1)
    features["nx"] = nx

    # PIE
    features["pie"] = elf.header.e_type == "ET_DYN"

    # RELRO
    has_relro = any(
        seg.header.p_type == "PT_GNU_RELRO"
        for seg in elf.iter_segments()
    )
    bind_now = False
    dyn = elf.get_section_by_name(".dynamic")
    if dyn:
        bind_now = any(
            tag.entry.d_tag == "DT_BIND_NOW"
            for tag in dyn.iter_tags()
        )
    features["relro"] = (
        "full"    if has_relro and bind_now else
        "partial" if has_relro else
        "none"
    )

    # Stack canary (heuristic via symbol table)
    canary = False
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if sym.name == "__stack_chk_fail":
                    canary = True
    features["stack_canary"] = canary

    return features


#  Strings 

def extract_strings(path: str, min_length: int = 4, max_strings: int = 5000) -> dict:
    strings = {"ascii": [], "unicode": [], "interesting": {}}
    try:
        with open(path, "rb") as f:
            data = f.read()

        ascii_pattern = rb'[\x20-\x7E]{%d,}' % min_length
        ascii_strings = re.findall(ascii_pattern, data)
        strings["ascii"] = [
            s.decode("ascii", errors="ignore")
            for s in ascii_strings[:max_strings]
        ]

        unicode_pattern = rb'(?:[\x20-\x7E]\x00){%d,}' % min_length
        unicode_strings = re.findall(unicode_pattern, data)
        strings["unicode"] = [
            s.decode("utf-16-le", errors="ignore")
            for s in unicode_strings[:max_strings]
        ]

        strings["interesting"] = extract_interesting_strings(
            strings["ascii"] + strings["unicode"]
        )

    except Exception as e:
        print(f"Error extracting strings: {e}")

    return strings


def extract_interesting_strings(all_strings: list[str]) -> dict:
    interesting = {
        "urls":              [],
        "ips":               [],
        "emails":            [],
        "file_paths":        [],
        "crypto_indicators": [],
    }

    url_pattern    = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    ip_pattern     = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    email_pattern  = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    path_pattern   = re.compile(r'/[a-zA-Z0-9_\-./]+', re.IGNORECASE)
    crypto_keywords = ['AES', 'DES', 'RSA', 'MD5', 'SHA', 'base64', 'encrypt', 'decrypt', 'cipher']

    for s in all_strings:
        interesting["urls"].extend(url_pattern.findall(s))
        interesting["ips"].extend(ip_pattern.findall(s))
        interesting["emails"].extend(email_pattern.findall(s))
        interesting["file_paths"].extend(path_pattern.findall(s))
        for keyword in crypto_keywords:
            if keyword.lower() in s.lower():
                interesting["crypto_indicators"].append(s)
                break

    for key in interesting:
        interesting[key] = list(set(interesting[key]))[:100]

    return interesting


#  Entropy summary 

def entropy_summary(file_data: bytes, section_list: list[dict]) -> dict:
    """
    Build a consolidated entropy picture across the whole file and its sections.
    """
    file_entropy = calc_entropy(file_data)

    # Pull entropy from already-computed section list (avoids re-reading data)
    section_entropies = [
        {
            "name":          s["name"],
            "entropy":       s["entropy"],
            "entropy_label": s["entropy_label"],
            "size":          s["size"],
        }
        for s in section_list
        if s["entropy"] is not None and s["size"] > 0
    ]
    section_entropies.sort(key=lambda x: x["entropy"], reverse=True)

    suspicious = [s for s in section_entropies if s["entropy"] >= 7.0]

    mean_entropy = (
        round(sum(s["entropy"] for s in section_entropies) / len(section_entropies), 6)
        if section_entropies else 0.0
    )

    return {
        "file_entropy":            file_entropy,
        "file_entropy_label":      entropy_label(file_entropy),
        "section_entropies":       section_entropies,
        "highest_entropy_section": section_entropies[0] if section_entropies else None,
        "suspicious_sections":     suspicious,
        "mean_section_entropy":    mean_entropy,
        "packed_indicator":        len(suspicious) > 0,
    }


#  Main extractor 

def extract_elf(path: str, output_dir=None) -> dict:
    with open(path, "rb") as f:
        file_data = f.read()

    elf = ELFFile(open(path, "rb"))

    sec_list = section_headers(elf)
    elf.stream.seek(0)  # reset after section pass

    result = {
        "metadata": {
            "timestamp":        datetime.now().isoformat(),
            "analyzer_version": "2.0",
            "file_path":        path,
        },
        "hashes":          get_file_hashes(path),
        "elf_header":      elf_header(elf),
        "program_headers": program_headers(elf),
        "section_headers": sec_list,
        "symbols":         symbols(elf),
        "relocations":     relocations(elf),
        "dynamic":         dynamic_section(elf),
        "interpreter":     interpreter(elf),
        "notes":           notes(elf),
        "dwarf":           dwarf_info(elf),
        "security":        security_features(elf),
        "strings":                   extract_strings(path),
        "data_section_extractions":   extract_data_section_files(elf, output_dir),
        # Entropy summary built from already-computed section data — no extra I/O
        "entropy":                   entropy_summary(file_data, sec_list),
    }

    # Packing assessment — runs last so it can draw on all other fields
    try:
        from static_analysis.packing_detection import assess_packing_elf
        result["packing"] = assess_packing_elf(result)
        verdict    = result["packing"]["verdict"]
        confidence = result["packing"]["confidence"]
        packers    = result["packing"]["packer_names"]
        print(f"[+] Packing assessment: {verdict} (confidence {confidence:.0%})"
              + (f" — {', '.join(packers)}" if packers else ""))
    except ImportError:
        print("[!] packing_detector.py not found — skipping packing assessment")

    return result


def run(src_path: str, output_dir: str = None) -> dict:
    data      = extract_elf(src_path, output_dir=output_dir)
    safe_data = json_safe(data)
    return safe_data


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage: {sys.argv[0]} <elf_binary> [output.json]")
        sys.exit(1)

    binary = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) == 3 else None

    data       = extract_elf(binary)
    safe_data  = json_safe(data)
    json_output = json.dumps(safe_data, indent=2)

    if output:
        with open(output, "w") as f:
            f.write(json_output)
    else:
        print(json_output)


if __name__ == "__main__":
    main()
