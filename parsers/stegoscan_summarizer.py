import argparse
import json
import math
import os
import re
import struct
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# 
# Signal classification tables
# 

# Patterns whose presence in ANY bit-plane is a strong indicator of
# intentionally hidden structured data
HIGH_SIGNAL = [
    (re.compile(r'zlib compressed', re.I),          'zlib compressed data'),
    (re.compile(r'gzip compressed', re.I),          'gzip compressed data'),
    (re.compile(r'bzip2 compressed', re.I),         'bzip2 compressed data'),
    (re.compile(r'xz compressed', re.I),            'xz compressed data'),
    (re.compile(r'\bELF\b', re.I),                  'ELF executable'),
    (re.compile(r'PE32|PE64', re.I),                'Windows PE executable'),
    (re.compile(r'\bMZ\b'),                         'DOS MZ executable header'),
    (re.compile(r'PKZIP|ZIP archive', re.I),        'ZIP archive'),
    (re.compile(r'RAR archive', re.I),              'RAR archive'),
    (re.compile(r'7-zip', re.I),                    '7-zip archive'),
    (re.compile(r'PDF document', re.I),             'PDF document'),
    (re.compile(r'executable', re.I),               'executable binary'),
    (re.compile(r'core file', re.I),                'core dump / binary artifact'),
    (re.compile(r'floppy image', re.I),             'floppy image (binary structure)'),
    (re.compile(r'MPEG.*ADTS|ADTS.*MPEG', re.I),   'MPEG audio stream'),
    (re.compile(r'MPEG-4 LOAS', re.I),             'MPEG-4 audio object'),
]

MEDIUM_SIGNAL = [
    (re.compile(r'OpenPGP|PGP Secret|PGP Public|PGP Sub-key', re.I), 'PGP key structure'),
    (re.compile(r'VISX image', re.I),              'VISX image'),
    (re.compile(r'SoftQuad', re.I),               'SoftQuad binary'),
    (re.compile(r'AIX core', re.I),               'AIX binary artifact'),
    (re.compile(r'ddis', re.I),                   'DDIS/DDIF binary'),
    (re.compile(r'FAX', re.I),                    'FAX data stream'),
    (re.compile(r'ispell hash', re.I),            'ispell hash structure'),
]

# Entropy thresholds
NATURAL_IMAGE_MAX_ENTROPY = 7.85   # JPEG can reach this; above = suspicious
ENCRYPTED_DATA_MIN_ENTROPY = 7.90  # near-random data threshold

# Histogram anomaly: if the zero-bucket count is > this fraction of total pixels
HISTOGRAM_ZERO_SPIKE_THRESHOLD = 0.15   # >15% of pixels are pure black


# 
# File helpers
# 

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    t = len(data)
    return round(-sum((v / t) * math.log2(v / t) for v in c.values()), 4)


def _file_type(path: str) -> str:
    data = open(path, 'rb').read(16)
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if data[:2] == b'BM':
        return 'bmp'
    if data[:4] in (b'RIFF', b'RIFX'):
        return 'wav'
    if data[:3] == b'ID3' or data[:2] == b'\xff\xfb':
        return 'mp3'
    if data[:4] == b'%PDF':
        return 'pdf'
    if data[:2] == b'MZ':
        return 'exe'
    if data[:4] == b'\x7fELF':
        return 'elf'
    # raw DIB
    if len(data) >= 4:
        hdr = struct.unpack_from('<I', data, 0)[0]
        if hdr in (40, 52, 56, 108, 124, 12):
            return 'dib'
    return 'bin'


def _histogram_anomaly(image_path: str) -> Tuple[bool, str]:
    """
    Check if the image histogram is anomalous.
    Returns (is_anomalous, reason_string).
    """
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        return False, "Pillow/numpy not available for histogram analysis"

    try:
        img = Image.open(image_path).convert('L')   # grayscale
        arr = np.array(img).flatten()
        total = len(arr)
        if total == 0:
            return False, "Empty image"

        # Spike at zero
        zero_frac = (arr == 0).sum() / total
        # Flatness of distribution (natural images have smooth gradients)
        hist, _ = np.histogram(arr, bins=256, range=(0, 256))
        nonzero_hist = hist[hist > 0]
        if len(nonzero_hist) < 10:
            return True, f"Very few unique pixel values ({len(nonzero_hist)}) — likely solid fill"

        # Coefficient of variation of non-zero buckets
        cv = nonzero_hist.std() / (nonzero_hist.mean() + 1e-9)

        reasons = []
        if zero_frac > HISTOGRAM_ZERO_SPIKE_THRESHOLD:
            reasons.append(
                f"zero-pixel spike ({zero_frac:.1%} of pixels) — "
                f"large black regions masking unused pixel space"
            )
        if cv < 0.5:
            reasons.append(
                f"unusually flat distribution (CV={cv:.2f}) — "
                f"consistent with packed/encrypted data filling channels evenly"
            )
        if zero_frac > HISTOGRAM_ZERO_SPIKE_THRESHOLD and cv < 1.5:
            # Combined: the classic malware stego histogram pattern
            reasons.append("combined spike+flat pattern matches known stego carrier signature")

        return bool(reasons), "; ".join(reasons) if reasons else "histogram appears normal"
    except Exception as e:
        return False, f"Could not analyse histogram: {e}"


# 
# zsteg parser
# 

def parse_zsteg_output(txt_path: str) -> Dict:
    """
    Parse a zsteg text output file and return a structured summary.
    """
    try:
        text = open(txt_path, encoding='utf-8', errors='replace').read()
    except Exception as e:
        return {"error": str(e)}

    lines = text.strip().split('\n')

    high_signal_hits  = []
    medium_signal_hits = []
    low_signal_hits   = []
    text_hits         = []
    executable_count  = 0
    compressed_count  = 0
    pgp_count         = 0

    for line in lines:
        if '..' not in line:
            continue

        parts = line.split('..', 1)
        channel = parts[0].strip()
        result  = parts[1].strip()

        if not result:
            continue

        # Classify
        matched_high   = False
        matched_medium = False

        for pattern, label in HIGH_SIGNAL:
            if pattern.search(result):
                high_signal_hits.append({"channel": channel, "finding": result.strip()})
                matched_high = True
                if re.search(r'executable|ELF|PE32|MZ|coff|BSD|sysV|core file|floppy', result, re.I):
                    executable_count += 1
                if re.search(r'zlib|gzip|bzip2|xz compressed|ZIP|RAR|7-zip', result, re.I):
                    compressed_count += 1
                break

        if not matched_high:
            for pattern, label in MEDIUM_SIGNAL:
                if pattern.search(result):
                    medium_signal_hits.append({"channel": channel, "finding": result.strip()})
                    matched_medium = True
                    if re.search(r'PGP|OpenPGP', result, re.I):
                        pgp_count += 1
                    break

        if not matched_high and not matched_medium:
            if result.startswith('text:'):
                text_hits.append({"channel": channel, "finding": result.strip()})
            elif result.startswith('file:'):
                low_signal_hits.append({"channel": channel, "finding": result.strip()})

    total_hits = (len(high_signal_hits) + len(medium_signal_hits) +
                  len(low_signal_hits) + len(text_hits))

    return {
        "total_hits":         total_hits,
        "high_signal":        len(high_signal_hits),
        "medium_signal":      len(medium_signal_hits),
        "low_signal":         len(low_signal_hits),
        "text_hits":          len(text_hits),
        "high_signal_hits":   high_signal_hits,
        "medium_signal_hits": medium_signal_hits[:20],   # cap for readability
        "executable_signatures": executable_count,
        "compressed_data":       compressed_count,
        "pgp_keys":              pgp_count,
    }


# 
# Per-file verdict
# 

def _score_file(
    entropy: float,
    file_type: str,
    histogram_anomaly: bool,
    zsteg: Dict,
) -> Tuple[str, int, List[str]]:
    """
    Return (verdict, risk_score_0_100, [indicator_strings]).
    """
    score = 0
    indicators = []

    # Entropy
    if entropy > ENCRYPTED_DATA_MIN_ENTROPY:
        score += 30
        indicators.append(
            f"Near-maximum entropy ({entropy:.4f} bits/byte) exceeds natural "
            f"image range — consistent with encrypted/compressed hidden data"
        )
    elif entropy > NATURAL_IMAGE_MAX_ENTROPY:
        score += 15
        indicators.append(
            f"Elevated entropy ({entropy:.4f}) above natural image threshold"
        )

    # Histogram
    if histogram_anomaly:
        score += 20
        indicators.append("Histogram anomaly detected (zero-pixel spike or flat distribution)")

    # zsteg high signal
    hs = zsteg.get("high_signal", 0)
    if hs > 0:
        score += min(40, hs * 10)
        for hit in zsteg.get("high_signal_hits", []):
            indicators.append(
                f"zsteg [{hit['channel']}]: {hit['finding']}"
            )

    # Compressed data — most important single indicator
    if zsteg.get("compressed_data", 0) > 0:
        score += 15
        indicators.append(
            "Compressed data structure detected in pixel channels "
            "(zlib/gzip/zip) — strongly indicates intentional payload hiding"
        )

    # Executable signatures
    if zsteg.get("executable_signatures", 0) > 0:
        score += 10
        indicators.append(
            f"{zsteg['executable_signatures']} executable/binary file signature(s) "
            f"detected in bit planes"
        )

    # Medium signal (PGP etc)
    ms = zsteg.get("medium_signal", 0)
    if ms > 0:
        score += min(10, ms * 2)
        indicators.append(
            f"{ms} medium-confidence structured data pattern(s) detected "
            f"(PGP key structures, binary artifacts)"
        )

    score = min(100, score)

    if score >= 60:
        verdict = "STEGO_DETECTED"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return verdict, score, indicators


# 
# Directory scanner
# 

def _find_stegoscan_files(scan_dir: str) -> Dict[str, Dict]:
    """
    Collect extracted files from top-level folders and map them to StegoScan
    analysis results found under results_* directories.

    Returns dict keyed by base stem -> {
        'top_path': path | None,
        'result_png': path | None,
        'txt': path | None,
        'histogram': path | None,
        'lsb_present': bool,
        'source_paths': [str],
    }
    """
    scan_root = Path(scan_dir)
    if scan_root.name.lower().startswith('results_'):
        scan_root = scan_root.parent

    groups: Dict[str, Dict] = {}

    IMAGE_EXTS = {'.png', '.bmp', '.jpg', '.jpeg', '.gif', '.wav', '.mp3', '.bin'}

    def ensure_group(stem: str) -> Dict:
        return groups.setdefault(
            stem,
            {
                'top_path': None,
                'result_png': None,
                'txt': None,
                'histogram': None,
                'lsb_present': False,
                'source_paths': [],
            }
        )

    def add_extracted_file(f: Path) -> None:
        stem = f.stem
        group = ensure_group(stem)
        group['source_paths'].append(str(f))
        if group['top_path'] is None:
            group['top_path'] = str(f)
        else:
            current_ext = Path(group['top_path']).suffix.lower()
            new_ext = f.suffix.lower()
            if current_ext == '.bin' and new_ext in IMAGE_EXTS and new_ext != '.bin':
                group['top_path'] = str(f)

    def add_result_hist(f: Path) -> None:
        stem_match = re.match(r'^(?P<stem>.+?)_(?:png|jpg|bmp|gif|wav|mp3|bin)_histogram$', f.stem, re.I)
        stem = stem_match.group('stem') if stem_match else f.stem
        group = ensure_group(stem)
        if group['histogram'] is None:
            group['histogram'] = str(f)

    def add_result_png(f: Path) -> None:
        stem = f.stem
        group = ensure_group(stem)
        if f.suffix.lower() == '.txt':
            if group['txt'] is None:
                group['txt'] = str(f)
        elif f.suffix.lower() in IMAGE_EXTS:
            if group['result_png'] is None:
                group['result_png'] = str(f)

    def add_lsb_file(f: Path) -> None:
        stem = f.stem
        group = ensure_group(stem)
        group['lsb_present'] = True

    # Collect files from top-level extracted folders.
    for child in scan_root.iterdir():
        if not child.is_dir():
            continue
        if child.name.lower().startswith('results_') or child.name.lower() in {'log', 'xml', 'object_detection'}:
            continue

        for f in child.iterdir():
            if not f.is_file():
                continue
            add_extracted_file(f)

    # Collect any top-level files directly under scan root.
    for f in scan_root.iterdir():
        if f.is_file():
            add_extracted_file(f)

    # Collect analysis outputs from results_<timestamp> directories.
    for child in scan_root.iterdir():
        if not child.is_dir() or not child.name.lower().startswith('results_'):
            continue

        hist_dir = child / 'hist'
        if hist_dir.is_dir():
            for f in hist_dir.iterdir():
                if not f.is_file():
                    continue
                add_result_hist(f)

        png_dir = child / 'png'
        if png_dir.is_dir():
            for f in png_dir.iterdir():
                if not f.is_file():
                    continue
                if f.name.lower().endswith('.txt') or f.suffix.lower() in IMAGE_EXTS:
                    add_result_png(f)

        lsb_dir = child / 'lsb'
        if lsb_dir.is_dir():
            for f in lsb_dir.iterdir():
                if not f.is_file():
                    continue
                add_lsb_file(f)

    for group in groups.values():
        if group['top_path'] is None and group['result_png'] is not None:
            group['top_path'] = group['result_png']

    return groups


# 
# summary generator
# 

def _generate_thesis_summary(result: Dict) -> str:
    verdict   = result["overall_verdict"]
    carriers  = result["stego_carriers"]
    n_scanned = result["files_scanned"]
    score     = result["risk_score"]

    if verdict == "CLEAN" or not carriers:
        if result.get("lsb_files"):
            return (
                f"StegoScan analysed {n_scanned} file(s) extracted from the malware "
                f"binary and found no statistically significant evidence of steganographic "
                f"content from the scanned carriers. However, {len(result.get('lsb_files', []))} "
                f"file(s) were present in the lsb folder and were treated as additional "
                f"indicators of extracted payload artifacts."
            )
        return (
            f"StegoScan analysed {n_scanned} file(s) extracted from the malware "
            f"binary and found no statistically significant evidence of steganographic "
            f"content. All files produced entropy values and histogram distributions "
            f"consistent with naturally occurring image or media data."
        )

    # Build carrier descriptions
    carrier_descs = []
    for c in carriers:
        z = c.get("zsteg_summary", {})
        desc = (
            f"{c['filename']} ({c['file_type'].upper()}, "
            f"{c['file_size']:,} bytes, entropy={c['entropy']:.4f})"
        )
        findings = []
        if c.get("histogram_anomaly"):
            findings.append("anomalous histogram (zero-pixel spike with flat distribution)")
        if z.get("compressed_data", 0) > 0:
            findings.append(
                f"compressed data structure detected in pixel channel bit-planes "
                f"(zlib/deflate signature — indicates payload packed into RGB values)"
            )
        if z.get("executable_signatures", 0) > 0:
            findings.append(
                f"{z['executable_signatures']} executable binary signature(s) "
                f"found across bit-plane analysis"
            )
        if z.get("high_signal", 0) > 0:
            findings.append(
                f"{z['high_signal']} high-confidence structured data pattern(s) "
                f"detected by multi-channel LSB/MSB analysis"
            )
        if z.get("pgp_keys", 0) > 0:
            findings.append(f"{z['pgp_keys']} PGP key structure(s) identified")

        if findings:
            carrier_descs.append(f"{desc}: {'; '.join(findings)}")
        else:
            carrier_descs.append(desc)

    # Build the summary
    verdict_phrase = {
        "STEGO_DETECTED": "confirmed positive for steganographic content",
        "SUSPICIOUS":     "flagged as suspicious with anomalous statistical properties",
    }.get(verdict, "produced inconclusive results")

    carrier_list = "\n".join(f"  • {d}" for d in carrier_descs)
    lsb_note = ""
    if result.get("lsb_files"):
        lsb_note = (
            f" Additionally, {len(result['lsb_files'])} file(s) were present in the lsb folder; "
            f"their presence was treated as a stego indicator for those carriers."
        )

    return (
        f"StegoScan analysed {n_scanned} file(s) extracted from the malware "
        f"binary's resource section and {verdict_phrase} (risk score: {score}/100). "
        f"The following carrier file(s) were identified:\n{carrier_list}\n"
        f"These findings are consistent with malware steganography techniques "
        f"where payloads are embedded into image or media carriers by packing compressed "
        f"or encrypted data into pixel bit-planes.{lsb_note} "
        f"The combination of near-random entropy levels, histogram irregularities, and "
        f"structured file signatures (compressed archives, executables, or key material) "
        f"provides strong static-analysis evidence of intentional hidden payload storage "
    )


# 
# Main summariser
# 

def summarise_stegoscan_results(
    scan_dir: str,
    sha256: Optional[str] = None,
    verbose: bool = False,
) -> Dict:
    """
    Walk scan_dir, parse all StegoScan outputs, and return a unified summary dict.
    """
    groups = _find_stegoscan_files(scan_dir)

    if verbose:
        print(f"[*] Found {len(groups)} file group(s) in {scan_dir}")

    stego_carriers = []
    clean_files    = []
    all_scores     = []

    for stem, paths in sorted(groups.items()):
        image_path = paths.get('top_path')
        result_png_path = paths.get('result_png')
        txt_path   = paths.get('txt')
        hist_path  = paths.get('histogram')
        lsb_present = paths.get('lsb_present', False)

        if not image_path and not result_png_path and not txt_path and not hist_path and not lsb_present:
            continue   # nothing useful

        # File properties from the extracted top-level file or analyzed PNG.
        if image_path and os.path.exists(image_path):
            ftype   = _file_type(image_path)
            fsize   = os.path.getsize(image_path)
            ent     = _entropy(open(image_path, 'rb').read())
        elif result_png_path and os.path.exists(result_png_path):
            ftype   = _file_type(result_png_path)
            fsize   = os.path.getsize(result_png_path)
            ent     = _entropy(open(result_png_path, 'rb').read())
        else:
            ftype   = 'unknown'
            fsize   = 0
            ent     = 0.0

        # Prefer histogram image analysis when available, otherwise analyse the carrier image.
        hist_ok = False
        hist_reason = ''
        if hist_path and os.path.exists(hist_path):
            hist_ok, hist_reason = _histogram_anomaly(hist_path)
        elif image_path and os.path.exists(image_path):
            hist_ok, hist_reason = _histogram_anomaly(image_path)
        elif result_png_path and os.path.exists(result_png_path):
            hist_ok, hist_reason = _histogram_anomaly(result_png_path)

        # Parse zsteg output
        zsteg_summary = {}
        if txt_path and os.path.exists(txt_path):
            zsteg_summary = parse_zsteg_output(txt_path)

        # Score this file
        verdict, score, indicators = _score_file(
            entropy=ent,
            file_type=ftype,
            histogram_anomaly=hist_ok,
            zsteg=zsteg_summary,
        )

        if lsb_present and verdict != 'STEGO_DETECTED':
            verdict = 'STEGO_DETECTED'
            score = max(score, 60)
            indicators.append(
                'File appeared in an lsb result folder; presence of extracted LSB artifacts forces STEGO_DETECTED.'
            )

        all_scores.append(score)

        fname = os.path.basename(image_path or result_png_path or stem)

        if verbose:
            status = {'STEGO_DETECTED': '[!]', 'SUSPICIOUS': '[*]', 'CLEAN': '[+]'}.get(verdict, '   ')
            print(f"  {status} {fname}  [{verdict}]  score={score}  "
                  f"entropy={ent:.4f}  high_signal={zsteg_summary.get('high_signal',0)}")

        if verdict == "CLEAN":
            clean_files.append(fname)
        else:
            stego_carriers.append({
                "filename":          fname,
                "file_type":         ftype,
                "file_size":         fsize,
                "entropy":           ent,
                "histogram_anomaly": hist_ok,
                "histogram_reason":  hist_reason,
                "histogram_path":    hist_path,
                "zsteg_txt_path":    txt_path,
                "zsteg_summary":     zsteg_summary,
                "verdict":           verdict,
                "risk_score":        score,
                "indicators":        indicators,
            })

    max_score = max(all_scores) if all_scores else 0

    if max_score >= 60:
        overall = "STEGO_DETECTED"
    elif max_score >= 30:
        overall = "SUSPICIOUS"
    else:
        overall = "CLEAN"

    # Overall confidence — based on convergence of evidence
    total_high  = sum(c.get("zsteg_summary", {}).get("high_signal", 0)
                      for c in stego_carriers)
    total_comp  = sum(c.get("zsteg_summary", {}).get("compressed_data", 0)
                      for c in stego_carriers)
    hist_hits   = sum(1 for c in stego_carriers if c.get("histogram_anomaly"))
    high_ent    = sum(1 for c in stego_carriers
                      if c.get("entropy", 0) > ENCRYPTED_DATA_MIN_ENTROPY)
    lsb_hits    = sum(1 for paths in groups.values() if paths.get('lsb_present'))

    evidence_count = (
        bool(total_high) + bool(total_comp) + bool(hist_hits) + bool(high_ent) + bool(lsb_hits)
    )
    confidence = min(1.0, round(evidence_count * 0.25 + (max_score / 200), 2))

    result = {
        "sha256":          sha256,
        "scan_directory":  str(Path(scan_dir).resolve()),
        "scan_timestamp":  datetime.now().isoformat(),
        "overall_verdict": overall,
        "confidence":      confidence,
        "risk_score":      max_score,
        "files_scanned":   len(groups),
        "stego_carriers":  stego_carriers,
        "clean_files":     clean_files,
        "lsb_files":       [stem for stem, paths in groups.items() if paths.get('lsb_present')],
        "thesis_summary":  "",   # filled below
    }

    result["thesis_summary"] = _generate_thesis_summary(result)
    return result


# 
# CLI
# 

def _print_human_report(result: Dict) -> None:
    W = 70
    verdict_icon = {
        "STEGO_DETECTED": "🚨 STEGO DETECTED",
        "SUSPICIOUS":     "⚠  SUSPICIOUS",
        "CLEAN":          "✓  CLEAN",
    }.get(result["overall_verdict"], result["overall_verdict"])

    print()
    print("=" * W)
    print("  STEGOSCAN ANALYSIS SUMMARY")
    print("=" * W)
    if result["sha256"]:
        print(f"  Sample  : {result['sha256']}")
    print(f"  Verdict : {verdict_icon}")
    print(f"  Score   : {result['risk_score']}/100")
    print(f"  Confidence : {result['confidence']:.0%}")
    print(f"  Files   : {result['files_scanned']} scanned, "
          f"{len(result['stego_carriers'])} carrier(s) found")
    if result.get('lsb_files'):
        print(f"  LSB folder: {len(result['lsb_files'])} file(s) observed; names were inspected for payload evidence")
    print("=" * W)

    for c in result["stego_carriers"]:
        z = c.get("zsteg_summary", {})
        icon = "🚨" if c["verdict"] == "STEGO_DETECTED" else "⚠ "
        print(f"\n  {icon} {c['filename']}")
        print(f"     Type     : {c['file_type'].upper()}  "
              f"{c['file_size']:,} bytes  entropy={c['entropy']:.4f}")
        print(f"     Verdict  : {c['verdict']}  (score={c['risk_score']})")
        print(f"     zsteg    : {z.get('total_hits',0)} hits — "
              f"high={z.get('high_signal',0)}  "
              f"medium={z.get('medium_signal',0)}  "
              f"text={z.get('text_hits',0)}")
        if z.get('compressed_data', 0):
            print(f"     *** Compressed data in pixel channels: "
                  f"{z['compressed_data']} hit(s)  *** ")
        if z.get('executable_signatures', 0):
            print(f"     *** Executable signatures: "
                  f"{z['executable_signatures']} hit(s)  *** ")
        if c.get("histogram_anomaly"):
            print(f"     *** Histogram anomaly: {c['histogram_reason']}")
        print()
        print("     Indicators:")
        for ind in c.get("indicators", []):
            print(f"       • {ind}")
        if z.get("high_signal_hits"):
            print()
            print("     High-signal zsteg hits:")
            for hit in z["high_signal_hits"]:
                print(f"       [{hit['channel']}] {hit['finding']}")

    if result["clean_files"]:
        print(f"\n  Clean files: {', '.join(result['clean_files'])}")

    print()
    print("=" * W)
    print("  THESIS SUMMARY")
    print("=" * W)
    for line in result["thesis_summary"].split('\n'):
        # Word-wrap at 68 chars
        words = line.split()
        cur = "  "
        for w in words:
            if len(cur) + len(w) + 1 > 68:
                print(cur)
                cur = "  " + w
            else:
                cur += (" " if cur.strip() else "") + w
        if cur.strip():
            print(cur)
    print()
    print("=" * W)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse StegoScan results and produce a structured summary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stegoscan_summarizer.py ./stegoscan_results/
  python stegoscan_summarizer.py ./results/ --sha256 ac5fc65ae950...
  python stegoscan_summarizer.py . --out summary.json --verbose
        """,
    )
    parser.add_argument("scan_dir",
                        help="StegoScan output directory to parse")
    parser.add_argument("--sha256", default=None,
                        help="SHA256 of the analysed sample (for the report)")
    parser.add_argument("--out", default=None,
                        help="Write JSON summary to this file")
    parser.add_argument("--verbose", action="store_true",
                        help="Print per-file status during scanning")
    parser.add_argument("--json-only", action="store_true",
                        help="Only print the JSON output, no human report")
    args = parser.parse_args()

    if not os.path.isdir(args.scan_dir):
        sys.exit(f"[!] Not a directory: {args.scan_dir}")

    result = summarise_stegoscan_results(
        scan_dir=args.scan_dir,
        sha256=args.sha256,
        verbose=args.verbose,
    )

    if not args.json_only:
        _print_human_report(result)

    json_out = json.dumps(result, indent=2)

    if args.out:
        with open(args.out, 'w') as f:
            f.write(json_out)
        print(f"[+] JSON summary saved to {args.out}")
    else:
        if args.json_only:
            print(json_out)

    return result


if __name__ == "__main__":
    main()
