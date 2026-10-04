import sys
import json
import argparse
from pathlib import Path

#  Fuzzy hashing backend import (portable) 

_ssdeep_backend = None
_backend_name = None

try:
    import ssdeep as _ssdeep_backend
    _backend_name = "ssdeep"
except ImportError:
    try:
        import pyssdeep as _ssdeep_backend
        _backend_name = "pyssdeep"
    except ImportError:
        try:
            import ppdeep as _ssdeep_backend
            _backend_name = "ppdeep"
        except ImportError:
            _ssdeep_backend = None
            _backend_name = None

if _ssdeep_backend is None:
    print(
        "[!] No fuzzy hashing backend found.\n"
        "    Install one of:\n"
        "      pip install ssdeep\n"
        "      pip install pyssdeep\n"
        "      pip install ppdeep\n"
        "\n"
        "    Notes:\n"
        "      - On Linux, ssdeep may require: sudo apt install libfuzzy-dev\n"
        "      - On Windows, ssdeep often fails to compile; pyssdeep/ppdeep are easier.\n"
    )
    sys.exit(1)


#  Backend wrappers (normalize API differences) 

def fuzzy_hash_file(path: str) -> str:
    """
    Compute fuzzy hash from file contents using whichever backend is installed.
    """

    # ssdeep (best, normal API)
    if _backend_name == "ssdeep":
        return _ssdeep_backend.hash_from_file(path)

    # pyssdeep (API differs depending on build)
    if _backend_name == "pyssdeep":
        if hasattr(_ssdeep_backend, "hash_from_file"):
            return _ssdeep_backend.hash_from_file(path)

        if hasattr(_ssdeep_backend, "hash_file"):
            return _ssdeep_backend.hash_file(path)

        if hasattr(_ssdeep_backend, "get_hash_file"):
            return _ssdeep_backend.get_hash_file(path)

        if hasattr(_ssdeep_backend, "fuzzy_hash_filename"):
            return _ssdeep_backend.fuzzy_hash_filename(path)

        # Fallback: read file content and hash bytes
        if hasattr(_ssdeep_backend, "hash"):
            with open(path, "rb") as f:
                data = f.read()
            return _ssdeep_backend.hash(data)

        if hasattr(_ssdeep_backend, "fuzzy_hash_buf"):
            with open(path, "rb") as f:
                data = f.read()
            return _ssdeep_backend.fuzzy_hash_buf(data)

        raise RuntimeError("pyssdeep backend does not support hashing files.")

    # ppdeep (usually supports hashing bytes, sometimes hash_from_file)
    if _backend_name == "ppdeep":
        if hasattr(_ssdeep_backend, "hash_from_file"):
            return _ssdeep_backend.hash_from_file(path)

        with open(path, "rb") as f:
            data = f.read()

        return _ssdeep_backend.hash(data)

    raise RuntimeError("No valid fuzzy hashing backend loaded.")


def fuzzy_compare(hash_a: str, hash_b: str) -> int:
    """
    Compare two fuzzy hashes and return similarity score [0, 100].
    """
    if not hash_a or not hash_b:
        return 0

    if hasattr(_ssdeep_backend, "compare"):
        try:
            return int(_ssdeep_backend.compare(hash_a, hash_b))
        except Exception:
            return 0

    if hasattr(_ssdeep_backend, "compare_hashes"):
        try:
            return int(_ssdeep_backend.compare_hashes(hash_a, hash_b))
        except Exception:
            return 0

    return 0


#  Shared helpers 

def extract_ssdeep(data: dict) -> str | None:
    """
    Pull the ssdeep fuzzy hash out of a report dict.

    Primary path:
        threat_intelligence → VirusTotal → <sha256> → ssdeep

    Falls back to checking every VT entry in case the keying differs.
    Returns the hash string, or None if not found.
    """
    vt = data.get("threat_intelligence", {}).get("VirusTotal", {})
    if not vt:
        return None

    sha256 = (
        data.get("ingest_analysis", {}).get("sha256")
        or data.get("static_analysis", {}).get("hashes", {}).get("sha256")
    )

    if sha256 and sha256 in vt:
        h = vt[sha256].get("ssdeep")
        if h:
            return h

    for entry in vt.values():
        if isinstance(entry, dict):
            h = entry.get("ssdeep")
            if h:
                return h

    return None


def load_report(json_path: Path) -> dict | None:
    """
    Load and validate a single report JSON from disk.

    Returns the parsed dict, or None if the file cannot be parsed or is
    missing a usable ssdeep hash.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  [!] Could not load {json_path.name}: {e}")
        return None

    if extract_ssdeep(data) is None:
        print(f"  [!] Skipping {json_path.name}: no ssdeep hash found")
        return None

    return data


def extract_binary_id(data: dict, json_path: Path) -> str:
    """
    Return a human-readable identifier for the binary.
    Prefers sha256 from ingest_analysis, falls back to the JSON filename stem.
    """
    sha = (
        data.get("ingest_analysis", {}).get("sha256")
        or data.get("static_analysis", {}).get("hashes", {}).get("sha256")
    )
    filename = data.get("ingest_analysis", {}).get("filename") or json_path.stem

    if sha:
        return f"{filename} [{sha[:12]}]"
    return filename


def _extract_binary_id_from_report(report: dict) -> str:
    """
    Extract a binary_id from an in-memory report dict (no json_path available).
    """
    ia = report.get("ingest_analysis", {})
    sha = ia.get("sha256") or report.get("static_analysis", {}).get("hashes", {}).get("sha256")
    filename = ia.get("filename") or "unknown"

    if sha:
        return f"{filename} [{sha[:12]}]"
    return filename


def compare_ssdeep(hash_a: str, hash_b: str) -> int:
    """
    Compare two fuzzy hashes and return similarity score in [0, 100].
    """
    return fuzzy_compare(hash_a, hash_b)


#  Flexible similarity scoring 

def _resolve_to_hash(item, suppress_warnings: bool = False) -> str | None:
    """
    Convert various input types to a fuzzy hash string.

    Supports:
        - JSON report file path (.json)
        - Binary file path
        - Report dict
        - Raw ssdeep hash string
    """
    if isinstance(item, (str, Path)):
        path = Path(item)

        # JSON report
        if path.exists() and path.is_file() and path.suffix.lower() == ".json":
            try:
                with open(path, "r", encoding="utf-8") as f:
                    report = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                if not suppress_warnings:
                    print(f"  [!] Could not load {path.name}: {e}")
                return None

            hash_val = extract_ssdeep(report)
            if hash_val is None:
                if not suppress_warnings:
                    print(f"  [!] {path.name}: no ssdeep hash found in this report")
                raise ValueError(f"JSON file {path.name} has no ssdeep field")

            return hash_val

        # Binary file
        if path.exists() and path.is_file():
            try:
                return fuzzy_hash_file(str(path))
            except Exception as e:
                if not suppress_warnings:
                    print(f"  [!] Could not compute fuzzy hash for {path.name}: {e}")
                return None

        # Otherwise treat as raw fuzzy hash string
        return str(item)

    if isinstance(item, dict):
        hash_val = extract_ssdeep(item)
        if hash_val is None:
            raise ValueError("Report dict has no ssdeep field")
        return hash_val

    return None


def calculate_similarity(item_a, item_b, suppress_warnings: bool = False) -> int:
    """
    Calculate fuzzy similarity score between two items.

    Items may be:
        - JSON report file path (.json)
        - Binary file path
        - Report dict
        - Raw fuzzy hash string
    """
    hash_a = _resolve_to_hash(item_a, suppress_warnings=suppress_warnings)
    hash_b = _resolve_to_hash(item_b, suppress_warnings=suppress_warnings)
    return compare_ssdeep(hash_a, hash_b)


def calculate_file_similarity(file_a, file_b) -> int:
    """
    Calculate fuzzy similarity score between two binary files.
    """
    file_a = Path(file_a)
    file_b = Path(file_b)

    if not file_a.exists():
        raise FileNotFoundError(f"File not found: {file_a}")
    if not file_b.exists():
        raise FileNotFoundError(f"File not found: {file_b}")

    if not file_a.is_file():
        raise IOError(f"Not a file: {file_a}")
    if not file_b.is_file():
        raise IOError(f"Not a file: {file_b}")

    hash_a = fuzzy_hash_file(str(file_a))
    hash_b = fuzzy_hash_file(str(file_b))

    return compare_ssdeep(hash_a, hash_b)


#  Single-report comparison (pipeline mode) 

def compare_single_report(
    new_report: dict,
    reports_dir: str | Path,
    min_score: int = 1,
) -> list[dict]:
    """
    Compare a newly processed report against every existing JSON in reports_dir
    using fuzzy hashing.

    Returns list of match dicts sorted by score descending.
    """
    reports_dir = Path(reports_dir)
    new_id = _extract_binary_id_from_report(new_report)
    new_hash = extract_ssdeep(new_report)

    if new_hash is None:
        print(f"[!] ssdeep similarity: no ssdeep hash in new report for {new_id}")
        return []

    matches = []

    for jp in sorted(reports_dir.glob("*.json")):
        existing = load_report(jp)
        if existing is None:
            continue

        existing_id = extract_binary_id(existing, jp)
        existing_hash = extract_ssdeep(existing)

        if existing_id == new_id:
            continue

        score = compare_ssdeep(new_hash, existing_hash)
        if score < min_score:
            continue

        matches.append({
            "binary_id": existing_id,
            "ssdeep_score": score,
            "ssdeep_new": new_hash,
            "ssdeep_match": existing_hash,
        })

    matches.sort(key=lambda x: x["ssdeep_score"], reverse=True)

    if matches:
        print(f"[+] ssdeep similarity ({_backend_name}): {len(matches)} match(es) found for {new_id}")
        for m in matches:
            print(f"    → {m['binary_id']}  |  score: {m['ssdeep_score']}/100")
    else:
        print(f"[+] ssdeep similarity ({_backend_name}): no matches found for {new_id}")

    return matches


#  Full-folder scan (standalone mode) 

def run(reports_dir: str, min_score: int, output_path: str | None):
    """
    Scan an entire directory of report JSONs and print all pairs whose
    fuzzy similarity score meets the threshold.
    """
    reports_dir = Path(reports_dir)

    if not reports_dir.is_dir():
        print(f"[-] Not a directory: {reports_dir}")
        sys.exit(1)

    json_files = sorted(reports_dir.glob("*.json"))
    if not json_files:
        print(f"[-] No JSON files found in {reports_dir}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  ssdeep Fuzzy Hash Similarity Check")
    print(f"{'='*60}")
    print(f"[+] Backend used      : {_backend_name}")
    print(f"[+] Reports directory : {reports_dir}")
    print(f"[+] JSON files found  : {len(json_files)}")
    print(f"[+] Min ssdeep score  : {min_score}/100")
    print()

    print("[*] Loading reports...")
    reports = []

    for jp in json_files:
        data = load_report(jp)
        if data is None:
            continue

        binary_id = extract_binary_id(data, jp)
        ssdeep_hash = extract_ssdeep(data)

        reports.append({
            "binary_id": binary_id,
            "ssdeep_hash": ssdeep_hash,
            "json_path": str(jp),
        })

        print(f"  [+] {binary_id}")
        print(f"       ssdeep: {ssdeep_hash}")

    if len(reports) < 2:
        print("\n[-] Need at least 2 valid reports to compare. Exiting.")
        sys.exit(1)

    print(f"\n[+] Loaded {len(reports)} reports successfully.")
    print("[*] Comparing binaries...")

    pairs_found = 0
    output_records = []

    for i in range(len(reports)):
        for j in range(i + 1, len(reports)):
            a = reports[i]
            b = reports[j]

            score = compare_ssdeep(a["ssdeep_hash"], b["ssdeep_hash"])
            if score < min_score:
                continue

            pairs_found += 1
            print(f"\n  ┌ Pair ")
            print(f"  │  A     : {a['binary_id']}")
            print(f"  │  B     : {b['binary_id']}")
            print(f"  │  Score : {score}/100")
            print(f"  │  Hash A: {a['ssdeep_hash']}")
            print(f"  │  Hash B: {b['ssdeep_hash']}")
            print(f"  └")

            output_records.append({
                "binary_a": a["binary_id"],
                "binary_b": b["binary_id"],
                "ssdeep_score": score,
                "ssdeep_a": a["ssdeep_hash"],
                "ssdeep_b": b["ssdeep_hash"],
            })

    print(f"\n{'='*60}")
    print(f"  Results: {pairs_found} pair(s) found above threshold")
    print(f"{'='*60}")

    if output_path:
        out = Path(output_path)
        with open(out, "w", encoding="utf-8") as f:
            json.dump({
                "backend_used": _backend_name,
                "reports_directory": str(reports_dir),
                "reports_scanned": len(reports),
                "min_score": min_score,
                "pairs_found": len(output_records),
                "results": sorted(output_records, key=lambda x: x["ssdeep_score"], reverse=True),
            }, f, indent=2)

        print(f"[+] Full results written to: {out}")

    print("[+] Done.")


#  Entry point 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compare binary analysis JSON reports by ssdeep fuzzy hash."
    )
    parser.add_argument(
        "reports_dir",
        help="Directory containing the binary analysis JSON reports"
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=1,
        metavar="N",
        help="Minimum ssdeep similarity score (1-100) to report a pair (default: 1)"
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Optional path to write full results as JSON"
    )

    args = parser.parse_args()
    run(args.reports_dir, args.min_score, args.output)
