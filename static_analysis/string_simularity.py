import json
import re
from pathlib import Path


#  Helpers 

def load_report(json_path: Path) -> dict | None:
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def extract_sha256(report: dict) -> str:
    return (
        report.get("ingest_analysis", {}).get("sha256")
        or report.get("static_analysis", {}).get("hashes", {}).get("sha256")
        or ""
    )


def extract_binary_id(data: dict, json_path: Path) -> str:
    sha = extract_sha256(data)
    filename = data.get("ingest_analysis", {}).get("filename") or json_path.stem
    return f"{filename} [{sha[:12]}]" if sha else filename


#  STRING NORMALIZATION + CLASSIFICATION 

NORMALIZATION_MAP = {
    "createfile": "file_open",
    "open": "file_open",
    "writefile": "file_write",
    "write": "file_write",
    "readfile": "file_read",
    "read": "file_read",
    "createremotethread": "process_inject",
    "ptrace": "process_inject",
    "regopenkey": "registry_open",
    "/etc/passwd": "sensitive_file"
}


def normalize_string(s: str) -> str:
    if not isinstance(s, str):
        return ""

    s = s.strip().lower()

    if len(s) < 4:
        return ""

    alnum_ratio = sum(c.isalnum() for c in s) / len(s)
    if alnum_ratio < 0.3:
        return ""

    # Apply normalization map but don't destroy uniqueness entirely
    for key, val in NORMALIZATION_MAP.items():
        if key in s:
            return val

    return s


def classify_string(s: str):
    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", s):
        return "ip"

    if "http://" in s or "https://" in s:
        return "url"

    if re.search(r"\b[a-z0-9.-]+\.(com|net|org|ru|cn|xyz)\b", s):
        return "domain"

    if "hkcu" in s or "hklm" in s:
        return "registry"

    if "\\" in s or "/etc/" in s:
        return "filesystem"

    if any(api in s for api in [
        "createremotethread", "virtualalloc", "writeprocessmemory"
    ]):
        return "suspicious_api"

    return "generic"


STRING_WEIGHTS = {
    "ip": 5.0,
    "domain": 5.0,
    "url": 4.0,
    "registry": 3.0,
    "filesystem": 2.5,
    "suspicious_api": 3.5,
    "generic": 1.0
}


#  String Extraction 

def extract_strings_from_report(report: dict) -> set[str]:
    strings = set()

    if not isinstance(report, dict):
        return strings

    sa = report.get("static_analysis") or {}
    sdata = sa.get("strings") or {}

    # ELF-style
    if isinstance(sdata, list):
        for s in sdata:
            norm = normalize_string(s)
            if norm:
                strings.add(norm)
        return strings

    # PE-style
    if isinstance(sdata, dict):
        for category in ["ascii", "unicode", "wide"]:
            for s in sdata.get(category, []) or []:
                norm = normalize_string(s)
                if norm:
                    strings.add(norm)

        interesting = sdata.get("interesting") or {}
        if isinstance(interesting, dict):
            for vals in interesting.values():
                for v in vals or []:
                    norm = normalize_string(v)
                    if norm:
                        strings.add(norm)

    return strings


#  Similarity Metrics 

def jaccard_similarity(a: set, b: set) -> float:
    union = len(a | b)
    return 0.0 if union == 0 else len(a & b) / union


def overlap_pct_smaller(a: set, b: set) -> float:
    smaller = min(len(a), len(b))
    return 0.0 if smaller == 0 else len(a & b) / smaller


def weighted_jaccard(a: set, b: set) -> float:
    union = a | b
    intersection = a & b

    num = 0.0
    den = 0.0

    for item in union:
        w = STRING_WEIGHTS.get(classify_string(item), 1.0)

        if item in intersection:
            num += w
        den += w

    return num / den if den else 0.0


def weighted_score(intersection: set) -> float:
    return sum(STRING_WEIGHTS.get(classify_string(s), 1.0) for s in intersection)


def extract_behavior_tags(strings: set[str]) -> set[str]:
    tags = set()
    for s in strings:
        cls = classify_string(s)
        if cls != "generic":
            tags.add(cls)
    return tags


#  Core Comparison 

def compare_string_sets(strings_a: set, strings_b: set):
    shared = strings_a & strings_b

    behavior_a = extract_behavior_tags(strings_a)
    behavior_b = extract_behavior_tags(strings_b)

    return {
        "shared_count": len(shared),

        # base similarity
        "similarity_score": round(jaccard_similarity(strings_a, strings_b), 6),

        #  required by advanced_similarity
        "weighted_similarity": round(weighted_jaccard(strings_a, strings_b), 6),

        #  cross-platform behavioral similarity
        "behavior_similarity": round(jaccard_similarity(behavior_a, behavior_b), 6),

        # extras
        "overlap_pct_of_smaller": round(overlap_pct_smaller(strings_a, strings_b), 6),
        "weighted_score": round(weighted_score(shared), 3),

        "shared_strings": list(shared)[:200]
    }


#  Single Report API 

def compare_strings_single_report(
    new_report: dict,
    reports_dir: str | Path,
    min_overlap: int = 5
):
    reports_dir = Path(reports_dir)

    new_strings = extract_strings_from_report(new_report)
    if not new_strings:
        print("[!] No strings in new report")
        return []

    new_sha = extract_sha256(new_report)

    matches = []
    seen_shas = set()

    for jp in reports_dir.glob("*.json"):

        if jp.name.endswith("_normalized.json"):
            continue

        existing = load_report(jp)
        if not existing:
            continue

        existing_sha = extract_sha256(existing)

        if existing_sha and existing_sha == new_sha:
            continue

        if existing_sha in seen_shas:
            continue
        if existing_sha:
            seen_shas.add(existing_sha)

        existing_strings = extract_strings_from_report(existing)
        if not existing_strings:
            continue

        result = compare_string_sets(new_strings, existing_strings)

        if result["shared_count"] < min_overlap:
            continue

        matches.append({
            "binary_id": extract_binary_id(existing, jp),
            "shared_count": result["shared_count"],
            "total_in_new": len(new_strings),
            "total_in_match": len(existing_strings),

            "similarity_score": result["similarity_score"],
            "weighted_similarity": result["weighted_similarity"],
            "behavior_similarity": result["behavior_similarity"],

            "weighted_score": result["weighted_score"],
            "overlap_pct_of_smaller": result["overlap_pct_of_smaller"],
            "shared_strings": result["shared_strings"]
        })

    # Deduplicate
    unique = {}
    for m in matches:
        unique[m["binary_id"]] = m

    matches = list(unique.values())

    # Sort by strongest signal
    matches.sort(key=lambda x: x["weighted_similarity"], reverse=True)

    print(f"[+] String similarity: {len(matches)} match(es)")
    for m in matches:
        print(
            f"    → {m['binary_id']} | shared: {m['shared_count']} "
            f"| jaccard: {m['similarity_score']:.2%} "
            f"| weighted: {m['weighted_similarity']:.2%} "
            f"| behavior: {m['behavior_similarity']:.2%} "
            f"| pct_small: {m['overlap_pct_of_smaller']:.2%}"
        )

    return matches
