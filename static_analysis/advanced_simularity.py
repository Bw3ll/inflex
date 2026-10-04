# TODO: add in function hash simularity plus ssdeep simularity and we should be good
# TODO: Fix the final envaluation to get it to score things as malware correctly

from pathlib import Path
import re
from static_analysis.string_simularity import (
    extract_strings_from_report,
    compare_string_sets,
    load_report,
    extract_sha256,
    extract_binary_id,
    jaccard_similarity,
)


#  Context extraction 

def extract_format_type(report: dict) -> str:
    """
    Return the normalised binary format: 'PE', 'ELF', 'MACHO', or 'UNKNOWN'.

    Primary source: report['format_type'] set during ingest.
    Fallback: ingest_analysis.extension / detected_type heuristic.
    """
    fmt = report.get("format_type", "").upper().strip()
    if fmt in {"PE", "ELF", "MACHO"}:
        return fmt

    # Fallback via ingest_analysis
    ia = report.get("ingest_analysis", {})
    detected = (ia.get("detected_type") or "").lower()
    ext      = (ia.get("extension")    or "").lower()

    if "elf" in detected or ext in {"elf", "so"}:
        return "ELF"
    if "portable executable" in detected or ext in {"exe", "dll", "sys", "drv"}:
        return "PE"
    if "mach-o" in detected or ext in {"macho", "dylib"}:
        return "MACHO"

    return "UNKNOWN"


def extract_verdict(report: dict) -> str:
    """
    Return a normalised verdict string: 'MALICIOUS', 'BENIGN', or 'UNKNOWN'.
    """
    ti = report.get("threat_intelligence", {})

    #  Step 1: VirusTotal ground truth 
    vt = ti.get("VirusTotal", {})
    max_malicious = 0
    max_engines   = 0

    for v in vt.values():
        if not isinstance(v, dict):
            continue
        stats = v.get("analysis_stats") or {}
        malicious = stats.get("malicious", 0) or 0
        total = sum(
            stats.get(k, 0) or 0
            for k in ("malicious", "suspicious", "undetected", "harmless")
        )
        max_malicious = max(max_malicious, malicious)
        max_engines   = max(max_engines, total)

    if max_malicious >= 5:
        return "MALICIOUS"
    if max_malicious == 0 and max_engines >= 10:
        return "BENIGN"

    #  Step 2: Pipeline verdict fallback 
    raw = (
        ti.get("MITRE_ATTACK", {}).get("verdict", "") or ""
    ).lower().strip()

    if any(kw in raw for kw in ("malicious", "suspicious")):
        return "MALICIOUS"
    if "benign" in raw:
        return "BENIGN"
    return "UNKNOWN"

_W = {
    #  Malicious vs Malicious 
    ("MALICIOUS", "MALICIOUS", True): {
        "string":    0.20,
        "ssdeep":    0.25,
        "func_hash": 0.20,
        "mitre":     0.20,
        "label":     0.15,
        "_note": "MAL/MAL same-format: ssdeep+func_hash are strongest family signals"
    },
    ("MALICIOUS", "MALICIOUS", False): {
        "string":    0.15,
        "ssdeep":    0.20,
        "func_hash": 0.15,
        "mitre":     0.30,
        "label":     0.20,
        "_note": "MAL/MAL cross-format: MITRE+label lead, ssdeep less reliable cross-arch"
    },

    #  Benign vs Benign 
    ("BENIGN", "BENIGN", True): {
        "string":    0.10,
        "ssdeep":    0.30,
        "func_hash": 0.25,
        "mitre":     0.25,
        "label":     0.10,
        "_note": "BEN/BEN same-format: structural similarity leads; strings too noisy"
    },
    ("BENIGN", "BENIGN", False): {
        "string":    0.05,
        "ssdeep":    0.25,
        "func_hash": 0.20,
        "mitre":     0.30,
        "label":     0.20,
        "_note": "BEN/BEN cross-format: MITRE+label only meaningful signal"
    },

    #  Malicious vs Benign 
    ("BENIGN", "MALICIOUS", True): {
        "string":    0.10,
        "ssdeep":    0.15,
        "func_hash": 0.15,
        "mitre":     0.30,
        "label":     0.30,
        "_note": "MAL/BEN same-format: label+MITRE lead; shared family names signal even across verdict boundary"
    },
    ("BENIGN", "MALICIOUS", False): {
        "string":    0.05,
        "ssdeep":    0.10,
        "func_hash": 0.10,
        "mitre":     0.40,
        "label":     0.35,
        "_note": "MAL/BEN cross-format: label+MITRE dominate; structural signals unreliable cross-format"
    },

    #  Unknown in either position (baseline) 
    ("MALICIOUS", "UNKNOWN", True):  {
        "string":    0.18,
        "ssdeep":    0.22,
        "func_hash": 0.18,
        "mitre":     0.22,
        "label":     0.20,
        "_note": "MAL/UNK same-format: balanced"
    },
    ("MALICIOUS", "UNKNOWN", False): {
        "string":    0.12,
        "ssdeep":    0.15,
        "func_hash": 0.13,
        "mitre":     0.30,
        "label":     0.30,
        "_note": "MAL/UNK cross-format: balanced"
    },
    ("BENIGN", "UNKNOWN", True): {
        "string":    0.12,
        "ssdeep":    0.25,
        "func_hash": 0.20,
        "mitre":     0.25,
        "label":     0.18,
        "_note": "BEN/UNK same-format: structural signals lead"
    },
    ("BENIGN", "UNKNOWN", False): {
        "string":    0.08,
        "ssdeep":    0.18,
        "func_hash": 0.14,
        "mitre":     0.32,
        "label":     0.28,
        "_note": "BEN/UNK cross-format: MITRE+label lead"
    },
    ("UNKNOWN", "UNKNOWN", True): {
        "string":    0.18,
        "ssdeep":    0.22,
        "func_hash": 0.18,
        "mitre":     0.22,
        "label":     0.20,
        "_note": "UNK/UNK same-format: balanced baseline"
    },
    ("UNKNOWN", "UNKNOWN", False): {
        "string":    0.12,
        "ssdeep":    0.15,
        "func_hash": 0.13,
        "mitre":     0.30,
        "label":     0.30,
        "_note": "UNK/UNK cross-format: balanced baseline"
    },
}


def _lookup_weights(
    verdict_a: str,
    verdict_b: str,
    format_a: str,
    format_b: str,
) -> dict:
    """
    Look up the correct weight table entry for a given pair of reports.

    The verdict pair is sorted alphabetically so the lookup is symmetric.
    format_match is True only when both formats are identical and known
    (UNKNOWN vs anything is treated as cross-format to be conservative).
    """
    format_match = (
        format_a == format_b
        and format_a != "UNKNOWN"
        and format_b != "UNKNOWN"
    )

    # Sort verdict pair so (A, B) and (B, A) hit the same key
    key_pair = tuple(sorted([verdict_a, verdict_b]))
    key = (key_pair[0], key_pair[1], format_match)

    return _W.get(key, _W[("UNKNOWN", "UNKNOWN", format_match)])


#  MITRE Extraction 

def extract_mitre(report: dict) -> set[str]:
    """
    Extract MITRE ATT&CK technique IDs from the report.

    Reads from threat_intelligence.MITRE_ATTACK.hits.capa, which is where
    your pipeline stores capa-sourced technique assignments.
    Falls back to the legacy threat_intel.mitre_attack path for compatibility.
    """
    # Primary path (normalised report schema)
    hits = (
        report.get("threat_intelligence", {})
              .get("MITRE_ATTACK", {})
              .get("hits", {})
              .get("capa", [])
    )
    techniques = {h.get("technique") for h in hits if h.get("technique")}
    if techniques:
        return techniques

    # Legacy path (advanced_simularity original schema)
    mitre = report.get("threat_intel", {}).get("mitre_attack", [])
    return {m.get("technique") for m in mitre if m.get("technique")}


#  Threat Labels 

# Vendor-added prefixes that pollute label comparison.
# "trojan.melofee" and "melofee" should be the same token.
# "trojan.winnti/graftor" should yield both "winnti" and "graftor".
_LABEL_STRIP_PREFIXES = (
    "trojan.", "win32.", "win64.", "linux.", "macos.", "osx.",
    "ransom.", "worm.", "backdoor.", "malware.", "heur.", "gen.",
    "packed.", "inject.", "agent.", "generic.", "riskware.",
)

# Labels that are too generic to be meaningful for family comparison
_LABEL_NOISE = {
    "exe", "elf", "dll", "malware", "unknown", "agent", "generic",
    "heur", "trojan", "worm", "backdoor", "ransom", "virus",
    "gen", "packed", "riskware", "suspicious",
}


def _normalise_label(raw: str) -> list[str]:
    """
    Normalise a single raw threat label into one or more clean tokens.

    Steps:
      1. Lowercase and strip whitespace
      2. Strip known vendor prefixes (trojan., win32., linux., etc.)
      3. Split on "/" and "." separators to handle composite labels
         like "winnti/graftor" -> ["winnti", "graftor"]
         and "trojan.melofee" -> ["melofee"]
      4. Discard tokens that are too short or in the noise set

    Returns a list of normalised tokens (may be empty if all tokens are noise).
    """
    if not raw or not isinstance(raw, str):
        return []

    label = raw.lower().strip()

    # Strip known prefixes iteratively (some labels have multiple: "heur.trojan.x")
    changed = True
    while changed:
        changed = False
        for prefix in _LABEL_STRIP_PREFIXES:
            if label.startswith(prefix):
                label = label[len(prefix):]
                changed = True

    # Split on composite separators
    parts = re.split(r'[/.]', label)

    # Filter noise and short tokens
    tokens = []
    for part in parts:
        part = part.strip()
        if len(part) >= 3 and part not in _LABEL_NOISE:
            tokens.append(part)

    return tokens


def extract_labels(report: dict) -> set[str]:
    """
    Extract normalised threat labels from VirusTotal and AbuseCH fields.

    All labels are normalised through _normalise_label() which strips vendor
    prefixes and splits composite labels, so "trojan.melofee", "melofee", and
    "trojan/melofee" all produce the token "melofee" and will match correctly.

    Reads from threat_intelligence (normalised schema) with fallback to
    threat_intel (legacy schema).
    """
    raw_labels: list[str] = []

    # Normalised schema
    ti = report.get("threat_intelligence", {})

    vt = ti.get("VirusTotal", {})
    for v in vt.values():
        if not isinstance(v, dict):
            continue
        pt = v.get("popular_threat_classification") or {}
        for item in pt.get("popular_threat_name", []) or []:
            val = (item or {}).get("value")
            if val:
                raw_labels.append(val)
        lbl = pt.get("suggested_threat_label") or ""
        if lbl:
            raw_labels.append(lbl)

    ab = ti.get("AbuseCH", {})
    for v in ab.values():
        if not isinstance(v, dict):
            continue
        sig = v.get("signature")
        if sig:
            raw_labels.append(sig)
        for tag in v.get("tags", []) or []:
            if tag:
                raw_labels.append(tag)

    # Normalise all raw labels and flatten into a single set
    labels: set[str] = set()
    for raw in raw_labels:
        for token in _normalise_label(raw):
            labels.add(token)

    if labels:
        return labels

    # Legacy schema fallback
    vt_legacy = report.get("threat_intel", {}).get("virustotal", {})
    for v in vt_legacy.values():
        pt = v.get("popular_threat_classification") or {}
        for item in pt.get("popular_threat_name", []) or []:
            val = (item or {}).get("value")
            if val:
                for token in _normalise_label(val):
                    labels.add(token)

    ab_legacy = report.get("threat_intel", {}).get("abusech", {})
    for v in ab_legacy.values():
        sig = v.get("signature")
        if sig:
            for token in _normalise_label(sig):
                labels.add(token)

    return labels

    # Legacy schema fallback
    vt_legacy = report.get("threat_intel", {}).get("virustotal", {})
    for v in vt_legacy.values():
        pt = v.get("popular_threat_classification") or {}
        for item in pt.get("popular_threat_name", []) or []:
            val = item.get("value")
            if val:
                labels.add(val.lower())

    ab_legacy = report.get("threat_intel", {}).get("abusech", {})
    for v in ab_legacy.values():
        sig = v.get("signature")
        if sig:
            labels.add(sig.lower())

    return labels


#  ssdeep similarity 

def _extract_ssdeep(report: dict) -> str | None:
    """
    Extract ssdeep hash from a report. Checks VT results (most reliable source)
    then static_analysis.hashes as fallback.
    """
    # VT stores ssdeep on each hash entry
    vt = report.get("threat_intelligence", {}).get("VirusTotal", {})
    for v in vt.values():
        if isinstance(v, dict):
            s = v.get("ssdeep")
            if s and isinstance(s, str) and ":" in s:
                return s

    # Static analysis fallback
    return (
        report.get("static_analysis", {})
              .get("hashes", {})
              .get("ssdeep")
    )


def _ssdeep_similarity(hash_a: str | None, hash_b: str | None) -> float:
    """
    Compute ssdeep similarity score in [0.0, 1.0].

    Uses the ssdeep library if available, otherwise falls back to a fast
    block-size + common-chunk heuristic that approximates the result
    without the C extension.
    """
    if not hash_a or not hash_b:
        return 0.0

    try:
        import ssdeep as _ssdeep
    except ImportError:
        try:
            import pyssdeep as _ssdeep
        except ImportError:
            _ssdeep = None

    if _ssdeep is not None:
        score = _ssdeep.compare(hash_a, hash_b)
        return score / 100.0

    # Pure-Python fallback: split into chunks and compute overlap
    try:
        parts_a = hash_a.split(":")
        parts_b = hash_b.split(":")
        if len(parts_a) < 2 or len(parts_b) < 2:
            return 0.0

        block_a, block_b = int(parts_a[0]), int(parts_b[0])
        # ssdeep only compares hashes with matching or adjacent block sizes
        if block_a != block_b and block_a != block_b * 2 and block_b != block_a * 2:
            return 0.0

        # Overlap of 7-character substrings (rolling window)
        def chunk_set(s: str, w: int = 7) -> set[str]:
            return {s[i:i+w] for i in range(max(0, len(s) - w + 1))}

        chunks_a = chunk_set(parts_a[1])
        chunks_b = chunk_set(parts_b[1])
        if not chunks_a or not chunks_b:
            return 0.0

        overlap = len(chunks_a & chunks_b)
        score = overlap / max(len(chunks_a), len(chunks_b))
        return round(min(score * 1.5, 1.0), 4)  # scale to approximate ssdeep range
    except Exception:
        return 0.0


#  Function hash similarity 

def _function_hash_similarity(report_a: dict, report_b: dict) -> float:
    """
    Compute Jaccard similarity over function hashes from disassembly.

    This is a stronger family signal than behavior tags because function
    hashes capture actual code structure rather than generic string categories.
    Returns 0.0 if either report lacks disassembly data.
    """
    funcs_a = report_a.get("disassembly", {}).get("functions", [])
    funcs_b = report_b.get("disassembly", {}).get("functions", [])

    if not funcs_a or not funcs_b:
        return 0.0

    hashes_a = {f["func_hash"] for f in funcs_a if f.get("func_hash")}
    hashes_b = {f["func_hash"] for f in funcs_b if f.get("func_hash")}

    if not hashes_a or not hashes_b:
        return 0.0

    union = len(hashes_a | hashes_b)
    return 0.0 if union == 0 else len(hashes_a & hashes_b) / union


#  Composite Scoring 

def compute_similarity(report_a: dict, report_b: dict) -> dict:
    """
    Compute a weighted composite similarity score between two reports.

    Signals used:
      string    — weighted Jaccard over normalised string sets
      ssdeep    — fuzzy hash similarity (structural proximity)
      func_hash — Jaccard over disassembly function hashes (code-level identity)
      mitre     — Jaccard over ATT&CK technique IDs
      label     — Jaccard over normalised threat family labels

    The old "behavior" signal (Jaccard over 6 tag types like filesystem/ip/
    suspicious_api) has been removed. It was too coarse — any two malicious
    Windows PEs with network capability shared all 3 common tags producing
    66% adjusted behavior similarity between completely unrelated families.
    ssdeep and function hash similarity replace it with structurally grounded
    signals that actually discriminate between families.

    Weights are selected dynamically based on verdict and format context.
    """
    #  Classify both reports 
    verdict_a = extract_verdict(report_a)
    verdict_b = extract_verdict(report_b)
    format_a  = extract_format_type(report_a)
    format_b  = extract_format_type(report_b)

    weights = _lookup_weights(verdict_a, verdict_b, format_a, format_b)
    context_note = weights.get("_note", "")

    #  Signal extraction 
    strings_a  = extract_strings_from_report(report_a)
    strings_b  = extract_strings_from_report(report_b)
    string_res = compare_string_sets(strings_a, strings_b)

    mitre_a   = extract_mitre(report_a)
    mitre_b   = extract_mitre(report_b)
    mitre_sim = jaccard_similarity(mitre_a, mitre_b)

    label_a   = extract_labels(report_a)
    label_b   = extract_labels(report_b)
    label_sim = jaccard_similarity(label_a, label_b)

    ssdeep_a   = _extract_ssdeep(report_a)
    ssdeep_b   = _extract_ssdeep(report_b)
    ssdeep_sim = _ssdeep_similarity(ssdeep_a, ssdeep_b)

    func_sim = _function_hash_similarity(report_a, report_b)

    #  Zero-out signals with no data on either side 
    active_weights = dict(weights)
    active_weights.pop("_note", None)
    # Remove "behavior" key if still present from old weight tables
    active_weights.pop("behavior", None)

    if not mitre_a or not mitre_b:
        active_weights["mitre"] = 0.0
    if not label_a or not label_b:
        active_weights["label"] = 0.0
    if ssdeep_sim == 0.0:
        active_weights["ssdeep"] = 0.0
    if func_sim == 0.0:
        active_weights["func_hash"] = 0.0

    # Renormalise so active weights always sum to 1.0
    total = sum(active_weights.values())
    if total == 0:
        total = 1.0
    for k in active_weights:
        active_weights[k] /= total

    #  Compute final score 
    weighted_str_sim = (
        string_res.get("weighted_jaccard")
        or string_res.get("weighted_similarity")
        or 0.0
    )

    final_score = (
        active_weights.get("string",    0.0) * weighted_str_sim +
        active_weights.get("ssdeep",    0.0) * ssdeep_sim       +
        active_weights.get("func_hash", 0.0) * func_sim         +
        active_weights.get("mitre",     0.0) * mitre_sim        +
        active_weights.get("label",     0.0) * label_sim
    )

    return {
        "final_score":                round(final_score, 6),
        "string_similarity":          string_res["similarity_score"],
        "weighted_string_similarity": weighted_str_sim,
        "ssdeep_similarity":          round(ssdeep_sim, 6),
        "function_hash_similarity":   round(func_sim, 6),
        "mitre_similarity":           round(mitre_sim, 6),
        "label_similarity":           round(label_sim, 6),
        "shared_strings":             string_res["shared_strings"],
        "context": {
            "verdict_a":      verdict_a,
            "verdict_b":      verdict_b,
            "format_a":       format_a,
            "format_b":       format_b,
            "format_match":   format_a == format_b and format_a != "UNKNOWN",
            "weights_used":   {k: round(v, 4) for k, v in active_weights.items()},
            "weight_note":    context_note,
        },
    }


#  Directory Comparison 

def compare_advanced(new_report: dict, reports_dir: str | Path) -> list[dict]:
    """
    Compare a new report against all existing reports in reports_dir.

    Each comparison uses context-aware dynamic weighting based on the
    verdict and format type of both reports.
    """
    reports_dir = Path(reports_dir)

    new_sha     = extract_sha256(new_report)
    new_verdict = extract_verdict(new_report)
    new_format  = extract_format_type(new_report)

    results = []
    seen    = set()

    for jp in reports_dir.glob("*.json"):
        if jp.name.endswith("_normalized.json"):
            continue

        existing = load_report(jp)
        if not existing:
            continue

        sha = extract_sha256(existing)

        if sha == new_sha:
            continue
        if sha in seen:
            continue
        seen.add(sha)

        sim = compute_similarity(new_report, existing)

        results.append({
            "binary_id": extract_binary_id(existing, jp),
            **sim,
        })

    results.sort(key=lambda x: x["final_score"], reverse=True)

    print(f"[+] Advanced similarity: {len(results)} matches "
          f"[new={new_format}/{new_verdict}]")

    for r in results[:10]:
        ctx = r.get("context", {})
        fmt_tag = (
            "same-fmt" if ctx.get("format_match")
            else f"{ctx.get('format_a','?')}/{ctx.get('format_b','?')}"
        )
        verdict_tag = f"{ctx.get('verdict_a','?')}/{ctx.get('verdict_b','?')}"
        print(
            f" -> {r['binary_id']} | FINAL: {r['final_score']:.2%} "
            f"| STR: {r['weighted_string_similarity']:.2%} "
            f"| SSDEEP: {r['ssdeep_similarity']:.2%} "
            f"| FUNC: {r['function_hash_similarity']:.2%} "
            f"| MITRE: {r['mitre_similarity']:.2%} "
            f"| LABEL: {r['label_similarity']:.2%} "
            f"| [{verdict_tag} {fmt_tag}]"
        )

    return results
