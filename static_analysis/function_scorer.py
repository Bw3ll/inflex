from __future__ import annotations

import re
from typing import Any


#  Signal weights (sum to 1.0) 

WEIGHTS = {
    "stackstring":        0.20,
    "dynamic_api":        0.22,
    "virtualalloc_exec":  0.18,
    "indirect_call":      0.12,
    "antivm":             0.10,
    "corpus_match":       0.10,
    "suspicious_strings": 0.08,   # strings_referenced: high-weight string classes
}

#  ATT&CK technique metadata per signal 

TECHNIQUE_MAP = {
    "stackstring":        ("T1027", "Obfuscated Files or Information — Stackstrings"),
    "dynamic_api":        ("T1129", "Shared Modules — Runtime API Resolution"),
    "virtualalloc_exec":  ("T1055", "Process Injection / Memory Allocation"),
    "indirect_call":      ("T1620", "Reflective Code Loading"),
    "antivm":             ("T1497", "Virtualization/Sandbox Evasion"),
    "suspicious_strings": ("T1082", "System Information Discovery / Suspicious String Indicators"),
}

#  Mnemonic-level pattern helpers 

# Refs to LoadLibrary / GetProcAddress after normalisation
_LOAD_LIBRARY_RE  = re.compile(r"loadlibrary",  re.I)
_GET_PROC_RE      = re.compile(r"getprocaddress", re.I)

# VirtualAlloc / VirtualAllocEx
_VIRT_ALLOC_RE    = re.compile(r"virtualalloc", re.I)

# Indirect call patterns: "call eax", "call ecx", "call [reg+...]"
# After normalisation operands use register names not immediates
_INDIRECT_CALL_RE = re.compile(
    r"^call\s+(?:eax|ebx|ecx|edx|esi|edi|esp|ebp"
    r"|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp"
    r"|r\d+|\[)",
    re.I,
)

# Anti-VM string references that survive normalisation as symbol names
_ANTIVM_RE = re.compile(
    r"(vmware|virtualbox|vbox|xen|qemu|sandbox|wine|cuckoo|vpcext)",
    re.I,
)

# Stackstring detection: run of consecutive "mov byte \[ebp" or
# "mov byte \[esp" instructions writing single bytes (constant immediate).
# After normalisation these appear as "mov byte [ebp - const]  const"
_STACK_BYTE_WRITE_RE = re.compile(
    r"^mov\s+byte\s+\[(?:ebp|esp|rbp|rsp)",
    re.I,
)

# Minimum consecutive stack-byte writes to flag as stackstring construction
STACKSTRING_RUN_THRESHOLD = 6

# High-weight string categories from string_simularity.py — IPs, domains, URLs,
# registry paths, and suspicious API names are the most meaningful indicators.
# Matched against strings_referenced (the ptr-attributed strings from disassembly.py).
_HIGH_VALUE_STRING_RE = re.compile(
    r"""
    \d{1,3}(\.\d{1,3}){3}           # IPv4 address
    | https?://                           # URL
    | [a-z0-9.\-]+\.(com|net|org|ru|cn|xyz|io)  # domain
    | hkcu|hklm|hkey                      # registry hives
    | \\pipe\\                        # named pipe
    | createremotethread|virtualalloc     # suspicious APIs
    | writeprocessmemory|ntunmapview     # injection APIs
    | /etc/passwd|/proc/                 # sensitive Linux paths
    | cmd\.exe|powershell|wscript        # shell launchers
    """,
    re.I | re.VERBOSE,
)

# Minimum indirect calls in a function to trigger the signal
INDIRECT_CALL_THRESHOLD = 2


#  Per-signal detectors 

def _detect_stackstring(mnemonics: list[str]) -> tuple[float, str]:
    """
    Detect stackstring construction by finding runs of consecutive
    byte-level stack writes (MOV BYTE [EBP/ESP - offset], imm).

    A run of >= STACKSTRING_RUN_THRESHOLD consecutive writes is strong
    evidence. Score scales with run length up to a cap of 1.0.
    """
    max_run = 0
    current_run = 0

    for m in mnemonics:
        if _STACK_BYTE_WRITE_RE.match(m):
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0

    if max_run < STACKSTRING_RUN_THRESHOLD:
        return 0.0, ""

    # Scale: 6 writes -> 0.5, 12+ writes -> 1.0
    score = min(1.0, max_run / 12.0)
    detail = (
        f"Stackstring construction: longest run of {max_run} consecutive "
        f"stack byte-writes (threshold {STACKSTRING_RUN_THRESHOLD})"
    )
    return score, detail


def _detect_dynamic_api(mnemonics: list[str]) -> tuple[float, str]:
    """
    Detect runtime API resolution: LoadLibraryA/W AND GetProcAddress
    both referenced in the same function, strongly suggesting dynamic
    import resolution to evade static IAT analysis.
    """
    has_loadlib  = any(_LOAD_LIBRARY_RE.search(m) for m in mnemonics)
    has_getproc  = any(_GET_PROC_RE.search(m) for m in mnemonics)

    if has_loadlib and has_getproc:
        return 1.0, "LoadLibrary + GetProcAddress pair — dynamic import resolution"

    if has_loadlib:
        return 0.4, "LoadLibrary reference without paired GetProcAddress"

    if has_getproc:
        return 0.4, "GetProcAddress reference without paired LoadLibrary"

    return 0.0, ""


def _detect_virtualalloc_exec(mnemonics: list[str]) -> tuple[float, str]:
    """
    Detect VirtualAlloc followed by an indirect call — classic shellcode
    staging or reflective injection pattern. VirtualAlloc alone scores
    lower; pairing with an indirect call to the allocated buffer raises it.
    """
    alloc_count   = sum(1 for m in mnemonics if _VIRT_ALLOC_RE.search(m))
    indirect_calls = sum(1 for m in mnemonics if _INDIRECT_CALL_RE.match(m))

    if alloc_count == 0:
        return 0.0, ""

    if indirect_calls > 0:
        return 1.0, (
            f"VirtualAlloc ({alloc_count}x) + indirect call ({indirect_calls}x) "
            f"— shellcode staging / reflective injection pattern"
        )

    return 0.5, f"VirtualAlloc ({alloc_count}x) without paired indirect call"


def _detect_indirect_calls(mnemonics: list[str]) -> tuple[float, str]:
    """
    High density of indirect calls (call eax / call [reg]) indicates
    runtime dispatch, obfuscated control flow, or hook trampolining.
    """
    count = sum(1 for m in mnemonics if _INDIRECT_CALL_RE.match(m))

    if count < INDIRECT_CALL_THRESHOLD:
        return 0.0, ""

    # Scale: 2 -> 0.3, 5+ -> 1.0
    score = min(1.0, count / 5.0)
    detail = f"High indirect-call density: {count} indirect call(s) in function"
    return score, detail


def _detect_antivm(mnemonics: list[str]) -> tuple[float, str]:
    """
    Detect anti-VM / sandbox evasion strings surviving in mnemonic
    symbol references (e.g. push str.vmware, push str.vbox).
    """
    hits = [m for m in mnemonics if _ANTIVM_RE.search(m)]

    if not hits:
        return 0.0, ""

    keywords = list({_ANTIVM_RE.search(h).group(1).lower() for h in hits})
    detail = f"Anti-VM/sandbox string references: {', '.join(keywords)}"
    return 1.0, detail


def _detect_suspicious_strings(strings_referenced: list[str]) -> tuple[float, str]:
    """
    Detect high-value / suspicious strings attributed to this function via
    disassembly.py's ptr-based cross-reference attribution.

    These are strings the function actually *uses* (resolved via r2's ptr
    field), not just strings that happen to be nearby in memory.  Matching
    against IP addresses, domains, registry hives, injection APIs, and shell
    launchers provides direct evidence of malicious capability.

    Score scales with the number of distinct high-value matches up to 1.0.

    Args:
        strings_referenced: List of string values from func['strings_referenced'].
    """
    if not strings_referenced:
        return 0.0, ""

    hits = [s for s in strings_referenced if _HIGH_VALUE_STRING_RE.search(s)]

    if not hits:
        return 0.0, ""

    # Scale: 1 hit -> 0.4, 3+ hits -> 1.0
    score = min(1.0, 0.4 + 0.2 * (len(hits) - 1))
    sample = hits[:5]
    detail = (
        f"{len(hits)} high-value string(s) attributed to this function: "
        + ", ".join(repr(s[:40]) for s in sample)
        + (" ..." if len(hits) > 5 else "")
    )
    return round(score, 4), detail


#  Corpus match helper 

def _build_corpus_index(report: dict) -> dict[str, list[str]]:
    """
    Build a mapping of func_hash -> [binary_id, ...] from the function
    similarity results already stored in disassembly.similarity.function_similarity.
    """
    index: dict[str, list[str]] = {}

    sim = report.get("disassembly", {}).get("similarity", {})
    for match in sim.get("function_similarity", []):
        binary_id = match.get("binary_id", "unknown")
        for sf in match.get("shared_functions", []):
            h = sf.get("func_hash")
            if h:
                index.setdefault(h, []).append(binary_id)

    return index


#  MITRE evidence index 

def _build_mitre_index(report: dict) -> dict[str, list[dict]]:
    """
    Build a mapping of technique_id -> [evidence, ...] from the capa hits
    stored in threat_intelligence.MITRE_ATTACK.hits.capa.

    Each evidence entry preserves the full capa record so function entries
    can display the matched rule name, tactic, confidence, and source.

    Path in normalized report:
        threat_intelligence.MITRE_ATTACK.hits.capa[]
            .technique   e.g. "T1027"
            .tactic      e.g. "Defense Evasion"
            .rule        e.g. "contain obfuscated stackstrings"
            .confidence  e.g. 0.7
            .source      e.g. "capa"
            .timestamp
    """
    index: dict[str, list[dict]] = {}

    ti = report.get("threat_intelligence", {})
    mitre = ti.get("MITRE_ATTACK", {})
    hits = mitre.get("hits", {})
    capa_hits = hits.get("capa", [])

    for hit in capa_hits:
        tid = hit.get("technique", "").upper().strip()
        if not tid:
            continue
        index.setdefault(tid, []).append({
            "technique_id": tid,
            "tactic":       hit.get("tactic", ""),
            "rule":         hit.get("rule", ""),
            "confidence":   hit.get("confidence", 0.0),
            "source":       hit.get("source", "capa"),
            "timestamp":    hit.get("timestamp", ""),
        })

    return index


#  Core scorer 

def _score_one_function(
    func: dict[str, Any],
    corpus_index: dict[str, list[str]],
    mitre_index: dict[str, list[dict]],
) -> dict[str, Any]:
    """
    Score a single function dict and return an enriched copy.

    Args:
        func:          A single entry from disassembly.functions.
        corpus_index:  func_hash -> [binary_id] from known-malicious corpus.
        mitre_index:   technique_id -> [capa evidence] from threat_intelligence.

    Returns:
        Enriched dict with suspicion_score, triggered_techniques (merged with
        capa evidence where IDs match), mitre_evidence (all capa hits whose
        technique ID was triggered), corpus_matches, and signal_breakdown.
        All original keys are preserved.
    """
    mnemonics = func.get("mnemonics", [])
    func_hash = func.get("func_hash", "")
    strings_referenced = func.get("strings_referenced", [])

    signal_scores: dict[str, float] = {}
    signal_details: dict[str, str]  = {}

    #  Run all detectors 
    detectors = {
        "stackstring":       lambda m: _detect_stackstring(m),
        "dynamic_api":       lambda m: _detect_dynamic_api(m),
        "virtualalloc_exec": lambda m: _detect_virtualalloc_exec(m),
        "indirect_call":     lambda m: _detect_indirect_calls(m),
        "antivm":            lambda m: _detect_antivm(m),
    }

    for signal_name, detector in detectors.items():
        raw_score, detail = detector(mnemonics)
        signal_scores[signal_name] = raw_score
        signal_details[signal_name] = detail

    ss_score, ss_detail = _detect_suspicious_strings(strings_referenced)
    signal_scores["suspicious_strings"] = ss_score
    signal_details["suspicious_strings"] = ss_detail

    #  Corpus match 
    corpus_matches = corpus_index.get(func_hash, [])
    if corpus_matches:
        signal_scores["corpus_match"] = 1.0
        signal_details["corpus_match"] = (
            f"Function hash matches {len(corpus_matches)} known-malicious "
            f"binary/ies: {', '.join(corpus_matches[:3])}"
            + (" ..." if len(corpus_matches) > 3 else "")
        )
    else:
        signal_scores["corpus_match"] = 0.0
        signal_details["corpus_match"] = ""

    #  Weighted final score 
    final_score = sum(
        WEIGHTS[sig] * signal_scores[sig]
        for sig in WEIGHTS
    )
    final_score = round(min(1.0, final_score), 6)

    #  Build triggered techniques list, merging capa evidence 
    # Start with the mnemonic-detected techniques
    triggered = []
    triggered_ids: set[str] = set()

    for sig, (tid, tname) in TECHNIQUE_MAP.items():
        if signal_scores.get(sig, 0.0) > 0.0:
            entry = {
                "technique_id":   tid,
                "technique_name": tname,
                "signal":         sig,
                "signal_score":   round(signal_scores[sig], 4),
                "detail":         signal_details[sig],
                # Merge capa evidence for this technique ID if available
                "capa_evidence":  mitre_index.get(tid, []),
            }
            triggered.append(entry)
            triggered_ids.add(tid)

    # Add any capa techniques not already covered by a mnemonic signal.
    # These are binary-level findings that couldn't be localised to a specific
    # function by the mnemonic detectors, so we attach them to every function
    # that has a non-zero suspicion score as contextual intelligence.
    # They are flagged with signal="capa_only" so the analyst knows the
    # attribution to this specific function is inferred, not proven.
    if final_score > 0.0:
        for tid, evidence_list in mitre_index.items():
            if tid not in triggered_ids:
                triggered.append({
                    "technique_id":   tid,
                    "technique_name": evidence_list[0].get("tactic", ""),
                    "signal":         "capa_only",
                    "signal_score":   0.0,
                    "detail":         (
                        f"Binary-level capa finding not localised to this function: "
                        f"{evidence_list[0].get('rule', '')}"
                    ),
                    "capa_evidence":  evidence_list,
                })

    # Sort: mnemonic-detected first (signal_score desc), capa-only last
    triggered.sort(key=lambda x: (x["signal"] == "capa_only", -x["signal_score"]))

    # Collect all capa evidence whose technique was triggered by mnemonics
    mitre_evidence = [
        ev
        for tid in triggered_ids
        for ev in mitre_index.get(tid, [])
    ]

    return {
        **func,
        "suspicion_score":      final_score,
        "triggered_techniques": triggered,
        "mitre_evidence":       mitre_evidence,
        "corpus_matches":       corpus_matches,
        "signal_breakdown": {
            sig: {
                "raw_score": round(signal_scores[sig], 4),
                "weight":    WEIGHTS[sig],
                "weighted":  round(WEIGHTS[sig] * signal_scores[sig], 6),
                "detail":    signal_details[sig],
            }
            for sig in WEIGHTS
        },
    }


#  Public API 

def score_functions(
    report: dict,
    top_n: int = 20,
) -> list[dict]:
    """
    Score all functions in a report's disassembly block, rank by suspicion,
    and inject the results back into report["disassembly"]["function_scores"].

    Args:
        report:  Full normalised report dict (must contain disassembly.functions).
        top_n:   How many top-ranked functions to include in the output list
                 (all are scored; only top_n are returned and stored).

    Returns:
        Ranked list of scored function dicts (len <= top_n), highest score first.
        Also populates report["disassembly"]["function_scores"] in-place.
    """
    disasm = report.get("disassembly", {})
    functions = disasm.get("functions", [])

    if not functions:
        print("[!] function_scorer: no functions found in disassembly block — skipping.")
        return []

    corpus_index = _build_corpus_index(report)
    mitre_index  = _build_mitre_index(report)

    if mitre_index:
        print(f"[+] Function scorer: loaded {sum(len(v) for v in mitre_index.values())} "
              f"capa MITRE hit(s) across {len(mitre_index)} technique(s): "
              f"{', '.join(sorted(mitre_index.keys()))}")
    else:
        print("[+] Function scorer: no capa MITRE hits found in report")

    scored = [_score_one_function(f, corpus_index, mitre_index) for f in functions]
    scored.sort(key=lambda x: x["suspicion_score"], reverse=True)

    top = scored[:top_n]

    #  Inject into report in-place 
    disasm["function_scores"] = {
        "ranked_functions": top,
        "total_scored":     len(scored),
        "top_n":            top_n,
        "scoring_weights":  WEIGHTS,
        "mitre_techniques_available": sorted(mitre_index.keys()),
    }

    #  Console summary 
    flagged = [f for f in scored if f["suspicion_score"] > 0.0]
    print(f"[+] Function scorer: {len(scored)} function(s) scored, "
          f"{len(flagged)} with non-zero suspicion")

    for f in top[:10]:
        mnemonic_techs = [
            t["technique_id"] for t in f["triggered_techniques"]
            if t["signal"] != "capa_only"
        ]
        capa_techs = [
            t["technique_id"] for t in f["triggered_techniques"]
            if t["signal"] == "capa_only"
        ]
        tech_str = ", ".join(mnemonic_techs) or "none"
        if capa_techs:
            tech_str += f" (capa-only: {', '.join(capa_techs)})"
        print(
            f"    -> {f['name']} @ {f['offset']} "
            f"| score: {f['suspicion_score']:.2%} "
            f"| techniques: {tech_str}"
        )

    return top
