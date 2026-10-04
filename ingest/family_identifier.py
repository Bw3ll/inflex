"""
family_identifier.py

This module performs family identification using multiple evidence channels:

Phase 1 — Community-driven label extraction (strongest when present)
    - VirusTotal popular_threat_name (uses VT vote counts)
    - VirusTotal suggested_threat_label
    - AbuseCH signature + tags
    - Vendor intel: Triage / Intezer / VMRay
    - Fallback: filename heuristics

Phase 2 — Corpus-based family inference
    Uses similarity signals from compare_advanced() (advanced_simularity.py):
      - label overlap
      - ssdeep similarity
      - function hash similarity
      - weighted string similarity
      - MITRE overlap

Phase 3 — Function-bridge family validation
    If a sample shares a high overlap of extracted function hashes with
    a corpus sample that has a known family label, this is treated as strong
    lineage evidence and can override weaker/ambiguous label signals.

Output schema:
    {
      "identified_family":     str | None,
      "family_confidence":     float,        # [0.0, 1.0]
      "family_source":         str,          # label_vote | func_bridge | corpus_vote | corpus_structural | unknown
      "family_tokens":         list[str],
      "family_token_votes":    dict[str, float],
      "top_family_candidates": [
          {"family": str, "score": float, "sources": list[str]}, ...
      ],
      "top_corpus_matches": [
        {
          "binary_id":     str,
          "family":        str | None,
          "family_score":  float,
          "label_sim":     float,
          "ssdeep_sim":    float,
          "func_sim":      float,
          "string_sim":    float,
          "mitre_sim":     float,
        }, ...
      ],
      "cluster_verdict":       str,
    }
"""

from __future__ import annotations

import re
from collections import defaultdict


#  Label normalisation

_LABEL_STRIP_PREFIXES = (
    "trojan.", "win32.", "win64.", "linux.", "macos.", "osx.",
    "ransom.", "worm.", "backdoor.", "malware.", "heur.", "gen.",
    "packed.", "inject.", "agent.", "generic.", "riskware.",
    "win.trojan.", "win.backdoor.", "linux.trojan.",
)

_LABEL_NOISE: set[str] = {
    "exe", "elf", "dll", "malware", "unknown", "agent", "generic",
    "heur", "trojan", "worm", "backdoor", "ransom", "virus", "gen",
    "packed", "riskware", "suspicious", "banker", "rat", "stealer",
    "loader", "dropper", "downloader", "spy", "adware", "pua",
    # Threat actor / campaign names — attribution, not family identifiers.
    "apt41", "apt28", "apt29", "apt32", "apt33", "apt34", "apt35",
    "apt38", "apt40", "lazarus", "sandworm", "cozy-bear", "fancy-bear",
    "equation-group", "carbanak", "fin7", "ta505",
}

# Known family patterns extractable from VT submitted filenames
_FILENAME_FAMILY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"zeus[.\-_]?panda", re.I),           "zeus-panda"),
    (re.compile(r"zeusgameover|gameover.zeus", re.I), "gameover-zeus"),
    (re.compile(r"\bzeusvm\b", re.I),                "zeus-vm"),
    (re.compile(r"\bzeus\b", re.I),                  "zeus"),
    (re.compile(r"\bwinnti\b", re.I),                "winnti"),
    (re.compile(r"\bmelofee\b", re.I),               "melofee"),
    (re.compile(r"\brunningrat\b", re.I),            "runningrat"),
    (re.compile(r"\bzxshell\b", re.I),               "zxshell"),
    (re.compile(r"\bfarfli\b", re.I),                "farfli"),
    (re.compile(r"\bcobalt.?strike\b", re.I),        "cobalt-strike"),
    (re.compile(r"\bmetasploit\b", re.I),            "metasploit"),
    (re.compile(r"\bmirai\b", re.I),                 "mirai"),
    (re.compile(r"\bemotet\b", re.I),                "emotet"),
    (re.compile(r"\btrickbot\b", re.I),              "trickbot"),
    (re.compile(r"\bqakbot|qbot\b", re.I),           "qakbot"),
    (re.compile(r"\bdanabot\b", re.I),               "danabot"),
    (re.compile(r"\bformbook\b", re.I),              "formbook"),
    (re.compile(r"\bagent.?tesla\b", re.I),          "agent-tesla"),
    (re.compile(r"\bnanocore\b", re.I),              "nanocore"),
    (re.compile(r"\bnjrat|bladabindi\b", re.I),      "njrat"),
    (re.compile(r"\basyncrat\b", re.I),              "asyncrat"),
    (re.compile(r"\bremcos\b", re.I),                "remcos"),
    (re.compile(r"\bdarkcomet\b", re.I),             "darkcomet"),
    (re.compile(r"\blumanyo\b", re.I),               "lumanyo"),
    (re.compile(r"\bvigorish\b", re.I),              "vigorish"),
    (re.compile(r"\bvigorf\b", re.I),                "vigorf"),
]


def _normalise_label(raw: str) -> list[str]:
    """Strip vendor prefixes and split composite labels into clean tokens."""
    if not raw or not isinstance(raw, str):
        return []

    label = raw.lower().strip()

    changed = True
    while changed:
        changed = False
        for prefix in _LABEL_STRIP_PREFIXES:
            if label.startswith(prefix):
                label = label[len(prefix):]
                changed = True

    parts = re.split(r"[/.]", label)
    return [
        p.strip() for p in parts
        if len(p.strip()) >= 3 and p.strip() not in _LABEL_NOISE
    ]


#  Family token extraction 


def extract_family_token_votes(report: dict) -> dict[str, float]:
    """
    Extract family tokens with weights.

    This differs from extract_family_tokens(): instead of returning a list,
    it returns a dict mapping token -> confidence vote weight.

    VirusTotal popular_threat_name counts are treated as community votes.
    Other sources contribute smaller but meaningful weights.

    Returns:
        {"dridex": 18.0, "yakes": 8.0, ...}
    """
    votes: dict[str, float] = defaultdict(float)

    ti = report.get("threat_intelligence", {})

    #  VirusTotal structured labels (community weighted) 
    vt = ti.get("VirusTotal", {})
    vt_names_all: list[str] = []

    for v in vt.values():
        if not isinstance(v, dict):
            continue

        ptc = v.get("popular_threat_classification") or {}

        for item in (ptc.get("popular_threat_name") or []):
            if not isinstance(item, dict):
                continue
            raw_val = item.get("value")
            count = float(item.get("count") or 1.0)
            for tok in _normalise_label(raw_val or ""):
                votes[tok] += count

        # suggested label is not a vote count, but still strong
        lbl = ptc.get("suggested_threat_label") or ""
        for tok in _normalise_label(lbl):
            votes[tok] += 6.0

        vt_names_all.extend(v.get("names") or [])

    #  AbuseCH + vendor intel (medium strength) 
    ab = ti.get("AbuseCH", {})
    for v in ab.values():
        if not isinstance(v, dict):
            continue

        sig = v.get("signature")
        for tok in _normalise_label(sig or ""):
            votes[tok] += 8.0

        for tag in (v.get("tags") or []):
            for tok in _normalise_label(tag or ""):
                votes[tok] += 3.0

        vi = v.get("vendor_intel") or {}
        for vendor_key, family_key in [
            ("Triage",  "malware_family"),
            ("Intezer", "family_name"),
            ("VMRay",   "malware_family"),
        ]:
            vendor = vi.get(vendor_key) or {}
            if isinstance(vendor, dict):
                fam = vendor.get(family_key)
                for tok in _normalise_label(fam or ""):
                    votes[tok] += 10.0

    #  Fallback: filename heuristics (weak) 
    if not votes:
        for name in vt_names_all:
            for pattern, canonical in _FILENAME_FAMILY_PATTERNS:
                if pattern.search(name):
                    votes[canonical] += 2.0
                    break

    return dict(votes)


def extract_family_tokens(report: dict) -> list[str]:
    """Compatibility wrapper: returns tokens ordered by descending vote."""
    votes = extract_family_token_votes(report)
    return [k for k, _ in sorted(votes.items(), key=lambda x: x[1], reverse=True)]


def _extract_corpus_family(corpus_report: dict) -> str | None:
    """Extract the best family token from a corpus report."""
    toks = extract_family_tokens(corpus_report)
    return toks[0] if toks else None


#  Family confidence scoring (single match) 

_FAMILY_SIGNAL_WEIGHTS: dict[str, float] = {
    "label":     0.45,
    "ssdeep":    0.15,
    "func_hash": 0.25,
    "string":    0.05,
    "mitre":     0.10,
}


def _family_match_score(sim_result: dict) -> float:
    """Compute a family confidence score for one corpus match."""
    label_sim   = float(sim_result.get("label_similarity", 0.0) or 0.0)
    ssdeep_sim  = float(sim_result.get("ssdeep_similarity", 0.0) or 0.0)
    func_sim    = float(sim_result.get("function_hash_similarity", 0.0) or 0.0)
    string_sim  = float(sim_result.get("weighted_string_similarity", 0.0) or 0.0)
    mitre_sim   = float(sim_result.get("mitre_similarity", 0.0) or 0.0)

    w = _FAMILY_SIGNAL_WEIGHTS

    active_total = (
        w["label"]     * (1 if label_sim > 0 else 0) +
        w["ssdeep"]    * (1 if ssdeep_sim > 0 else 0) +
        w["func_hash"] * (1 if func_sim > 0 else 0) +
        w["string"]    * 1 +
        w["mitre"]     * (1 if mitre_sim > 0 else 0)
    )

    if active_total == 0:
        return 0.0

    raw = (
        w["label"]     * label_sim +
        w["ssdeep"]    * ssdeep_sim +
        w["func_hash"] * func_sim +
        w["string"]    * string_sim +
        w["mitre"]     * mitre_sim
    ) / active_total

    return round(min(raw, 1.0), 6)


#  Function bridge detection 


def _best_function_bridge_match(scored_matches: list[dict]) -> dict | None:
    """
    Return the single strongest function-hash overlap match that also has a family label.
    """
    best = None
    best_score = 0.0

    for m in scored_matches:
        fam = m.get("family")
        func_sim = float(m.get("func_sim") or 0.0)

        if not fam:
            continue

        if func_sim > best_score:
            best_score = func_sim
            best = m

    # only treat as function-bridge if it passes minimum meaningful overlap
    if best and best_score >= 0.30:
        return best

    return None


#  Cluster verdict assignment 


def _cluster_verdict(
    family_confidence: float,
    identified_family: str | None,
    best_match: dict | None,
) -> str:
    """
    Assign a high-level cluster verdict based on match confidence and context.

    Verdicts:
      known_malicious_family  — strong match to confirmed malicious family
      known_benign_family     — strong match to confirmed benign family
      novel_variant           — strong structural match but no family label
      related_unknown         — moderate match; likely related but family unclear
      unrelated               — weak match; probably coincidental overlap
      unknown                 — insufficient data
    """
    if not best_match or family_confidence < 0.10:
        return "unknown"

    ctx = best_match.get("context", {})
    verdict_b = ctx.get("verdict_b", "UNKNOWN")

    if family_confidence >= 0.55:
        if identified_family:
            if verdict_b == "MALICIOUS":
                return "known_malicious_family"
            if verdict_b == "BENIGN":
                return "known_benign_family"
            return "known_family_verdict_uncertain"
        return "novel_variant"

    if family_confidence >= 0.25:
        return "related_unknown"

    return "unrelated"


#  Public API 

def _extract_sha256_from_binary_id(binary_id: str) -> str | None:
    """
    Attempt to extract a sha256-like token from a binary_id string.
    Supports formats like:
      "abc123....bin [abc123]"
      "44ae...ffc3.bin [44ae5d2173ef]"
    """
    if not binary_id or not isinstance(binary_id, str):
        return None

    # Try full sha256 at start
    m = re.match(r"^([a-f0-9]{64})", binary_id.strip(), re.I)
    if m:
        return m.group(1).lower()

    # Try bracket short hash [xxxxxxxxxxxx]
    m = re.search(r"\[([a-f0-9]{8,64})\]", binary_id, re.I)
    if m:
        return m.group(1).lower()

    return None


def _resolve_corpus_report_for_binary_id(
    binary_id: str,
    corpus_reports: dict[str, dict] | None,
) -> dict | None:
    """
    Resolve a binary_id from the disassembly similarity section into a corpus report.
    corpus_reports may be keyed by:
      - full binary_id string
      - sha256
      - short hash prefix
    """
    if not corpus_reports or not binary_id:
        return None

    # direct key match
    if binary_id in corpus_reports:
        return corpus_reports[binary_id]

    # try extracting hash tokens
    tok = _extract_sha256_from_binary_id(binary_id)
    if tok:
        # exact sha256 key
        if tok in corpus_reports:
            return corpus_reports[tok]

        # prefix match fallback
        for k, v in corpus_reports.items():
            if isinstance(k, str) and k.lower().startswith(tok):
                return v

    # try stripping extension
    stripped = binary_id.split(".")[0].strip()
    if stripped in corpus_reports:
        return corpus_reports[stripped]

    return None


def _best_disassembly_function_bridge(report: dict, corpus_reports: dict[str, dict] | None) -> dict | None:
    """
    Reads report["disassembly"]["similarity"]["function_similarity"] and returns the
    strongest function-similarity bridge match that can be resolved to a known family.

    Returns:
        {
          "binary_id": str,
          "family": str,
          "similarity_score": float,
          "overlap_pct_of_smaller": float,
          "shared_count": int,
          "total_in_new": int,
          "total_in_match": int
        }
    """
    if not corpus_reports:
        return None

    dis = report.get("disassembly") or {}
    sim = dis.get("similarity") or {}
    func_sims = sim.get("function_similarity") or []

    if not isinstance(func_sims, list):
        return None

    best = None
    best_score = 0.0

    for entry in func_sims:
        if not isinstance(entry, dict):
            continue

        bid = entry.get("binary_id") or ""
        similarity_score = float(entry.get("similarity_score") or 0.0)
        overlap_pct = float(entry.get("overlap_pct_of_smaller") or 0.0)

        if similarity_score <= 0 and overlap_pct <= 0:
            continue

        cr = _resolve_corpus_report_for_binary_id(bid, corpus_reports)
        if not cr:
            continue

        fam = _extract_corpus_family(cr)
        if not fam:
            continue

        # Use the stronger of the two
        score = max(similarity_score, overlap_pct)

        if score > best_score:
            best_score = score
            best = {
                "binary_id": bid,
                "family": fam,
                "similarity_score": similarity_score,
                "overlap_pct_of_smaller": overlap_pct,
                "shared_count": int(entry.get("shared_count") or 0),
                "total_in_new": int(entry.get("total_in_new") or 0),
                "total_in_match": int(entry.get("total_in_match") or 0),
            }

    # Require meaningful similarity
    if best and best_score >= 0.30:
        return best

    return None


def identify_family(
    report: dict,
    corpus_matches: list[dict],
    corpus_reports: dict[str, dict] | None = None,
) -> dict:
    """
    Identify the malware family using:
      - community-driven label voting (VT counts)
      - corpus family voting
      - function-bridge validation/override

    Args:
        report: normalized report for the new sample
        corpus_matches: compare_advanced() output list
        corpus_reports: optional map of binary_id/sha256 -> report dict

    Returns:
        dict matching output schema in module docstring.
    """
    #  Phase 1: extract community votes 
    token_votes = extract_family_token_votes(report)
    tokens_sorted = [k for k, _ in sorted(token_votes.items(), key=lambda x: x[1], reverse=True)]

    # Normalized "label confidence" derived from vote dominance
    label_candidate = tokens_sorted[0] if tokens_sorted else None
    label_conf = 0.0
    if token_votes and label_candidate:
        total = sum(token_votes.values())
        if total > 0:
            label_conf = token_votes[label_candidate] / total

    #  Phase 2: score corpus matches 
    scored_matches: list[dict] = []

    for match in corpus_matches or []:
        fam_score = _family_match_score(match)
        if fam_score < 0.01:
            continue

        corpus_family: str | None = None
        if corpus_reports:
            bid = match.get("binary_id", "")
            cr = corpus_reports.get(bid)
            if not cr:
                # sometimes corpus is keyed by sha256
                sha256 = match.get("sha256") or ""
                if sha256:
                    cr = corpus_reports.get(sha256)
            if cr:
                corpus_family = _extract_corpus_family(cr)

        scored_matches.append({
            "binary_id":    match.get("binary_id", ""),
            "family":       corpus_family,
            "family_score": fam_score,
            "label_sim":    round(float(match.get("label_similarity", 0.0) or 0.0), 4),
            "ssdeep_sim":   round(float(match.get("ssdeep_similarity", 0.0) or 0.0), 4),
            "func_sim":     round(float(match.get("function_hash_similarity", 0.0) or 0.0), 4),
            "string_sim":   round(float(match.get("weighted_string_similarity", 0.0) or 0.0), 4),
            "mitre_sim":    round(float(match.get("mitre_similarity", 0.0) or 0.0), 4),
            "context":      match.get("context", {}),
        })

    scored_matches.sort(key=lambda x: x["family_score"], reverse=True)
    top_matches = scored_matches[:5]

    #  Phase 3: aggregate family votes across corpus matches 
    corpus_family_votes: dict[str, float] = defaultdict(float)

    for m in scored_matches[:25]:
        fam = m.get("family")
        if not fam:
            continue

        # Weight by overall score, but boost if function similarity is strong
        func_sim = float(m.get("func_sim") or 0.0)
        boost = 1.0
        if func_sim >= 0.70:
            boost = 2.0
        elif func_sim >= 0.50:
            boost = 1.5
        elif func_sim >= 0.30:
            boost = 1.2

        corpus_family_votes[fam] += float(m.get("family_score") or 0.0) * boost

    corpus_candidate = None
    corpus_conf = 0.0
    if corpus_family_votes:
        corpus_candidate = max(corpus_family_votes.items(), key=lambda x: x[1])[0]
        total = sum(corpus_family_votes.values())
        if total > 0:
            corpus_conf = corpus_family_votes[corpus_candidate] / total

    #  Phase 4: function-bridge override logic 
    func_bridge = _best_function_bridge_match(scored_matches)

    func_bridge_family = None
    func_bridge_conf = 0.0
    if func_bridge:
        func_bridge_family = func_bridge.get("family")
        fs = float(func_bridge.get("func_sim") or 0.0)
        # map func_sim into a confidence scale
        if fs >= 0.70:
            func_bridge_conf = 0.95
        elif fs >= 0.50:
            func_bridge_conf = 0.85
        elif fs >= 0.30:
            func_bridge_conf = 0.70

    #  Phase 4.5: Disassembly function similarity bridge (NEW) 
    dis_func_bridge = _best_disassembly_function_bridge(report, corpus_reports)

    dis_bridge_family = None
    dis_bridge_conf = 0.0

    if dis_func_bridge:
        dis_bridge_family = dis_func_bridge.get("family")
        sim_score = float(dis_func_bridge.get("similarity_score") or 0.0)
        overlap = float(dis_func_bridge.get("overlap_pct_of_smaller") or 0.0)

        strength = max(sim_score, overlap)

        # map into confidence
        if strength >= 0.95:
            dis_bridge_conf = 0.98
        elif strength >= 0.85:
            dis_bridge_conf = 0.94
        elif strength >= 0.70:
            dis_bridge_conf = 0.88
        elif strength >= 0.50:
            dis_bridge_conf = 0.80
        elif strength >= 0.30:
            dis_bridge_conf = 0.70

    #  Decide final family 
    identified_family: str | None = None
    family_confidence: float = 0.0
    family_source: str = "unknown"

    # Rule 1: very strong label dominance
    if label_candidate and label_conf >= 0.55:
        identified_family = label_candidate
        family_confidence = min(0.95, 0.60 + label_conf * 0.50)
        family_source = "label_vote"

    # Rule 2: Disassembly function similarity is strongest override signal
    elif dis_bridge_family and dis_bridge_conf >= 0.88:
        identified_family = dis_bridge_family
        family_confidence = dis_bridge_conf
        family_source = "disassembly_func_bridge"

    # Rule 3: function bridge overrides weak/ambiguous labels
    elif func_bridge_family and func_bridge_conf >= 0.85:
        identified_family = func_bridge_family
        family_confidence = func_bridge_conf
        family_source = "func_bridge"

    # Rule 4: label exists but disassembly bridge provides validation or override
    elif label_candidate and dis_bridge_family and dis_bridge_conf >= 0.70:
        if dis_bridge_family == label_candidate:
            identified_family = label_candidate
            family_confidence = min(0.97, 0.80 + label_conf * 0.20)
            family_source = "label_vote+disassembly_bridge"
        else:
            identified_family = dis_bridge_family
            family_confidence = min(0.95, dis_bridge_conf)
            family_source = "disassembly_bridge_override"

    # Rule 5: label exists but function bridge provides validation/override
    elif label_candidate and func_bridge_family and func_bridge_conf >= 0.70:
        if func_bridge_family == label_candidate:
            identified_family = label_candidate
            family_confidence = min(0.95, 0.75 + (label_conf * 0.20))
            family_source = "label_vote+func_bridge"
        else:
            identified_family = func_bridge_family
            family_confidence = min(0.90, func_bridge_conf - 0.05)
            family_source = "func_bridge_override"

    # Rule 6: label exists, but isn't decisive -> still use it
    elif label_candidate and label_conf >= 0.30:
        identified_family = label_candidate
        family_confidence = min(0.90, 0.55 + label_conf * 0.50)
        family_source = "label_vote"

    # Rule 7: no strong label, but corpus converges to a likely family
    elif not label_candidate and corpus_candidate and corpus_conf >= 0.30:
        identified_family = f"possibly {corpus_candidate}"
        family_confidence = min(0.50, 0.25 + corpus_conf * 0.60)
        family_source = "closest_family"

    # Rule 8: no label, but corpus converges
    elif corpus_candidate and corpus_conf >= 0.45:
        identified_family = corpus_candidate
        family_confidence = min(0.85, 0.45 + corpus_conf * 0.60)
        family_source = "corpus_vote"

    # Rule 9: best match is structurally strong but unnamed
    elif top_matches and top_matches[0]["family_score"] >= 0.50:
        identified_family = None
        family_confidence = float(top_matches[0]["family_score"])
        family_source = "corpus_structural"

    else:
        identified_family = None
        family_confidence = float(top_matches[0]["family_score"]) if top_matches else 0.0
        family_source = "unknown"

    #  Candidate list output 
    candidates: list[dict] = []

    if label_candidate:
        candidates.append({
            "family": label_candidate,
            "score": round(label_conf, 4),
            "sources": ["label_vote"],
        })

    if corpus_candidate and corpus_candidate != label_candidate:
        candidates.append({
            "family": corpus_candidate,
            "score": round(corpus_conf, 4),
            "sources": ["corpus_vote"],
        })

    if func_bridge_family and func_bridge_family not in {label_candidate, corpus_candidate}:
        candidates.append({
            "family": func_bridge_family,
            "score": round(func_bridge_conf, 4),
            "sources": ["func_bridge"],
        })

    if dis_bridge_family and dis_bridge_family not in {label_candidate, corpus_candidate, func_bridge_family}:
        candidates.append({
            "family": dis_bridge_family,
            "score": round(dis_bridge_conf, 4),
            "sources": ["disassembly_func_bridge"],
        })

    # Ensure final family is always included
    if identified_family and all(c["family"] != identified_family for c in candidates):
        candidates.append({
            "family": identified_family,
            "score": round(family_confidence, 4),
            "sources": [family_source],
        })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    candidates = candidates[:3]

    best_match = top_matches[0] if top_matches else None
    cluster = _cluster_verdict(family_confidence, identified_family, best_match)

    return {
        "identified_family":      identified_family,
        "family_confidence":      round(float(family_confidence), 4),
        "family_source":          family_source,
        "family_tokens":          tokens_sorted,
        "family_token_votes":     {k: round(v, 3) for k, v in sorted(token_votes.items(), key=lambda x: x[1], reverse=True)},
        "top_family_candidates":  candidates,
        "top_corpus_matches":     top_matches,
        "cluster_verdict":        cluster,
    }


def print_family_report(result: dict) -> None:
    """Print a human-readable family identification summary."""
    fam  = result.get("identified_family") or "Unknown"
    conf = float(result.get("family_confidence", 0.0) or 0.0)
    src  = result.get("family_source", "unknown")
    clus = result.get("cluster_verdict", "unknown")

    print(f"[+] Family identification: {fam} ({conf:.0%} confidence via {src})")
    print(f"    Cluster verdict: {clus}")

    toks = result.get("family_tokens") or []
    if toks:
        print(f"    Family tokens: {', '.join(toks)}")

    votes = result.get("family_token_votes") or {}
    if votes:
        top = list(votes.items())[:5]
        print("    Community label votes:")
        for k, v in top:
            print(f"      - {k}: {v}")

    matches = result.get("top_corpus_matches") or []
    if matches:
        print("    Top corpus matches:")
        for m in matches[:5]:
            corpus_fam = m.get("family") or "?"
            print(
                f"      -> {m['binary_id']} | family={corpus_fam} | "
                f"score={m['family_score']:.2%} | "
                f"label={m['label_sim']:.2%} "
                f"ssdeep={m['ssdeep_sim']:.2%} "
                f"func={m['func_sim']:.2%} "
                f"mitre={m['mitre_sim']:.2%}"
            )
