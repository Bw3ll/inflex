from collections import Counter

WEIGHTS = {
    "virustotal": 0.40,
    "capa":       0.30,
    "yara":       0.15,
    "abuse":      0.10,
    "osint":      0.05,
}

VERDICTS = [
    (0.85, "Malicious"),
    (0.65, "Likely Malicious"),
    (0.40, "Suspicious / Dual-Use"),
    (0.15, "Likely Benign"),
    (0.00, "Benign")
]

HIGH_RISK_TACTICS = {
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "command-and-control",
    "collection",         # keylogging, clipboard theft, screen capture
    "exfiltration",
    "impact",
}

# When VT ratio exceeds this AND abuse confirms, floor confidence here
CONFIRMED_MALWARE_FLOOR = 0.90

# VT ratio above which we treat as strong positive
VT_HIGH_CONFIDENCE_THRESHOLD = 0.75


def capa_score(capa_hits: list) -> float:
    """
    Score behavioral evidence from CAPA ATT&CK mappings.

    High-risk tactics (persistence, priv-esc, defense-evasion, C2, collection,
    exfiltration) score 0.15 per unique technique hit, others score 0.05.
    Capped at 0.90 so capa alone cannot push to maximum confidence.
    """
    if not capa_hits:
        return 0.0

    # Deduplicate by technique ID to avoid inflation from multiple capa rules
    # mapping to the same technique
    seen_techniques = set()
    score = 0.0
    for hit in capa_hits:
        tid = hit.get("technique")
        tactic = (hit.get("tactic") or "").lower()
        if tid in seen_techniques:
            continue
        seen_techniques.add(tid)
        if tactic in HIGH_RISK_TACTICS:
            score += 0.15
        else:
            score += 0.05

    return min(score, 0.90)


def yara_score(yara_hits: list) -> float:
    """
    Score YARA signature matches.

    Zero hits does NOT mean clean — local rules may not yet cover this variant.
    Score is only non-zero when rules actually fire.
    """
    if not yara_hits:
        return 0.0
    return min(0.4 + 0.1 * len(yara_hits), 1.0)


def vt_score(vt_result) -> float:
    """
    Score VirusTotal detections.

    Accepts either:
      - dict with 'positives' and 'total' keys (from threat_intel normalisation)
      - dict with 'analysis_stats' (raw VT API format)
      - pre-computed float/int

    The score is the raw detection ratio — no artificial scaling. 59/66 = 0.89.
    The weight (0.40) then gives VT its appropriate influence in the fusion.
    """
    if not vt_result:
        return 0.0

    if isinstance(vt_result, (int, float)):
        return min(float(vt_result), 1.0)

    # Normalised format: {"positives": N, "total": N}
    if "positives" in vt_result:
        positives = vt_result.get("positives", 0) or 0
        total     = vt_result.get("total", 1) or 1
        return min(positives / max(total, 1), 1.0)

    # Raw VT format: {"analysis_stats": {...}}
    stats = vt_result.get("analysis_stats") or {}
    if stats:
        malicious = stats.get("malicious", 0) or 0
        total = sum(
            stats.get(k, 0) or 0
            for k in ("malicious", "suspicious", "undetected", "harmless")
        )
        return min(malicious / max(total, 1), 1.0)

    return 0.0


def fuse_scores(scores: dict) -> float:
    """
    Weighted average fusion across all signal sources.

    Only active sources (weight > 0) contribute. A source with score 0.0
    still contributes its weight — meaning a YARA miss genuinely pulls the
    score down slightly, which is intentional. The new weight ordering
    (VT=0.40, capa=0.30, yara=0.15, abuse=0.10, osint=0.05) ensures VT
    dominates when there is strong detection consensus.
    """
    total_weight = sum(WEIGHTS.get(src, 0) for src in scores)
    if total_weight == 0:
        return 0.0
    return sum(WEIGHTS.get(src, 0) * score for src, score in scores.items()) / total_weight


def check_confirmed_malware(vt_result, abuse_result) -> bool:
    """
    Ground-truth override: VT ratio above threshold AND Abuse.ch confirms.

    When both conditions are met, local YARA silence is irrelevant — we have
    multi-source ground truth and should floor at CONFIRMED_MALWARE_FLOOR.
    """
    computed_vt = vt_score(vt_result)
    confirmed_in_abuse = isinstance(abuse_result, (int, float)) and abuse_result >= 0.5
    return computed_vt >= VT_HIGH_CONFIDENCE_THRESHOLD and confirmed_in_abuse


def check_vt_overwhelming(vt_result) -> bool:
    """
    Secondary override: VT alone is overwhelming (>= 0.85 ratio) even without
    Abuse.ch confirmation. A file with 59/66 detections should not be "Likely
    Benign" regardless of YARA silence.
    """
    return vt_score(vt_result) >= 0.85


def verdict_from_confidence(conf: float) -> str:
    for threshold, label in VERDICTS:
        if conf >= threshold:
            return label
    return "Unknown"


def build_reasoning(scores: dict, capa_hits: list, yara_hits: list,
                    floored: bool = False, vt_floored: bool = False) -> list[str]:
    reasons = []

    if floored:
        reasons.append(
            "Confidence floored: overwhelming VirusTotal detections confirmed by "
            "Abuse.ch signature — local YARA silence does not negate multi-source ground truth"
        )
    elif vt_floored:
        reasons.append(
            "Confidence floored: VirusTotal detection ratio is overwhelming "
            "(>=85%) — local YARA silence does not negate multi-engine consensus"
        )

    if capa_hits:
        # Count unique techniques
        unique_techs = len({h.get("technique") for h in capa_hits if h.get("technique")})
        reasons.append(
            f"Behavioral analysis identified {unique_techs} unique ATT&CK "
            f"technique(s) from {len(capa_hits)} capa rule match(es)"
        )

    if yara_hits:
        reasons.append(f"YARA matched {len(yara_hits)} known malware signature(s)")
    else:
        reasons.append(
            "No local YARA signatures matched — local rules may not yet cover this variant"
        )

    for src, score in scores.items():
        if score == 0.0:
            reasons.append(f"No risk contribution from {src}")

    return reasons


def analyze(
    capa_hits:    list,
    yara_hits:    list,
    vt_result     = None,
    abuse_result  = None,
    osint_result  = None,
) -> dict:
    """
    Compute a final maliciousness verdict from all available signal sources.
    """
    scores = {
        "virustotal": vt_score(vt_result),
        "capa":       capa_score(capa_hits),
        "yara":       yara_score(yara_hits),
        "abuse":      float(abuse_result or 0.0),
        "osint":      float(osint_result or 0.0),
    }

    #  Override checks 
    floored    = check_confirmed_malware(vt_result, abuse_result)
    vt_floored = (not floored) and check_vt_overwhelming(vt_result)

    if floored:
        confidence = CONFIRMED_MALWARE_FLOOR
    elif vt_floored:
        # Floor at the VT ratio itself (e.g. 59/66 = 0.89 -> capped at 0.90)
        confidence = min(scores["virustotal"], CONFIRMED_MALWARE_FLOOR)
    else:
        confidence = fuse_scores(scores)

    verdict   = verdict_from_confidence(confidence)
    reasoning = build_reasoning(scores, capa_hits, yara_hits, floored, vt_floored)

    return {
        "verdict":    verdict,
        "confidence": round(confidence, 3),
        "scores":     scores,
        "reasoning":  reasoning,
        "hits": {
            "capa": capa_hits,
            "yara": yara_hits,
        },
    }
