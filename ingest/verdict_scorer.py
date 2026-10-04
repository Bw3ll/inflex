"""
verdict_scorer.py

Signals are evaluated in three tiers:

  Tier 1 — Ground truth overrides (skip fusion entirely):
    - VT ratio >= 85% AND Abuse.ch confirmed  -> floor at 0.92
    - VT ratio >= 85% alone                   -> floor at VT ratio
    - Abuse.ch confirmed AND any capa hits     -> floor at 0.80

  Tier 2 — Weighted fusion of all available signals:
    virustotal: 0.42  (strongest — multi-engine consensus is ground truth)
    capa:       0.28  (behavioral, format-independent, hard to fake)
    yara:       0.15  (meaningful when it fires; low weight so silence
                       doesn't collapse the verdict)
    abuse:      0.10  (confirmation signal)
    emerging:   0.15  (emerging technical evidence such as steganography,
                       high-entropy payloads, or hidden payload delivery)
    corpus:     0.03  (weak corroboration from family match)
    osint:      0.02  (weakest — easily gamed or absent)

  Tier 3 — Verdict tiers mapped from confidence:
    >= 0.85  Malicious
    >= 0.65  Likely Malicious
    >= 0.40  Suspicious / Dual-Use
    >= 0.15  Likely Benign
    >= 0.00  Benign
"""

from __future__ import annotations
from collections import Counter


#  Configuration 

WEIGHTS: dict[str, float] = {
    "virustotal": 0.42,
    "capa":       0.28,
    "yara":       0.15,
    "abuse":      0.10,
    "emerging":   0.15,
    "corpus":     0.03,
    "osint":      0.02,
}

VERDICT_TIERS: list[tuple[float, str]] = [
    (0.85, "Malicious"),
    (0.65, "Likely Malicious"),
    (0.40, "Suspicious / Dual-Use"),
    (0.15, "Likely Benign"),
    (0.00, "Benign"),
]

# Tactics that contribute a higher per-technique score
HIGH_RISK_TACTICS: set[str] = {
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "command-and-control",
    "collection",       # keylogging, clipboard theft, screen capture
    "exfiltration",
    "impact",
    "lateral-movement",
}

# Ground truth override thresholds
VT_OVERWHELMING_THRESHOLD    = 0.85   # VT alone floors verdict
VT_HIGH_CONFIDENCE_THRESHOLD = 0.75   # VT + Abuse.ch floor verdict
ABUSE_CONFIRMED_SCORE        = 0.50   # Abuse.ch score when hash is found

FLOOR_VT_PLUS_ABUSE   = 0.92
FLOOR_VT_ALONE        = None   # uses actual VT ratio as floor
FLOOR_ABUSE_PLUS_CAPA = 0.80


#  Signal scorers 

def _vt_score(vt_result) -> float:
    """
    Compute a [0.0, 1.0] score from VirusTotal results.

    Accepts multiple input formats:
      - dict with 'analysis_stats' key (raw VT API / normalised report format)
      - dict with 'positives' and 'total' keys
      - pre-computed float/int ratio

    Returns the raw detection ratio with no artificial inflation. 59/66 = 0.894.
    """
    if not vt_result:
        return 0.0

    if isinstance(vt_result, (int, float)):
        return min(float(vt_result), 1.0)

    # Raw VT format via normalised report: VirusTotal is a dict of hash -> entry
    # Scan all entries and take the maximum detection ratio seen
    if isinstance(vt_result, dict):
        # Check if this is the full VirusTotal sub-dict (keyed by hash)
        max_ratio = 0.0
        for v in vt_result.values():
            if not isinstance(v, dict):
                continue
            stats = v.get("analysis_stats") or {}
            if stats:
                mal   = stats.get("malicious", 0) or 0
                total = sum(
                    stats.get(k, 0) or 0
                    for k in ("malicious", "suspicious", "undetected", "harmless")
                )
                if total > 0:
                    max_ratio = max(max_ratio, mal / total)

        if max_ratio > 0:
            return min(max_ratio, 1.0)

        # Fallback: single entry with positives/total
        pos   = vt_result.get("positives", 0) or 0
        total = vt_result.get("total", 1) or 1
        return min(pos / max(total, 1), 1.0)

    return 0.0


def _capa_score(capa_hits: list) -> float:
    """
    Score behavioral evidence from capa ATT&CK technique mappings.

    Deduplicates by technique ID so N capa rules matching the same
    technique ID don't produce N×score inflation. High-risk tactics
    score 0.15 per unique technique, others 0.05. Capped at 0.90.
    """
    if not capa_hits:
        return 0.0

    seen: set[str] = set()
    score = 0.0

    for hit in capa_hits:
        tid    = hit.get("technique", "")
        tactic = (hit.get("tactic") or "").lower().strip()

        if tid and tid in seen:
            continue
        if tid:
            seen.add(tid)

        if tactic in HIGH_RISK_TACTICS:
            score += 0.15
        else:
            score += 0.05

    return min(score, 0.90)


def _yara_score(yara_hits: list) -> float:
    """
    Score YARA signature matches.

    Zero hits does NOT mean clean — local rule sets simply may not cover
    this variant yet. Score is only non-zero when rules actually fire.
    Each additional hit contributes diminishing returns.
    """
    if not yara_hits:
        return 0.0
    return min(0.50 + 0.05 * (len(yara_hits) - 1), 1.0)


def _emerging_score(emerging_result: float) -> float:
    """
    Score evidence from emerging or non-public threat indicators.

    This supports files with strong technical indicators such as steganographic
    payload carriers, high-entropy sections, or hidden payload delivery
    techniques, even when community reputation feeds are missing.
    """
    try:
        score = float(emerging_result or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return min(max(score, 0.0), 1.0)


#  Override checks 

def _check_vt_plus_abuse(vt_score: float, abuse_result: float) -> bool:
    """VT high confidence AND Abuse.ch confirmed -> strongest ground truth."""
    return (
        vt_score >= VT_HIGH_CONFIDENCE_THRESHOLD
        and abuse_result >= ABUSE_CONFIRMED_SCORE
    )


def _check_vt_overwhelming(vt_score: float) -> bool:
    """VT alone is overwhelming even without Abuse.ch."""
    return vt_score >= VT_OVERWHELMING_THRESHOLD


def _check_abuse_plus_capa(abuse_result: float, capa_hits: list) -> bool:
    """Abuse.ch confirmed AND behavioral evidence present."""
    return abuse_result >= ABUSE_CONFIRMED_SCORE and bool(capa_hits)


def _should_use_emerging(vt_raw: float, abuse_result: float) -> bool:
    """Use emerging threat evidence only when public reputation sources are absent."""
    return vt_raw == 0.0 and abuse_result == 0.0


#  Fusion 

def _fuse(scores: dict[str, float], no_public_reputation: bool = False) -> float:
    """
    Weighted average fusion. Only keys present in WEIGHTS contribute.
    Sources with score 0.0 still consume their weight — a YARA miss
    genuinely pulls the score down slightly, which is intentional.
    The new VT-dominant weighting ensures detection consensus wins.
    
    When no public reputation sources (VT/Abuse) are available, suppress their
    zero contributions and boost emerging threat weight instead.
    """
    # Adjust weights if no public reputation available
    weights = WEIGHTS.copy()
    if no_public_reputation:
        # Suppress VT/Abuse zero contributions and redistribute to emerging
        weights["virustotal"] = 0.0
        weights["abuse"] = 0.0
        weights["emerging"] = 0.50  # boost emerging from 0.10 to 0.50
    
    total_weight = sum(weights.get(k, 0.0) for k in scores)
    if total_weight == 0:
        return 0.0
    return sum(weights.get(k, 0.0) * v for k, v in scores.items()) / total_weight


def _verdict_label(confidence: float) -> str:
    for threshold, label in VERDICT_TIERS:
        if confidence >= threshold:
            return label
    return "Unknown"


#  Reasoning builder 

def _build_reasoning(
    scores:       dict[str, float],
    capa_hits:    list,
    yara_hits:    list,
    override:     str | None,
    vt_raw_score: float,
) -> list[str]:
    reasons: list[str] = []

    if override == "vt_plus_abuse":
        reasons.append(
            "Confidence floored: overwhelming VirusTotal detections confirmed by "
            "Abuse.ch — local YARA silence does not negate multi-source ground truth"
        )
    elif override == "vt_alone":
        reasons.append(
            f"Confidence floored at VT detection ratio ({vt_raw_score:.0%}): "
            "multi-engine consensus overrides weak local signatures"
        )
    elif override == "abuse_plus_capa":
        reasons.append(
            "Confidence floored: Abuse.ch hash confirmation combined with "
            "behavioral evidence from capa"
        )

    if capa_hits:
        unique_techs = len({h.get("technique") for h in capa_hits if h.get("technique")})
        unique_tactics = {(h.get("tactic") or "").lower() for h in capa_hits}
        high_risk = unique_tactics & HIGH_RISK_TACTICS
        reasons.append(
            f"capa identified {unique_techs} unique ATT&CK technique(s) "
            f"across {len(capa_hits)} rule match(es)"
            + (f"; high-risk tactics: {', '.join(sorted(high_risk))}" if high_risk else "")
        )

    if yara_hits:
        reasons.append(f"YARA matched {len(yara_hits)} signature(s)")
    else:
        reasons.append(
            "No local YARA signatures matched — rules may not yet cover this variant"
        )

    for src, score in scores.items():
        if score == 0.0 and src not in ("corpus", "osint"):
            reasons.append(f"No risk contribution from {src}")

    if scores.get("emerging", 0.0) > 0:
        reasons.append(
            "Emerging threat evidence detected: hidden-payload / high-entropy artifact "
            "signal not yet confirmed by community reputation sources"
        )
        if scores.get("emerging", 0.0) >= 0.50:
            reasons.append(
                "Strong steganographic or hidden-payload evidence is influencing the verdict."
            )

    if scores.get("corpus", 0.0) > 0:
        reasons.append(
            f"Corpus family match provides corroborating malicious signal "
            f"(corpus score: {scores['corpus']:.0%})"
        )

    return reasons


#  Public API 

def score_verdict(
    capa_hits:     list,
    yara_hits:     list,
    vt_result              = None,
    abuse_result:  float   = 0.0,
    emerging_result: float   = 0.0,
    corpus_signal: float   = 0.0,
    osint_result:  float   = 0.0,
) -> dict:
    """
    Compute a final maliciousness verdict.

    Args:
        capa_hits:      List of ATT&CK hit dicts from capa analysis.
                        Each dict must have 'technique' and 'tactic' keys.
        yara_hits:      List of YARA rule match dicts.
        vt_result:      VirusTotal data. Accepts:
                          - The full threat_intelligence.VirusTotal dict
                            (keyed by hash, each value has 'analysis_stats')
                          - A dict with 'positives'/'total' keys
                          - A pre-computed float ratio
        abuse_result:   Abuse.ch score. Use 0.5 when hash is found in the
                        database, 0.0 when not found.
        emerging_result: Emerging threat score derived from non-public technical
                        evidence (e.g. steganographic carriers, high entropy,
                        hidden payload delivery patterns).
        corpus_signal:  Confidence score from family_identifier when it
                        identifies a known-malicious family match. Pass 0.0
                        if no family match or family is unknown.
        osint_result:   OSINT enrichment score (0.0-1.0).

    Returns:
        {
          "verdict":     str,           -- human label
          "confidence":  float,         -- [0.0, 1.0]
          "override":    str | None,    -- which ground-truth tier fired
          "scores":      dict,          -- per-source scores before weighting
          "reasoning":   list[str],     -- human-readable explanation
          "hits": {
            "capa": list,
            "yara": list,
          }
        }
    """
    vt_raw = _vt_score(vt_result)

    scores: dict[str, float] = {
        "virustotal": vt_raw,
        "capa":       _capa_score(capa_hits),
        "yara":       _yara_score(yara_hits),
        "abuse":      float(abuse_result or 0.0),
        "emerging":   _emerging_score(emerging_result),
        "corpus":     float(min(corpus_signal or 0.0, 1.0)),
        "osint":      float(osint_result or 0.0),
    }

    #  Override tier evaluation 
    override: str | None = None
    confidence: float

    if _check_vt_plus_abuse(vt_raw, scores["abuse"]):
        override    = "vt_plus_abuse"
        confidence  = FLOOR_VT_PLUS_ABUSE

    elif _check_vt_overwhelming(vt_raw):
        override    = "vt_alone"
        confidence  = vt_raw           # floor AT the ratio, not above it

    elif _check_abuse_plus_capa(scores["abuse"], capa_hits):
        override    = "abuse_plus_capa"
        confidence  = FLOOR_ABUSE_PLUS_CAPA

    else:
        no_pub_rep = _should_use_emerging(vt_raw, scores["abuse"])
        confidence = _fuse(scores, no_public_reputation=no_pub_rep)
        if no_pub_rep:
            # If using emerging evidence, suppress it once reputation sources appear
            scores["virustotal"] = 0.0
            scores["abuse"] = 0.0

        # Strong stego or hidden-payload evidence should elevate verdicts even
        # when community reputation is absent.
        if no_pub_rep and scores.get("emerging", 0.0) >= 0.50:
            confidence = max(confidence, 0.40)
        if no_pub_rep and scores.get("emerging", 0.0) >= 0.70:
            confidence = max(confidence, 0.55)

    confidence = round(min(confidence, 1.0), 4)
    verdict    = _verdict_label(confidence)
    reasoning  = _build_reasoning(scores, capa_hits, yara_hits, override, vt_raw)

    return {
        "verdict":    verdict,
        "confidence": confidence,
        "override":   override,
        "scores":     {k: round(v, 4) for k, v in scores.items()},
        "reasoning":  reasoning,
        "hits": {
            "capa": capa_hits,
            "yara": yara_hits,
        },
    }
