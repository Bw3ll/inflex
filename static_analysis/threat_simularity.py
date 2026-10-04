import json
from pathlib import Path
from collections import Counter


#  Helpers 

def extract_sha256(report: dict) -> str:
    return (
        report.get("ingest_analysis", {}).get("sha256")
        or report.get("static_analysis", {}).get("hashes", {}).get("sha256")
        or ""
    )


def normalize_label(label: str) -> str:
    if not label:
        return ""

    label = label.lower().strip()

    # remove common prefixes
    for prefix in ["trojan.", "worm.", "ransom.", "win32.", "malware.", "heur:"]:
        label = label.replace(prefix, "")

    # split composite labels
    if "/" in label:
        label = label.split("/")[0]

    # remove junk / noise
    blacklist = {
        "exe", "generic", "malware", "unknown",
        "win32", "agent", "heur", "trojan"
    }

    if label in blacklist:
        return ""

    # remove IP-like junk (e.g., 38-55-205-7 → becomes digits)
    cleaned = label.replace(".", "").replace("-", "")
    if cleaned.isdigit():
        return ""

    return label.strip()


#  Label Extraction 

def extract_labels_from_report(report: dict) -> set[str]:
    labels = set()

    ti = report.get("threat_intelligence") or {}

    #  VirusTotal 
    vt = ti.get("VirusTotal") or {}

    seen_sha = set()  # avoid duplicate entries (same sample via md5/sha1/sha256)

    for _, entry in vt.items():
        if not isinstance(entry, dict):
            continue

        sha = entry.get("sha256")
        if sha and sha in seen_sha:
            continue
        if sha:
            seen_sha.add(sha)

        ptc = entry.get("popular_threat_classification") or {}

        # suggested label
        lbl = normalize_label(ptc.get("suggested_threat_label", ""))
        if lbl:
            labels.add(lbl)

        # names
        for item in ptc.get("popular_threat_name") or []:
            if isinstance(item, dict):
                lbl = normalize_label(item.get("value", ""))
                if lbl:
                    labels.add(lbl)

        # categories
        for item in ptc.get("popular_threat_category") or []:
            if isinstance(item, dict):
                lbl = normalize_label(item.get("value", ""))
                if lbl:
                    labels.add(lbl)

    #  AbuseCH 
    abuse = ti.get("AbuseCH") or {}

    for _, entry in abuse.items():
        if not isinstance(entry, dict):
            continue

        # signature
        lbl = normalize_label(entry.get("signature", ""))
        if lbl:
            labels.add(lbl)

        # tags
        for tag in entry.get("tags") or []:
            lbl = normalize_label(tag)
            if lbl:
                labels.add(lbl)

        vendor = entry.get("vendor_intel") or {}

        # ANY.RUN
        for item in vendor.get("ANY.RUN") or []:
            if isinstance(item, dict):
                lbl = normalize_label(item.get("malware_family", ""))
                if lbl:
                    labels.add(lbl)

        # Triage
        triage = vendor.get("Triage") or {}
        lbl = normalize_label(triage.get("malware_family", ""))
        if lbl:
            labels.add(lbl)

        for tag in triage.get("tags") or []:
            lbl = normalize_label(tag)
            if lbl:
                labels.add(lbl)

        # Intezer
        intezer = vendor.get("Intezer") or {}
        lbl = normalize_label(intezer.get("family_name", ""))
        if lbl:
            labels.add(lbl)

        # VMRay
        vmray = vendor.get("VMRay") or {}
        lbl = normalize_label(vmray.get("malware_family", ""))
        if lbl:
            labels.add(lbl)

        # Kaspersky
        kas = vendor.get("Kaspersky") or {}
        for det in kas.get("detections") or []:
            lbl = normalize_label(det)
            if lbl:
                labels.add(lbl)

    return labels


#  Similarity 

def jaccard_similarity(a: set, b: set) -> float:
    union = len(a | b)
    return 0.0 if union == 0 else len(a & b) / union


def compare_label_sets(a: set, b: set):
    shared = a & b

    return {
        "shared_count": len(shared),
        "similarity_score": round(jaccard_similarity(a, b), 6),
        "shared_labels": list(shared)
    }


#  Core API 

def compare_threat_labels_single_report(
    new_report: dict,
    reports_dir: str | Path,
    min_shared: int = 1
):
    reports_dir = Path(reports_dir)

    new_labels = extract_labels_from_report(new_report)
    if not new_labels:
        print("[!] No threat labels in new report")
        return []

    new_sha = extract_sha256(new_report)

    matches = []

    for jp in reports_dir.glob("*.json"):

        #  skip normalized duplicates
        if jp.name.endswith("_normalized.json"):
            continue

        try:
            with open(jp, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            continue

        existing_sha = extract_sha256(existing)

        #  skip self-match
        if existing_sha and existing_sha == new_sha:
            continue

        existing_labels = extract_labels_from_report(existing)
        if not existing_labels:
            continue

        result = compare_label_sets(new_labels, existing_labels)

        if result["shared_count"] < min_shared:
            continue

        matches.append({
            "file": jp.stem,
            "shared_count": result["shared_count"],
            "similarity_score": result["similarity_score"],
            "shared_labels": result["shared_labels"]
        })

    # deduplicate by file name (safety)
    unique = {}
    for m in matches:
        unique[m["file"]] = m

    matches = list(unique.values())

    matches.sort(key=lambda x: x["similarity_score"], reverse=True)

    print(f"[+] Threat label similarity: {len(matches)} match(es)")
    for m in matches:
        print(
            f"    → {m['file']} | shared: {m['shared_count']} "
            f"| jaccard: {m['similarity_score']:.2%}"
        )

    return matches
