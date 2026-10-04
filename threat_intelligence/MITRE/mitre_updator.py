from datetime import datetime, timedelta, timezone
import json
import os

from threat_intelligence.MITRE.stix_ingest import load_attack_stix
from threat_intelligence.MITRE.normalize import normalize_technique
from threat_intelligence.MITRE.run_capa import run
from threat_intelligence.MITRE.yara_engine import run_yara
from threat_intelligence.MITRE.yara_mapping import extract_attack_ids
from threat_intelligence.MITRE.final_verdict import analyze

# from stix_ingest import load_attack_stix
# from normalize import normalize_technique
# from run_capa import run
# from yara_engine import run_yara
# from yara_mapping import extract_attack_ids
# from final_verdict import analyze

STORE_PATH = "threat_intelligence\\MITRE\\mitre_store1.json"
UPDATE_INTERVAL = timedelta(days=1)


def load_store():
    if not os.path.exists(STORE_PATH):
        return {"last_updated": None, "techniques": {}}
    with open(STORE_PATH, "r") as f:
        return json.load(f)


def save_store(store):
    with open(STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)


def needs_update(ts):
    if not ts:
        return True
    last = datetime.fromisoformat(ts.replace("Z", ""))
    return datetime.now(timezone.utc) - last > UPDATE_INTERVAL


def update_store():
    store = load_store()

    if not needs_update(store["last_updated"]):
        print("[+] MITRE store is current")
        return

    stix_objects = load_attack_stix()
    normalized = []

    for obj in stix_objects:
        tech = normalize_technique(obj)
        if tech:
            normalized.append(tech)

    # Pass 1: parent techniques
    for tech in normalized:
        tid = tech["id"]
        if "." not in tid:
            if tid not in store["techniques"]:
                store["techniques"][tid] = {
                    "name": tech["name"],
                    "tactics": tech["tactics"],
                    "platforms": tech["platforms"],
                    "data_sources": tech["data_sources"],

                    #  EXTENDED STRUCTURE
                    "evidence": {},

                    "subtechniques": {},
                    "history": [{
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "change": "Technique added"
                    }]
                }

    # Pass 2: sub-techniques
    for tech in normalized:
        tid = tech["id"]
        if "." in tid:
            parent = tid.split(".")[0]
            if parent in store["techniques"]:
                subs = store["techniques"][parent]["subtechniques"]
                if tid not in subs:
                    subs[tid] = {
                        "name": tech["name"],
                        "added": datetime.now(timezone.utc).isoformat()
                    }
                    store["techniques"][parent]["history"].append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "change": f"Added sub-technique {tid}"
                    })

    store["last_updated"] = datetime.now(timezone.utc).isoformat()
    save_store(store)
    print("[+] MITRE ATT&CK store updated successfully")


def correlate_yara(store, yara_hits):
    for hit in yara_hits:
        attack_ids = extract_attack_ids(hit)

        for tid in attack_ids:
            if tid not in store["techniques"]:
                continue

            evidence = store["techniques"][tid]["evidence"].setdefault("yara", [])
            evidence.append({
                "rule": hit["rule"],
                "namespace": hit["namespace"],
                "tags": hit["tags"],
                "meta": hit["meta"]
            })

            store["techniques"][tid]["history"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "change": f"YARA evidence added ({hit['rule']})"
            })

def run_mitre(sample=None, vt_result=None, abuse_result=None, osint_result=None):
    """
    Run MITRE ATT&CK analysis (CAPA + YARA) and generate final verdict.
    
    Args:
        sample: Path to the sample file to analyze
        vt_result: VirusTotal results dict with 'positives' and 'total' keys
        abuse_result: Abuse.ch/AbuseIPDB risk score (0.0-1.0)
        osint_result: OSINT risk score (0.0-1.0)
    
    Returns:
        Dictionary with final verdict, confidence, scores, and reasoning
    """
    print("WE ARE IN RUN MITRE FUNCTION NOW")
    update_store()

    # CAPA
    capa_results = run(sample)

    # YARA
    yara_hits = run_yara(sample)

    print(f"[+] YARA hits: {len(yara_hits)}")
    for hit in yara_hits:
        print(hit)

    store = load_store()
    correlate_yara(store, yara_hits)
    save_store(store)

    print("[+] CAPA + YARA correlation complete")

    # Generate final verdict with all available threat intelligence
    final_verdict = analyze(
        capa_hits=capa_results,
        yara_hits=yara_hits,
        vt_result=vt_result,
        abuse_result=abuse_result,
        osint_result=osint_result
    )

    print(final_verdict)
    return final_verdict


if __name__ == "__main__":
    update_store()

    sample = r"C:\Users\lcbba\OneDrive\Desktop\labs\labs\Lab 9\FTP Utility\KMFtp.exe"

    # CAPA
    capa_results = run(sample)

    # YARA
    yara_hits = run_yara(sample)

    print(f"[+] YARA hits: {len(yara_hits)}")
    for hit in yara_hits:
        print(hit)

    store = load_store()
    correlate_yara(store, yara_hits)
    save_store(store)

    print("[+] CAPA + YARA correlation complete")

    final_verdict = analyze(capa_results, yara_hits)

    print(final_verdict)
