from datetime import datetime
import json

MITRE_STORE_PATH = "threat_intelligence\\MITRE\\mitre_store1.json"


def load_mitre_map():
    """Load MITRE store and build a map: name -> T####"""
    with open(MITRE_STORE_PATH, "r") as f:
        store = json.load(f)

    mapping = {}
    for tid, data in store["techniques"].items():
        mapping[data["name"]] = tid
        for sub_id, sub_data in data.get("subtechniques", {}).items():
            mapping[sub_data["name"]] = sub_id

    return mapping


MITRE_NAME_MAP = load_mitre_map()


def ingest_capa(capa_json):
    evidence = []

    rules = capa_json.get("rules", {})
    for rule_name, rule in rules.items():
        meta = rule.get("meta", {})
        attack_entries = meta.get("attack", [])

        for entry in attack_entries:
            # capa v9 format
            if isinstance(entry, dict):
                name = entry.get("technique")
                tactic = entry.get("tactic")
            else:
                # fallback for older capa styles
                name = entry
                tactic = None

            if not name:
                continue

            # Convert technique NAME to MITRE ATT&CK ID
            tid = MITRE_NAME_MAP.get(name)
            if not tid:
                # Skip unknown or non-ATT&CK capa techniques
                continue

            evidence.append({
                "technique": tid,     # now T#### format
                "tactic": tactic,
                "source": "capa",
                "rule": rule_name,
                "confidence": 0.7,
                "timestamp": datetime.utcnow().isoformat()
            })

    return evidence
