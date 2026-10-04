def normalize_technique(obj):
    refs = obj.get("external_references", [])
    mitre_id = None

    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            mitre_id = ref.get("external_id")
            break

    if not mitre_id:
        return None

    return {
        "id": mitre_id,
        "name": obj.get("name"),
        "tactics": [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ],
        "platforms": obj.get("x_mitre_platforms", []),
        "data_sources": obj.get("x_mitre_data_sources", []),
        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        "created": obj.get("created"),
        "modified": obj.get("modified")  # ← NEW
    }

