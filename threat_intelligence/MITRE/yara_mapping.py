def extract_attack_ids(yara_hit):
    meta = yara_hit.get("meta", {})
    attack = set()

    for key in ("mitre", "attack", "attack_technique", "attack_id"):
        val = meta.get(key)
        if isinstance(val, str):
            attack.add(val)
        elif isinstance(val, list):
            attack.update(val)

    return list(attack)
