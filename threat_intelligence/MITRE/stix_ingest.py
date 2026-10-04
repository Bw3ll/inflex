import requests

MITRE_ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def load_attack_stix():
    resp = requests.get(MITRE_ENTERPRISE_STIX_URL, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    return [
        obj for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
    ]
