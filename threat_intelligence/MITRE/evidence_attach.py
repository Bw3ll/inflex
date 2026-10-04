import json


def attach_evidence(store_path, evidence):
    with open(store_path, "r") as f:
        store = json.load(f)

    for ev in evidence:
        tid = ev.get("technique")

        if not tid:
            continue

        if tid not in store["techniques"]:
            # skip techniques not in MITRE dataset
            continue

        # Ensure evidence structure exists
        technique = store["techniques"][tid]
        ev_store = technique.setdefault("evidence", {})
        src = ev["source"]

        # Append safely
        ev_store.setdefault(src, []).append(ev)

    with open(store_path, "w") as f:
        json.dump(store, f, indent=2)
