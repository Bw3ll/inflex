# # 1. Update MITRE ATT&CK store
# python mitre_updator.py
#
# # 2. Analyze a binary with CAPA
# python run_capa.py "C:\Users\lcbba\OneDrive\Desktop\labs\labs\Lab 4\lab4-program4\lab4-program4.exe"


import json
import subprocess
# import sys

from threat_intelligence.MITRE.capa_ingest import ingest_capa
from threat_intelligence.MITRE.evidence_attach import attach_evidence

# from capa_ingest import ingest_capa
# from evidence_attach import attach_evidence

CAPA_BIN = r"C:\Users\lcbba\Downloads\bio_correlation_test\MITRE\capa.exe"
CAPA_RULES_PATH = r"C:\Users\lcbba\Downloads\bio_correlation_test\MITRE\capa-rules-9.3.1"
STORE_PATH = "threat_intelligence\\MITRE\\mitre_store1.json"


def run(sample_path):
    result = subprocess.run(
        [
            CAPA_BIN,
            sample_path,
            "--json",
            "--quiet",
            "-r", CAPA_RULES_PATH
        ],
        text=True,
        capture_output=True
    )

    if result.returncode not in (0, 9, 10):
        # Only fail for unknown codes
        print(result.stderr)
        raise RuntimeError(f"capa failed with code {result.returncode}")

    # capa returns 9 or 10 for "no rules matched" or unsupported file
    if result.returncode in (9, 10):
        print("[!] CAPA returned no matches or unsupported file type.")
        return

    # clean JSON extraction
    raw = result.stdout
    start = raw.find("{")
    end = raw.rfind("}") + 1
    clean = raw[start:end]

    capa_json = json.loads(clean)
    evidence = ingest_capa(capa_json)
    attach_evidence(STORE_PATH, evidence)

    print(evidence)

    print(f"[+] CAPA evidence attached ({len(evidence)} techniques)")

    return evidence


if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     print("Usage: python run_capa.py <sample>")
    #     sys.exit(1)

    # run(sys.argv[1])
    # run(r"C:\Users\lcbba\OneDrive\Desktop\labs\labs\Lab 4\lab4-program4\lab4-program4.exe")
    run(r"C:\Users\lcbba\OneDrive\Desktop\labs\labs\Lab 9\FTP Utility\KMFtp.exe")
