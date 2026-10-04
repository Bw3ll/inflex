import os
import subprocess
# import shutil
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

YARA_EXE = os.path.join(BASE_DIR, "yara64.exe")
YARAC_EXE = os.path.join(BASE_DIR, "yarac64.exe")

RULE_BASE = os.path.join(BASE_DIR, "yara_rules")

REPOS = {
    "yara-rules": "https://github.com/Yara-Rules/rules.git",
    "elastic": "https://github.com/elastic/protections-artifacts.git"
}


def collect_rule_dirs():
    """
    Return top-level rule directories instead of individual files
    to avoid Windows command length limits.
    """
    dirs = []
    for name in os.listdir(RULE_BASE):
        path = os.path.join(RULE_BASE, name)
        if os.path.isdir(path):
            dirs.append(path)
    return dirs


def ensure_yara_present():
    if not os.path.exists(YARA_EXE):
        raise RuntimeError("yara64.exe not found in MITRE directory")
    if not os.path.exists(YARAC_EXE):
        raise RuntimeError("yarac64.exe not found in MITRE directory")


def git_sync(repo_url, dest):
    try:
        if not os.path.exists(dest):
            print(f"[+] Cloning {repo_url}")
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, dest],
                check=True,
                timeout=120
            )
        else:
            print(f"[+] Updating {dest}")
            subprocess.run(
                ["git", "-C", dest, "pull"],
                check=True,
                timeout=120
            )
    except Exception as e:
        print(f"[!] YARA rule update failed, using cached rules: {e}")


def update_rules():
    # ensure_yara_present()
    os.makedirs(RULE_BASE, exist_ok=True)

    for name, repo in REPOS.items():
        dest = os.path.join(RULE_BASE, name)
        git_sync(repo, dest)


def collect_rule_files():
    rule_files = []
    for root, _, files in os.walk(RULE_BASE):
        for f in files:
            if f.endswith(".yar") or f.endswith(".yara"):
                rule_files.append(os.path.join(root, f))
    return rule_files


def compile_rules(rule_dirs):
    """
    Incrementally compile YARA rules, skipping invalid ones.
    Produces a known-good compiled.yarc.
    """
    compiled = os.path.join(RULE_BASE, "compiled.yarc")
    good_rules = []

    print("[*] Validating YARA rules...")

    for rule_dir in rule_dirs:
        for root, _, files in os.walk(rule_dir):
            for f in files:
                if not f.endswith((".yar", ".yara")):
                    continue

                rule_path = os.path.join(root, f)

                cmd = [
                    YARAC_EXE,
                    "-w",
                    rule_path,
                    compiled
                ]

                try:
                    subprocess.run(
                        cmd,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    good_rules.append(rule_path)
                except subprocess.CalledProcessError:
                    # Intentionally skip bad rules
                    continue

    if not good_rules:
        raise RuntimeError("No valid YARA rules compiled")

    print(f"[+] Compiled {len(good_rules)} valid YARA rules")
    return compiled


def run_yara(sample_path):
    """
    Runs YARA rules against a sample using compiled rule directories
    (Windows-safe).
    """
    ensure_yara_present()

    update_rules()

    rule_dirs = collect_rule_dirs()
    if not rule_dirs:
        print("[!] No YARA rules available, skipping YARA scan")
        return []

    if not os.path.exists(sample_path):
        raise FileNotFoundError(sample_path)

    rule_dirs = collect_rule_dirs()
    if not rule_dirs:
        return []

    compiled_rules = compile_rules(rule_dirs)

    if not os.path.exists(compiled_rules):
        print("[!] No compiled YARA rules available")
        return []

    cmd = [
        YARA_EXE,
        "-w",
        compiled_rules,
        sample_path
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="ignore"
    )

    results = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue

        rule, target = line.split(" ", 1)

        results.append({
            "engine": "yara",
            "rule": rule.strip(),
            "target": os.path.basename(target.strip()),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    return results
