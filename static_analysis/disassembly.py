# TODO: This will take each file type and output the user written disassembly for later processing and analysis

# TODO: This is currently a standalone file for PE files and needs to be built out and pipelined
# TODO: It is also setup to run in WSL and not native linux and needs to be converted

# For set up:
#   1. wsl -d Ubuntu
#   2. sudo apt update && sudo apt install radare2 -y


import os
import sys
import shutil
import subprocess
import json
import hashlib
import re

# Adjust this if your distro name is different
WSL_DISTRO = "Ubuntu"

HEX_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')


def to_wsl_path(win_path: str) -> str:
    drive, rest = os.path.splitdrive(win_path)
    drive = drive.rstrip(":").lower()
    return f"/mnt/{drive}{rest.replace(os.sep, '/')}"


def file_sha256(path: str) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run_radare2_cmd(binary_path: str) -> str:
    """
    Run radare2 to analyze and list functions (aflj).
    """
    binary = to_wsl_path(binary_path)
    cmd = f"wsl -d {WSL_DISTRO} r2 -A -q -c 'e scr.pager=false; aflj; q' '{binary}'"
    output = subprocess.check_output(cmd, shell=True, encoding="utf-8")
    functions = json.loads(output)
    return functions


def normalize_op_str(op):
    """
    Normalizes an r2 op/disasm dict by replacing immediates with CONST to reduce noise.
    """
    disasm = op.get("disasm") or op.get("opcode") or ""
    # strip immediates and numbers
    norm = HEX_RE.sub("CONST", disasm)
    norm = norm.replace(",", " ").strip()
    return norm.lower()


def run_radare2_pdfj(binary_path: str, addr: int):
    """Disassemble one function at addr, assuming analysis already done in -A run."""
    binary = to_wsl_path(binary_path)
    cmd = f"wsl -d {WSL_DISTRO} r2 -A -q -c 'e scr.pager=false; pdfj @ {addr}; q' '{binary}'"
    output = subprocess.check_output(cmd, shell=True, encoding="utf-8")
    return json.loads(output)


def extract_function_hashes(binary_path: str, out_json: str = None):
    print(f"[+] Running radare2 analysis on: {binary_path}")

    # Step 1: run analysis + aflj
    aflj_out = run_radare2_cmd(binary_path)

    # Filtering rules
    SKIP_PREFIXES = ("sym._", "sym.__mingw", "sym.__")
    MIN_FUNC_SIZE = 30

    results = []
    for f in aflj_out:
        addr = f.get("offset")
        name = f.get("name") or f.get("demname") or f"func_{addr:x}"
        size = f.get("size", 0)

        # Apply filters
        if name.startswith(SKIP_PREFIXES):
            continue
        if size < MIN_FUNC_SIZE:
            continue

        # Step 2: disassemble this function only
        try:
            fj = run_radare2_pdfj(binary_path, addr)
            ops = fj.get("ops") or []
        except Exception as e:
            print(f"[-] Failed to disassemble {name} @ {hex(addr)}: {e}")
            continue

        if not ops:
            continue

        normalized_ops = [normalize_op_str(op) for op in ops]
        normalized_ops = [ln for ln in normalized_ops if ln.strip()]
        opcode_blob = "\n".join(normalized_ops)
        func_hash = hashlib.sha256(opcode_blob.encode("utf-8")).hexdigest()

        results.append({
            "name": name,
            "offset": hex(addr),
            "size": size,
            "func_hash": func_hash,
            "mnemonics": normalized_ops,
        })

    # Output JSON
    if not out_json:
        base = os.path.basename(binary_path)
        out_json = f"{base}_functions.json"

    filehash = file_sha256(binary_path)

    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "binary": os.path.abspath(binary_path),
                "sha256": filehash,
                "functions": results,
            },
            fh,
            indent=2,
        )

    print(
        f"[+] Wrote filtered function hashes to: {out_json} "
        f"(functions: {len(results)}, sha256: {filehash})"
    )
    return out_json


def compare_binaries(file1: str, file2: str, out_json: str = None):
    """
    Compare two JSON outputs of extract_function_hashes().
    Returns similarity metrics and shared function hashes.
    Optionally writes results to a JSON file.
    """

    with open(file1, "r", encoding="utf-8") as f1:
        data1 = json.load(f1)
    with open(file2, "r", encoding="utf-8") as f2:
        data2 = json.load(f2)

    funcs1 = {f["func_hash"]: f for f in data1["functions"]}
    funcs2 = {f["func_hash"]: f for f in data2["functions"]}

    set1, set2 = set(funcs1.keys()), set(funcs2.keys())
    intersection = set1 & set2
    union = set1 | set2

    jaccard = len(intersection) / len(union) if union else 0
    overlap1 = len(intersection) / len(set1) if set1 else 0
    overlap2 = len(intersection) / len(set2) if set2 else 0

    result = {
        "binary1": data1["binary"],
        "sha256_file1": data1.get("sha256"),
        "binary2": data2["binary"],
        "sha256_file2": data2.get("sha256"),
        "functions_in_file1": len(set1),
        "functions_in_file2": len(set2),
        "shared_functions": len(intersection),
        "jaccard_index": jaccard,
        "overlap_file1": overlap1,
        "overlap_file2": overlap2,
        "shared_function_details": [
            {
                "func_hash": h,
                "file1_name": funcs1[h]["name"],
                "file2_name": funcs2[h]["name"]
            }
            for h in intersection
        ],
    }

    if out_json:
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[+] Wrote comparison results to: {out_json}")

    print("[*] Comparison summary:")
    print(f"  File 1: {os.path.basename(file1)}")
    print(f"    Path: {result['binary1']}")
    print(f"    SHA256: {result['sha256_file1']}")
    print(f"    Functions: {result['functions_in_file1']}")
    print(f"  File 2: {os.path.basename(file2)}")
    print(f"    Path: {result['binary2']}")
    print(f"    SHA256: {result['sha256_file2']}")
    print(f"    Functions: {result['functions_in_file2']}")
    print(f"  Shared functions: {result['shared_functions']}")
    print(f"  Jaccard index: {result['jaccard_index']:.2f}")
    print(f"  Overlap wrt file1: {result['overlap_file1']:.2f}")
    print(f"  Overlap wrt file2: {result['overlap_file2']:.2f}")

    return result


if __name__ == "__main__":
    binary = r""
    print("Extracting functions from:", binary)
    out = extract_function_hashes(binary)
    print("Wrote:", out)

    file1 = ""
    file2 = ""
    result = compare_binaries(file1, file2, "")

