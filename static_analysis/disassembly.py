# TODO: This will take each file type and output the user written disassembly for later processing and analysis

# TODO: This is currently a standalone file for PE files and needs to be built out and pipelined
# TODO: It is also setup to run in WSL and not native linux and needs to be converted

# For set up:
#   1. wsl -d Ubuntu
#   2. sudo apt update && sudo apt install radare2 -y


import os
import sys
import subprocess
import json
import hashlib
import re
from pathlib import Path

# Adjust this if your distro name is different
WSL_DISTRO = "Ubuntu"

HEX_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')


def to_wsl_path(win_path: str) -> str:
    drive, rest = os.path.splitdrive(win_path)
    drive = drive.rstrip(":").lower()
    return f"/mnt/{drive}{rest.replace(os.sep, '/')}"


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


def extract_function_hashes(binary_path: str):
    """
    Extract function hashes from a binary.
    Returns a dictionary with disassembly data to be added to existing JSON.
    """
    print(f"[+] Running radare2 analysis on: {binary_path}")

    # Step 1: run analysis + aflj
    try:
        aflj_out = run_radare2_cmd(binary_path)
    except Exception as e:
        print(f"[-] Failed to run radare2 analysis: {e}")
        return None

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

    print(f"[+] Extracted {len(results)} functions")

    return {
        "functions": results,
        "function_count": len(results),
        "similar_binaries": []
    }


def calculate_similarity(funcs1: list, funcs2: list) -> float:
    """
    Calculate Jaccard similarity between two lists of function hashes.
    """
    set1 = {f["func_hash"] for f in funcs1}
    set2 = {f["func_hash"] for f in funcs2}

    intersection = set1 & set2
    union = set1 | set2

    if not union:
        return 0.0

    return len(intersection) / len(union)


def compare_with_existing(current_json_path: Path, current_sha256: str, results_dir: Path, threshold: float = 0.6):
    """
    Compare current file with all existing files in results directory.
    Update both files if similarity exceeds threshold.

    Args:
        current_json_path: Path to the current file's JSON
        current_sha256: SHA256 hash of current binary
        results_dir: Directory containing all result JSONs
        threshold: Similarity threshold (default 0.6 = 60%)

    Returns:
        List of similar binaries found
    """

    # TODO: Make this more efficient as currently it is very slow having to check each funciton hash with all others individually

    print(f"[+] Comparing with existing files in {results_dir}...")

    # Load current file data
    with open(current_json_path, "r", encoding="utf-8") as f:
        current_data = json.load(f)

    # Validate current file has disassembly data
    if "disassembly" not in current_data or "functions" not in current_data["disassembly"]:
        print(f"[-] Error: Current file missing disassembly data")
        return []

    current_functions = current_data["disassembly"]["functions"]
    similar_found = []

    # Iterate through all JSON files in results directory
    for other_file in results_dir.glob("*.json"):
        # Skip comparing with itself
        if other_file.name == current_json_path.name:
            continue

        try:
            with open(other_file, "r", encoding="utf-8") as f:
                other_data = json.load(f)

            # Skip files without disassembly data
            if "disassembly" not in other_data or "functions" not in other_data["disassembly"]:
                continue

            # Get the SHA256 from the filename or hash field
            other_sha256 = other_data.get("hash", {}).get("sha256") or other_file.stem
            other_functions = other_data["disassembly"]["functions"]

            # Calculate similarity
            similarity = calculate_similarity(current_functions, other_functions)

            print(f"  [{other_file.name}] Similarity: {similarity:.2%}")

            # If similarity exceeds threshold, update both files
            if similarity >= threshold:
                similar_info = {
                    "sha256": other_sha256,
                    "similarity": round(similarity, 4),
                    "file_path": other_data.get("file_info", {}).get("path", "unknown")
                }
                similar_found.append(similar_info)

                # Update the other file to include reference to current file
                other_similar = other_data["disassembly"].get("similar_binaries", [])

                # Check if current file is already in the list
                if not any(s["sha256"] == current_sha256 for s in other_similar):
                    other_similar.append({
                        "sha256": current_sha256,
                        "similarity": round(similarity, 4),
                        "file_path": current_data.get("file_info", {}).get("path", "unknown")
                    })
                    other_data["disassembly"]["similar_binaries"] = other_similar

                    # Write back updated data
                    with open(other_file, "w", encoding="utf-8") as f:
                        json.dump(other_data, f, indent=2)

                    print(f"  [✓] Updated {other_file.name} with similarity reference")

        except Exception as e:
            print(f"  [-] Error comparing with {other_file.name}: {e}")
            continue

    # Update current file with similar binaries
    if similar_found:
        current_data["disassembly"]["similar_binaries"] = similar_found
        with open(current_json_path, "w", encoding="utf-8") as f:
            json.dump(current_data, f, indent=2)

        print(f"[+] Found {len(similar_found)} similar binaries (>{threshold:.0%} similarity)")
    else:
        print(f"[*] No similar binaries found above {threshold:.0%} threshold")

    return similar_found


def process_disassembly(binary_path: str, results_dir: str = "results"):
    """
    Extract disassembly data from binary and return it as a dictionary.
    Does not modify files directly - returns data for multiprocessing pipeline.

    Args:
        binary_path: Path to the binary file
        results_dir: Directory containing all result JSONs (for similarity comparison)

    Returns:
        Dictionary with disassembly data, or None on failure
    """
    binary_path = Path(binary_path)
    results_dir = Path(results_dir)

    # Verify binary exists
    if not binary_path.exists():
        print(f"[-] Binary not found: {binary_path}")
        return None

    # Extract function hashes
    print(f"[+] Extracting disassembly data...")
    disassembly_data = extract_function_hashes(str(binary_path))

    if disassembly_data is None:
        print(f"[-] Failed to extract disassembly data")
        return None

    print(f"[+] Disassembly extraction complete")
    return disassembly_data


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        results_dir = sys.argv[2] if len(sys.argv) > 2 else "results"
    else:
        # Default test
        binary_path = r"C:\Users\lcbba\OneDrive\Desktop\labs\labs\Activity 4\crackme\crackme\crackme0x02.exe"
        results_dir = r"C:\Users\lcbba\OneDrive\Desktop\INFLEX\results"

    print("=" * 60)
    print("Binary Disassembly Analysis")
    print("=" * 60)

    result = process_disassembly(binary_path, results_dir)

    if result:
        print("\n" + "=" * 60)
        print("Processing Complete!")
        print("=" * 60)
        print(f"Functions extracted: {result['function_count']}")
        print(f"\nDisassembly data:")
        print(json.dumps(result, indent=2))
    else:
        print("[-] Failed to process disassembly")
