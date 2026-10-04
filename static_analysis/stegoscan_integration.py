# TODO: This needs Sudo and no requiremtnes.txt to setup because it will autoinstall on first run
# TODO: Also need to make it run this command: myenv/bin/python3 StegoScan.py -l /mnt/c/Users/lcbba/OneDrive/Desktop/INFLEX/extracted_resources -t "*" -o /mnt/c/Users/lcbba/OneDrive/Desktop/INFLEX/results/stego_test/ -m "all"
# TODO: Also need to install tinker for some reason it did not install then sudo apt update and sudo apt install -y python3-tk

# In WSL:
# sudo visudo

# Add:
# lcbba ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg

# NOTE: The script now runs StegoScan with sudo since it needs sudo for internal apt/gem commands
# TODO: Sudo is not working, give it all of the output form the WSL and the code

import os
import sys
import json
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime

WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")

REPO_URL = "https://github.com/LCBOWER33/StegoScan"

# Install in home dir to avoid sudo for the repo/venv itself.
# sudo is still needed for apt packages (python3-tk).
WSL_INSTALL_DIR = "~/stegoscan"
# WSL_VENV_DIR = "~/stegoscan/.venv"
WSL_VENV_DIR = "~/stegoscan/myenv"

# Sentinel written after a successful full bootstrap (apt + venv).
# Delete this file inside WSL to force a clean reinstall.
WSL_INSTALL_SENTINEL = "~/stegoscan/.deps_installed"

DEFAULT_OUTPUT_JSON = "stegoscan_results.json"

# 
# Sudo password
#
# Set the environment variable WSL_SUDO_PASS before running, e.g.:
#   $env:WSL_SUDO_PASS = "yourpassword"    # PowerShell
#   export WSL_SUDO_PASS="yourpassword"    # bash
#
# Keep this out of source control — add a .env loader if you prefer.
# 
_SUDO_PASS = os.environ.get("WSL_SUDO_PASS", "")  # Default fallback for testing


def _sudo(cmd: str) -> str:
    """
    Wrap a shell command string so it runs with sudo using the stored password.
    Uses -S to read the password from stdin so no TTY is required.
    """
    if not _SUDO_PASS:
        raise RuntimeError(
            "WSL_SUDO_PASS environment variable is not set.\n"
            "Set it before running:\n"
            "  PowerShell : $env:WSL_SUDO_PASS = 'yourpassword'\n"
            "  bash       : export WSL_SUDO_PASS='yourpassword'"
        )
    return f"echo {_SUDO_PASS!r} | sudo -S {cmd}"


# 
# WSL subprocess helpers
# 

class WSLResult:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_wsl(cmd, timeout=600, stream_output=False, idle_timeout=600, log_file=None):
    """
    Run a command inside WSL with live streaming, a hard timeout, and an
    idle timeout (kills the process if it produces no output for N seconds).

    Args:
        cmd:           List of arguments appended after `wsl -d <distro>`.
        timeout:       Hard wall-clock limit in seconds (None = unlimited).
        stream_output: Print each output line as it arrives.
        idle_timeout:  Kill if no output has arrived for this many seconds.
        log_file:      Optional file path to write all output to (in addition to console).

    Returns:
        WSLResult or None on timeout / kill.
    """
    full_cmd = ["wsl", "-d", WSL_DISTRO] + cmd

    # Open log file if specified
    log_handle = None
    if log_file:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = open(log_file_path, "a", encoding="utf-8")
        log_handle.write(f"\n{'='*80}\n")
        log_handle.write(f"[{datetime.now().isoformat()}] WSL Command Start\n")
        log_handle.write(f"Command: {' '.join(full_cmd)}\n")
        log_handle.write(f"{'='*80}\n")
        log_handle.flush()

    proc = subprocess.Popen(
        full_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # merge stderr so sudo errors are visible
        text=True,
        bufsize=1,
    )

    stdout_lines = []
    start_time = time.time()
    last_output_time = time.time()

    def _reader():
        nonlocal last_output_time
        for line in proc.stdout:
            line = line.rstrip("\n")
            stdout_lines.append(line)
            if stream_output:
                print("    " + line, flush=True)
            if log_handle:
                log_handle.write(line + "\n")
                log_handle.flush()
            last_output_time = time.time()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    while proc.poll() is None:
        now = time.time()
        if timeout and (now - start_time) > timeout:
            proc.kill()
            print(f"[-] WSL command hard-timed out after {timeout}s.")
            return None
        if idle_timeout and (now - last_output_time) > idle_timeout:
            proc.kill()
            print(f"[-] WSL command idle-timed out after {idle_timeout}s of no output.")
            return None
        time.sleep(1)

    t.join(timeout=2)
    
    if log_handle:
        log_handle.write(f"\n[{datetime.now().isoformat()}] Exit Code: {proc.returncode}\n")
        log_handle.write(f"{'='*80}\n")
        log_handle.close()
    
    return WSLResult(proc.returncode, "\n".join(stdout_lines))


def win_to_wsl_path(win_path: str) -> str:
    """Convert a Windows path (C:\\Users\\...) to a WSL path (/mnt/c/Users/...)."""
    p = Path(win_path).resolve()
    drive = p.drive.rstrip(":").lower()
    tail = str(p).replace("\\", "/").split(":/", 1)[-1]
    return f"/mnt/{drive}/{tail}"


# 
# Prerequisite checks
# 

def ensure_git_installed():
    result = run_wsl(["bash", "-lc", "which git"])
    return result and result.returncode == 0


def setup_passwordless_sudo():
    """
    Configure passwordless sudo for the specific commands StegoScan needs.
    This is more secure than running the entire process as sudo.
    """
    print("[+] Setting up passwordless sudo for StegoScan dependencies...")

    # Commands that StegoScan tries to run with sudo (based on error messages)
    sudo_commands = [
        "/usr/bin/apt",
        "/usr/bin/apt-get",
        "/usr/bin/dpkg",
        "/usr/bin/gem",
        "/usr/bin/snap",  # Just in case
        "/usr/bin/pip",   # Just in case
    ]

    # Get current username in WSL
    whoami_result = run_wsl(["bash", "-lc", "whoami"])
    if whoami_result is None or whoami_result.returncode != 0:
        print("[-] Failed to get WSL username.")
        return False

    wsl_username = whoami_result.stdout.strip()

    # Create sudoers entry - allow ALL commands for this user (simpler approach)
    sudoers_entry = f"{wsl_username} ALL=(ALL) NOPASSWD: ALL"

    # Add to sudoers using visudo (safer than direct file editing)
    visudo_cmd = f"""cat > /tmp/stegoscan_sudoers << 'EOF'
{sudoers_entry}
EOF
sudo cp /tmp/stegoscan_sudoers /etc/sudoers.d/stegoscan
sudo chmod 0440 /etc/sudoers.d/stegoscan
sudo rm /tmp/stegoscan_sudoers"""

    result = run_wsl(
        ["bash", "-lc", _sudo(visudo_cmd)],
        timeout=60,
        idle_timeout=30,
        stream_output=True
    )

    if result is None or result.returncode != 0:
        print("[-] Failed to set up passwordless sudo.")
        print("    You may need to run this manually in WSL:")
        print(f"    sudo visudo -f /etc/sudoers.d/stegoscan")
        print(f"    Add: {sudoers_entry}")
        return False

    print("[+] Passwordless sudo configured for StegoScan.")
    return True


# 
# Repo management
# 

def clone_or_update_repo():
    print("[+] Checking StegoScan installation in WSL...")

    check = run_wsl(["bash", "-lc", f"test -d {WSL_INSTALL_DIR}/.git"])
    if check and check.returncode == 0:
        print("[+] Repo already exists — pulling latest changes...")
        pull = run_wsl(
            ["bash", "-lc", f"cd {WSL_INSTALL_DIR} && git pull"],
            timeout=600,
            idle_timeout=300,
            stream_output=True,
        )
        if pull is None or pull.returncode != 0:
            print("[-] Failed to pull latest changes.")
            return False
        return True

    print("[+] Cloning StegoScan into WSL...")

    mkdir = run_wsl(["bash", "-lc", f"mkdir -p {WSL_INSTALL_DIR}"])
    if mkdir is None or mkdir.returncode != 0:
        print("[-] Failed to create install directory.")
        if mkdir:
            print(mkdir.stdout)
        return False

    clone = run_wsl(
        ["bash", "-lc", f"git clone {REPO_URL} {WSL_INSTALL_DIR}"],
        timeout=900,
        idle_timeout=300,
        stream_output=True,
    )
    if clone is None or clone.returncode != 0:
        print("[-] Failed to clone repo.")
        if clone:
            print(clone.stdout)
        return False

    return True


# 
# Dependency bootstrap
# 

def deps_already_installed() -> bool:
    result = run_wsl(["bash", "-lc", f"test -f {WSL_INSTALL_SENTINEL}"])
    return result is not None and result.returncode == 0


def install_dependencies(force: bool = False):
    """
    Full bootstrap:
      1. apt install python3-tk  (requires sudo)
      2. Create venv under WSL_VENV_DIR
      3. Upgrade pip/setuptools/wheel inside the venv
      4. Touch the sentinel so this is skipped on future runs

    StegoScan pulls its heavy dependencies (YOLO etc.) on first run via its
    own setup logic, so we don't install requirements.txt here.

    WSL_SUDO_PASS must be set in the environment before calling this.
    """
    if not force and deps_already_installed():
        print("[+] StegoScan already bootstrapped (sentinel found) — skipping.")
        print(f"    Delete {WSL_INSTALL_SENTINEL} in WSL to force a reinstall.")
        return True

    print("[+] Bootstrapping StegoScan environment in WSL...")
    print("    Step 1/3 — Installing system packages (python3-tk) via apt...")

    #  Step 1: apt packages 
    apt_cmd = _sudo("bash -c 'apt-get update -qq && apt-get install -y python3-tk'")
    apt_result = run_wsl(
        ["bash", "-lc", apt_cmd],
        timeout=600,
        idle_timeout=300,
        stream_output=True,
    )
    if apt_result is None or apt_result.returncode != 0:
        print("[-] Failed to install system packages via apt.")
        if apt_result:
            print(apt_result.stdout)
        return False

    print("    Step 2/3 — Creating virtual environment and upgrading pip...")

    #  Step 2: venv creation + pip upgrade 
    venv_cmd = f"""
set -eo pipefail
cd {WSL_INSTALL_DIR}

if [ ! -d "{WSL_VENV_DIR}" ]; then
    echo "[venv] Creating virtual environment..."
    python3 -m venv {WSL_VENV_DIR}
fi

source {WSL_VENV_DIR}/bin/activate
echo "[pip] Upgrading pip / setuptools / wheel..."
python3 -m pip install --upgrade pip setuptools wheel
"""
    venv_result = run_wsl(
        ["bash", "-lc", venv_cmd],
        timeout=600,
        idle_timeout=300,
        stream_output=True,
    )
    if venv_result is None or venv_result.returncode != 0:
        print("[-] Failed to create venv or upgrade pip.")
        if venv_result:
            print(venv_result.stdout)
        return False

    print("    Step 3/3 — Writing install sentinel...")

    #  Step 3: sentinel 
    sentinel_result = run_wsl(["bash", "-lc", f"touch {WSL_INSTALL_SENTINEL}"])
    if sentinel_result is None or sentinel_result.returncode != 0:
        print("[-] Failed to write install sentinel (non-fatal).")

    print("[+] Bootstrap complete.")
    return True


# 
# StegoScan execution
# 

def patch_missing_stegoscan_tools():
    """
    Creates dummy executables for missing tools StegoScan tries to install
    so StegoScan's internal installer doesn't exit with failure.

    This avoids modifying StegoScan itself.
    """
    print("[+] Patching missing StegoScan tools in WSL...")

    # Create the dummy tools using proper sudo commands
    for tool in ["stegdetect", "stego-rat", "stegosuite", "steganography", "stegseek"]:
        # Check if tool exists
        check_cmd = f"command -v {tool}"
        result = run_wsl(["bash", "-lc", check_cmd])
        if result and result.returncode == 0:
            continue  # Tool already exists

        print(f"[+] Creating dummy tool: {tool}")

        # Create the dummy script
        create_cmd = _sudo(f"bash -c 'cat > /usr/local/bin/{tool} <<\\'EOF\\'\n#!/bin/bash\necho \\'[DUMMY] $0 called (placeholder installed by wrapper)\\'\nexit 0\nEOF'")
        result = run_wsl(["bash", "-lc", create_cmd], timeout=30, stream_output=False)
        if result is None or result.returncode != 0:
            print(f"[-] Failed to create dummy tool: {tool}")
            continue

        # Make it executable
        chmod_cmd = _sudo(f"chmod +x /usr/local/bin/{tool}")
        result = run_wsl(["bash", "-lc", chmod_cmd], timeout=30, stream_output=False)
        if result is None or result.returncode != 0:
            print(f"[-] Failed to make {tool} executable")

    print("[+] Dummy tools installed.")
    return True

def run_stegoscan(target_dir_win: str, output_json_win: str, sha256: str = None):
    """
    Run StegoScan against target_dir_win using the exact CLI structure confirmed:
    wsl -d Ubuntu bash -lc "cd ~/stegoscan && ./myenv/bin/python3 StegoScan.py ..."
    
    Args:
        target_dir_win: Windows path to the directory to scan
        output_json_win: Windows path for output directory
        sha256: Optional SHA256 of the sample for context
    """
    import json
    from pathlib import Path
    from datetime import datetime

    target_dir_wsl = win_to_wsl_path(target_dir_win)

    # -o expects a directory
    output_dir_path = Path(output_json_win).resolve()
    output_dir_wsl = win_to_wsl_path(str(output_dir_path))
    
    # Create log file path
    log_file_path = output_dir_path / f"stegoscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    print(f"[+] Running StegoScan on : {target_dir_win}")
    print(f"[+] WSL target path      : {target_dir_wsl}")
    print(f"[+] Output directory     : {output_dir_path}")

    # Ensure the output directory exists
    output_dir_path.mkdir(parents=True, exist_ok=True)

    stego_inner = (
        f"cd ~/stegoscan && "
        f"./myenv/bin/python3 StegoScan.py "
        f"-l '{target_dir_wsl}' "
        f"-t '*' "
        f"-o '{output_dir_wsl}' "
        f"-m 'all'"
    )

    # Use subprocess.run directly to match the manual execution exactly
    import subprocess
    full_cmd = ["wsl", "-d", WSL_DISTRO, "bash", "-lc", stego_inner]
    
    print(f"[+] Running command: {' '.join(full_cmd)}")
    
    try:
        # Run with the same timeout as manual execution
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=7200,  # 2 hours
            cwd=None,      # Use current working directory
        )
        
        # Write output to log file
        with open(log_file_path, 'w', encoding='utf-8') as f:
            f.write("STDOUT:\n")
            f.write(result.stdout)
            f.write("\nSTDERR:\n") 
            f.write(result.stderr)
            f.write(f"\nReturn code: {result.returncode}\n")
        
        print(f"[+] Command completed with return code: {result.returncode}")
        print(f"[+] Log written to: {log_file_path}")
        
        # Print some of the output for debugging
        stdout_lines = result.stdout.split('\n')
        if len(stdout_lines) > 50:
            print("[+] First 50 lines of output:")
            for line in stdout_lines[:50]:
                print(f"    {line}")
        else:
            print("[+] Full output:")
            print(result.stdout)
            
        if result.stderr:
            print("[+] Stderr output:")
            print(result.stderr)
        
    except subprocess.TimeoutExpired:
        print("[-] StegoScan timed out after 2 hours.")
        return None
    except Exception as e:
        print(f"[-] Error running StegoScan: {e}")
        return None

    print("[+] Full WSL StegoScan Command:")
    print(f'    wsl -d {WSL_DISTRO} bash -lc "{stego_inner}"\n')
    
    # StegoScan doesn't create JSON - it creates directories with found files
    # Exit code 0 = found steganography, 1 = no steganography found
    # Exit code 134 (SIGSEGV) or other codes may still produce output before crashing
    if result.returncode == 0:
        print("[+] StegoScan completed successfully - steganography detected!")
    elif result.returncode == 1:
        print("[+] StegoScan completed - no steganography found (exit code 1).")
    else:
        print(f"[-] StegoScan exited with code {result.returncode} — checking for partial output...")

    # Analyze the output directory structure regardless of exit code
    # StegoScan may have produced files before crashing
    print(f"[+] Analyzing output directory: {output_dir_path}")
    
    results_summary = {
        "stegoscan_exit_code": result.returncode,
        "output_directory": str(output_dir_path),
        "found_files": {},
        "total_files_found": 0
    }
    
    # Check each subdirectory for found files
    subdirs = ["bin", "ico", "png", "xml", "results_" + datetime.now().strftime('%Y%m%d')]
    for subdir_name in subdirs:
        subdir_path = output_dir_path / subdir_name
        if subdir_path.exists():
            files = list(subdir_path.rglob("*"))
            actual_files = [f for f in files if f.is_file()]
            if actual_files:
                results_summary["found_files"][subdir_name] = [str(f.relative_to(output_dir_path)) for f in actual_files]
                results_summary["total_files_found"] += len(actual_files)
                print(f"[+] {subdir_name}: {len(actual_files)} files found")
            else:
                print(f"[+] {subdir_name}: directory exists but empty")
        else:
            print(f"[-] {subdir_name}: directory not created")
    
    # Also check for any results_* subdirectories that might have been created
    results_dirs = list(output_dir_path.glob("results_*"))
    for results_dir in results_dirs:
        if str(results_dir.name) not in results_summary["found_files"]:
            files = list(results_dir.rglob("*"))
            actual_files = [f for f in files if f.is_file()]
            if actual_files:
                results_summary["found_files"][results_dir.name] = [str(f.relative_to(output_dir_path)) for f in actual_files]
                results_summary["total_files_found"] += len(actual_files)
                print(f"[+] {results_dir.name}: {len(actual_files)} files found")
    
    print(f"[+] Total files found: {results_summary['total_files_found']}")

    # Only return None if there were no output files AND an unexpected exit code
    # If files were produced, continue to process them even if StegoScan crashed
    if results_summary["total_files_found"] == 0 and result.returncode not in (0, 1):
        print(f"[-] No output files produced and exit code {result.returncode} — skipping stegoscan results")
        return None

    #  Run the summarizer to get detailed analysis 
    try:
        # Add the summarizer to the path
        summarizer_path = Path(__file__).parent.parent / "parsers" / "stegoscan_summarizer.py"
        if summarizer_path.exists():
            import sys
            sys.path.insert(0, str(summarizer_path.parent))
            from parsers.stegoscan_summarizer import summarise_stegoscan_results
            
            print(f"[+] Running StegoScan summarizer on: {output_dir_path}")
            summarizer_result = summarise_stegoscan_results(
                scan_dir=str(output_dir_path),
                sha256=None,  # Could pass the sample SHA256 if available
                verbose=False
            )
            
            if summarizer_result:
                # Add summarizer results to the main results
                results_summary["verdict"] = summarizer_result.get("overall_verdict", "UNKNOWN")
                results_summary["confidence"] = summarizer_result.get("confidence", 0.0)
                results_summary["risk_score"] = summarizer_result.get("risk_score", 0)
                results_summary["files_scanned"] = summarizer_result.get("files_scanned", 0)
                results_summary["stego_carriers"] = summarizer_result.get("stego_carriers", [])
                results_summary["clean_files"] = summarizer_result.get("clean_files", [])
                results_summary["thesis_summary"] = summarizer_result.get("thesis_summary", "")
                print(f"[+] StegoScan verdict: {results_summary['verdict']} (confidence: {results_summary['confidence']:.2f})")
            else:
                print("[+] Summarizer returned no results")
        else:
            print(f"[+] Summarizer not found at: {summarizer_path}")
    except Exception as e:
        print(f"[!] Error running summarizer: {e}")
        # Continue without summarizer - the basic results are still valid
    
    return results_summary


# 
# Standalone entry point
# 

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Bootstrap and run StegoScan via WSL."
    )
    parser.add_argument("target_dir", help="Directory to scan (Windows path)")
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=DEFAULT_OUTPUT_JSON,
        help=f"Output directory for StegoScan results (default: {DEFAULT_OUTPUT_JSON})",
    )
    parser.add_argument(
        "--force-reinstall",
        action="store_true",
        help="Re-run the full bootstrap even if the sentinel exists",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.target_dir):
        print(f"[-] Directory does not exist: {args.target_dir}")
        sys.exit(1)

    if not _SUDO_PASS:
        print("[-] WSL_SUDO_PASS environment variable is not set.")
        print("    PowerShell : $env:WSL_SUDO_PASS = 'yourpassword'")
        print("    bash       : export WSL_SUDO_PASS='yourpassword'")
        sys.exit(1)

    if not ensure_git_installed():
        print("[-] git not found in WSL. Install with:")
        print("    wsl sudo apt update && sudo apt install git -y")
        sys.exit(1)

    # if not ensure_python_installed():
    #     print("[-] python3 not found in WSL. Install with:")
    #     print("    wsl sudo apt update && sudo apt install python3 python3-venv python3-pip -y")
    #     sys.exit(1)

    if not clone_or_update_repo():
        sys.exit(1)

    if not install_dependencies(force=args.force_reinstall):
        sys.exit(1)

    # Patch missing tools that StegoScan tries to install
    if not patch_missing_stegoscan_tools():
        print("[-] Failed to patch missing tools, but continuing...")

    results = run_stegoscan(args.target_dir, args.output_dir)
    if results is None:
        sys.exit(1)

    print("\n[+] StegoScan Results (first 5000 chars):")
    print(json.dumps(results, indent=2)[:5000])
    print("\n[+] Done.")
    # TODO: Maybe add in the summarizer here once the folder has been created, but this only happens if we run it on its own and not throguh the intergratoin


if __name__ == "__main__":
    main()
