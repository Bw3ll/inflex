"""
SHAREM Shellcode Analysis Integration Module

This module provides an automated integration of the SHAREM shellcode analysis
framework, handling installation, configuration, and analysis execution.
"""

import os
import sys
import subprocess
import json
import tempfile
import shutil
import re
import hashlib
from pathlib import Path
from typing import Dict, Optional, Union
from static_analysis.disassembly import normalize_op_str
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SharemAnalyzer:
    """
    Wrapper class for SHAREM shellcode analysis framework.
    Handles automatic installation, configuration, and analysis.
    """
    
    def __init__(self, sharem_dir: Optional[str] = None, auto_setup: bool = True):
        """
        Initialize the SHAREM analyzer.
        
        Args:
            sharem_dir: Directory where SHAREM is/will be installed
            auto_setup: Automatically setup SHAREM if not already installed
        """
        self.sharem_dir = Path(sharem_dir) if sharem_dir else Path.home() / ".sharem"
        self.sharem_repo = self.sharem_dir / "sharem"
        self.sharem_cli = self.sharem_repo / "sharem_cli"
        self.is_installed = self._check_installation()
        
        if not self.is_installed and auto_setup:
            logger.info("SHAREM not found. Initiating automatic setup...")
            self.setup()
    
    def _check_installation(self) -> bool:
        """Check if SHAREM is already installed."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list"],
                capture_output=True,
                text=True,
                check=True
            )
            return "sharem" in result.stdout.lower()
        except Exception as e:
            logger.warning(f"Error checking SHAREM installation: {e}")
            return False
    
    def setup(self):
        """
        Automatically clone, install, and configure SHAREM.
        """
        try:
            # Create installation directory
            self.sharem_dir.mkdir(parents=True, exist_ok=True)
            
            # Clone the repository if not already present
            if not self.sharem_repo.exists():
                logger.info(f"Cloning SHAREM from GitHub...")
                subprocess.run(
                    ["git", "clone", "-b", "testing", 
                     "https://github.com/Bw3ll/sharem.git",
                     str(self.sharem_repo)],
                    check=True,
                    cwd=str(self.sharem_dir)
                )
            
            # Install SHAREM as a package
            logger.info("Installing SHAREM as a Python package...")
            installer_dir = self.sharem_repo / "installers"
            
            if not installer_dir.exists():
                raise RuntimeError(f"Installers directory not found: {installer_dir}")
            
            if sys.platform == "win32":
                # Windows installation - run the bat file
                bat_file = installer_dir / "windows_installer.bat"
                
                if not bat_file.exists():
                    # Try alternate bat file
                    bat_file = installer_dir / "windows_installer_alternate.bat"
                
                if bat_file.exists():
                    logger.info(f"Running Windows installer: {bat_file}")
                    logger.info("This may take several minutes...")
                    
                    # Run the bat file - it calls setup.py
                    result = subprocess.run(
                        [str(bat_file)],
                        cwd=str(installer_dir),
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    
                    logger.info(f"Installer output: {result.stdout}")
                    if result.stderr:
                        logger.warning(f"Installer warnings/errors: {result.stderr}")
                    
                    if result.returncode != 0:
                        logger.error(f"Installer returned code {result.returncode}")
                        # Try manual installation as fallback
                        logger.info("Attempting manual installation as fallback...")
                        self._manual_install()
                else:
                    logger.warning("Windows installer .bat file not found, attempting manual installation...")
                    self._manual_install()
            else:
                # Linux installation
                sh_file = installer_dir / "linux_installer.sh"
                if sh_file.exists():
                    logger.info(f"Running Linux installer: {sh_file}")
                    # Make executable
                    subprocess.run(["chmod", "+x", str(sh_file)], check=True)
                    subprocess.run(
                        ["sudo", str(sh_file)],
                        check=True,
                        cwd=str(installer_dir)
                    )
                else:
                    logger.warning("Linux installer not found, attempting manual installation...")
                    self._manual_install()
            
            # Verify installation
            self.is_installed = self._check_installation()
            
            if self.is_installed:
                logger.info("✓ SHAREM installed successfully!")
                logger.info("Note: First emulation will harvest/inflate DLLs (5-15 min)")
            else:
                logger.error("✗ SHAREM installation verification failed")
                logger.error("Run 'py -m pip list' to check if 'sharem' is listed")
                raise RuntimeError("SHAREM installation verification failed")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Setup failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during setup: {e}")
            raise
    
    def _manual_install(self):
        """
        Fallback manual installation if bat file fails.
        """
        logger.info("Performing manual installation...")
        
        # Find setup.py
        setup_py = self.sharem_repo / "setup.py"
        
        if not setup_py.exists():
            raise RuntimeError(f"setup.py not found at {setup_py}")
        
        # Install dependencies from requirements.txt if exists
        requirements = self.sharem_repo / "requirements.txt"
        if requirements.exists():
            logger.info("Installing requirements...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
                check=True
            )
        
        # Install SHAREM as editable package
        logger.info("Installing SHAREM package...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", str(self.sharem_repo)],
            check=True,
            cwd=str(self.sharem_repo)
        )
    
    #  Config path 
    # SHAREM's config lives at:
    #   <sharem_dir>/sharem/sharem/sharem/sharem/config.cfg
    # The nested path is intentional — it mirrors SHAREM's package layout.
    @property
    def _config_path(self) -> Path:
        return self.sharem_dir / "sharem" / "sharem" / "sharem" / "sharem" / "config.cfg"

    def _ensure_headless_startup(self) -> bool:
        """Read config.cfg and ensure startup_enabled = True.

        SHAREM headless mode is activated by [SHAREM STARTUP] startup_enabled = True.
        If the value is already True this is a no-op.  If it is False (the default)
        the line is patched in-place and the file is re-written.

        Returns True if the config was already correct, False if it was patched.
        """
        cfg_path = self._config_path
        if not cfg_path.exists():
            raise FileNotFoundError(
                f"SHAREM config not found at {cfg_path}. "
                "Verify the SHAREM installation path."
            )

        with open(cfg_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_startup_section = False
        patched = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("["):
                in_startup_section = stripped.lower() == "[sharem startup]"
            if in_startup_section and stripped.lower().startswith("startup_enabled"):
                key, _, val = stripped.partition("=")
                if val.strip().lower() != "true":
                    logger.info(f"config.cfg: patching startup_enabled = False -> True")
                    line = f"{key.rstrip()} = True\n"
                    patched = True
                else:
                    logger.info("config.cfg: startup_enabled already True — no change needed")
            new_lines.append(line)

        if patched:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            logger.info(f"config.cfg updated: {cfg_path}")

        return not patched   # True = was already correct

    @property
    def _headless_logs_dir(self) -> Path:
        """Fixed path to SHAREM headless output directory.

        In headless mode SHAREM always writes to:
            <sharem_dir>/sharem/sharem/sharem/sharem/logs/default
        """
        return self.sharem_dir / "sharem" / "sharem" / "sharem" / "sharem" / "logs" / "default"

    def _collect_headless_json_reports(self, run_start_time: float) -> Dict:
        """
        Load and merge all JSON files written by SHAREM during this run.
        """
        import time as _time

        logs_dir = self._headless_logs_dir
        if not logs_dir.exists():
            logger.warning(f"SHAREM headless logs dir not found: {logs_dir}")
            return {}

        # Only files touched during this run
        all_json = list(logs_dir.glob("*.json"))
        this_run = [f for f in all_json if f.stat().st_mtime >= run_start_time]

        if not this_run:
            logger.warning(
                f"No new JSON files in {logs_dir} since run started "
                f"(found {len(all_json)} total, 0 from this run)"
            )
            return {}

        logger.info(
            f"Found {len(this_run)} JSON file(s) from this run in {logs_dir}: "
            + ", ".join(f.name for f in sorted(this_run))
        )

        # Load each file
        raw: Dict[str, dict] = {}
        for jf in sorted(this_run):
            try:
                with open(jf, "r", encoding="utf-8", errors="ignore") as f:
                    raw[jf.name] = json.load(f)
                logger.info(f"  Loaded: {jf.name}")
            except Exception as e:
                logger.warning(f"  Failed to load {jf.name}: {e}")

        #  Build unified result from SHAREM JSON schema 
        # jsondefault.json  schema (from observed output):
        #   dateAnalyzed, classification, reason, fileType, bits, entryPoint,
        #   md5, sha256, ssdeep, pushret, callpop, PEB, fstenv, heavensGate,
        #   syscall, strings[], shellcode{rawhex,strlit}, deobfuscation{},
        #   emulation{api_calls[], syscalls_emulation[], dlls[], file_*, web_*,
        #             exe_dll_artifacts[], registry_*, commandLine_*, ...}
        #
        # jsondefaultdisasm.json  schema:
        #   disassembly[]{address, instruction, hex, size, dataType,
        #                  dataAccessed, string, comment, label}

        main   = raw.get("jsondefault.json", {})
        disasm = raw.get("jsondefaultdisasm.json", {})

        #  Basic info 
        basic_info = {
            "md5":          main.get("md5"),
            "sha256":       main.get("sha256"),
            "ssdeep":       main.get("ssdeep"),
            "file_size":    None,   # injected from raw bytes after return
            "entropy":      None,   # injected from raw bytes after return
            "date_analyzed": main.get("dateAnalyzed"),
            "file_type":    main.get("fileType"),
            "bits":         main.get("bits"),
            "entry_point":  main.get("entryPoint"),
            "shellcode_hex": main.get("shellcode", {}).get("rawhex"),
            "shellcode_strlit": main.get("shellcode", {}).get("strlit"),
        }

        #  Classification 
        # cpu_instructions: use instruction count from disassembly JSON
        # (SHAREM does not write the CPU counter to jsondefault.json directly)
        cpu_instructions = len(disasm.get("disassembly", []))

        # Features — derive from string types present and non-empty indicator arrays
        features_detected = []
        string_types = {s.get("type","") for s in main.get("strings", [])}
        if "ascii" in string_types:
            features_detected.append("ASCII strings")
        if "pushString" in string_types:
            features_detected.append("Push stack strings")
        if "unicode" in string_types or "wide" in string_types:
            features_detected.append("Unicode strings")
        if disasm.get("disassembly"):
            features_detected.append("Disassembly")
        feature_map = [
            ("pushret",     "Push/Ret"),
            ("callpop",     "Call/Pop"),
            ("PEB",         "PEB Walking"),
            ("fstenv",      "FSTENV (GetEIP)"),
            ("heavensGate", "Heaven's Gate (WoW64)"),
            ("syscall",     "Windows Syscalls"),
        ]
        for key, label in feature_map:
            if main.get(key):
                features_detected.append(label)

        analysis_metadata = {
            "shellcode_type":         main.get("classification", "unknown"),
            "classification_reason":  main.get("reason", ""),
            "architecture":           f"x86 ({main.get('bits', '?')}-bit)" if main else "unknown",
            "emulation_status":       "completed" if main else "unknown",
            "cpu_instructions":       cpu_instructions,
            "features_detected":      features_detected,
        }

        #  Emulation block 
        emu = main.get("emulation", {})

        # APIs — normalize to the same {address,name,arguments,return_value} shape
        apis_called = []
        for call in emu.get("api_calls", []):
            args = []
            for param in call.get("parameters", []):
                for val_entry in param.get("value", []):
                    args.append({
                        "type":  val_entry.get("type", ""),
                        "name":  param.get("type", ""),
                        "value": val_entry.get("value", "")
                    })
            apis_called.append({
                "address":      call.get("address"),
                "name":         call.get("api_name"),
                "dll":          call.get("dll_name"),
                "signature":    f"{call.get('address')} {call.get('api_name')}(...)",
                "arguments":    args,
                "return_value": call.get("return_value"),
                "call_args":    []
            })

        dlls_loaded = list(dict.fromkeys(emu.get("dlls", [])))

        artifacts = {
            "files":       list(dict.fromkeys(
                               emu.get("file_misc", []) +
                               emu.get("file_create", []) +
                               emu.get("file_write", [])
                           )),
            "executables": list(dict.fromkeys(emu.get("exe_dll_artifacts", []))),
            "web":         list(dict.fromkeys(emu.get("web_artifacts", []))),
            "command_line": list(dict.fromkeys(emu.get("commandLine_artifacts", []))),
        }

        # File operations
        file_operations = []
        for op_key in ("file_read","file_write","file_create","file_delete",
                       "file_copy","file_move","file_hash"):
            for entry in emu.get(op_key, []):
                file_operations.append({"operation": op_key, "path": entry})

        # Registry
        registry_operations = {
            "actions":      emu.get("registry_actions", []),
            "techniques":   emu.get("registry_techniques", []),
            "hierarchy":    emu.get("registry_hierarchy", []),
            "entries":      emu.get("registry_miscellaneous", []),
        }

        # Network
        network_indicators = list(dict.fromkeys(emu.get("web_artifacts", [])))

        # Syscalls
        syscalls = emu.get("syscalls_emulation", [])

        #  Strings 
        seen_strings: set = set()
        strings_found = []
        for s in main.get("strings", []):
            key = (s.get("value",""), s.get("offset",""), s.get("type",""))
            if key in seen_strings:
                continue
            seen_strings.add(key)
            val   = s.get("value", "")
            stype = s.get("type", "")
            is_meaningful = (
                stype == "pushString"
                or (len(val) >= 5 and ("." in val or "/" in val or "\\" in val))
            )
            strings_found.append({
                "value":      val,
                "offset":     s.get("offset"),
                "length":     s.get("length"),
                "type":       stype,
                "source":     s.get("source"),
                "meaningful": is_meaningful,
                "disasm_ref": None,   # cross-referenced below
            })

        #  Disassembly 
        disasm_offset_map: dict = {}
        disassembly = []
        for instr in disasm.get("disassembly", []):
            comment = instr.get("comment", "") or ""
            # Split multi-line comments into annotation + call_args
            comment_lines = [c.strip() for c in comment.splitlines() if c.strip()]
            annotation  = comment_lines[0].lstrip("; ") if comment_lines else None
            call_args   = []
            for cl in comment_lines[1:]:
                cl = cl.strip().strip("()")
                if cl:
                    call_args.append(cl)
            entry = {
                "offset":      instr.get("address"),
                "instruction": instr.get("instruction"),
                "bytes":       instr.get("hex"),
                "size":        instr.get("size"),
                "ascii_repr":  instr.get("string"),
                "annotation":  annotation,
                "call_args":   call_args,
                "label":       instr.get("label") or None,
            }
            disasm_offset_map[entry["offset"]] = len(disassembly)
            disassembly.append(entry)

        # Cross-reference strings to disassembly by offset
        for s in strings_found:
            idx = disasm_offset_map.get(s["offset"])
            if idx is not None:
                d = disassembly[idx]
                s["disasm_ref"] = {
                    "offset":      d["offset"],
                    "instruction": d["instruction"],
                    "annotation":  d["annotation"],
                }

        #  Deobfuscation info 
        deobfuscation = main.get("deobfuscation", {})

        #  Emulation summary 
        meaningful_strings = [s for s in strings_found if s.get("meaningful")]
        emulation_summary = {
            "total_apis":               len(apis_called),
            "total_syscalls":           len(syscalls),
            "dlls_loaded":              len(dlls_loaded),
            "artifacts_found":          len(artifacts["files"]) + len(artifacts["executables"]),
            "disassembly_instructions": len(disassembly),
            "strings_found":            len(strings_found),
            "meaningful_strings":       len(meaningful_strings),
            "network_activity":         len(network_indicators) > 0,
            "file_activity":            len(file_operations) > 0,
            "registry_activity":        bool(registry_operations["entries"]),
            "strings_detected":         len(strings_found) > 0,
            "entropy":                  None,   # injected after return
            "md5":                      basic_info.get("md5"),
            "file_size":                None,   # injected after return
            "shellcode_classification": analysis_metadata["shellcode_type"],
            "classification_reason":    analysis_metadata["classification_reason"],
            "emulation_depth":          cpu_instructions,
        }

        return {
            "status":                 "completed",
            "_source_files":          sorted(raw.keys()),
            "_source_dir":            str(logs_dir),
            "basic_info":             basic_info,
            "analysis_metadata":      analysis_metadata,
            "apis_called":            apis_called,
            "syscalls":               syscalls,
            "network_indicators":     network_indicators,
            "file_operations":        file_operations,
            "registry_operations":    registry_operations,
            "strings_found":          strings_found,
            "disassembly":            disassembly,
            "disassembly_annotations": [d["annotation"] for d in disassembly if d["annotation"]],
            "dlls_loaded":            dlls_loaded,
            "artifacts":              artifacts,
            "deobfuscation":          deobfuscation,
            "emulation_summary":      emulation_summary,
        }

    def analyze_shellcode(
        self,
        shellcode_path: str,
        architecture: str = "32",
        output_json: bool = True,
        timeout: int = 300,
        analysis_mode: str = "full",
        known_sha256: Optional[str] = None
    ) -> Dict:
        """
        Analyze shellcode using SHAREM in headless mode.
        """
        import time as _time
        import math as _math

        if not self.is_installed:
            raise RuntimeError("SHAREM is not installed. Run setup() first.")

        shellcode_path = Path(shellcode_path)
        if not shellcode_path.exists():
            raise FileNotFoundError(f"Shellcode file not found: {shellcode_path}")

        #  Step 1: Ensure headless startup is enabled 
        self._ensure_headless_startup()

        #  Step 2: Compute file metrics from raw bytes 
        try:
            raw_bytes = shellcode_path.read_bytes()
            file_size = len(raw_bytes)
            if file_size > 0:
                freq = [0] * 256
                for b in raw_bytes:
                    freq[b] += 1
                entropy = -sum(
                    (c / file_size) * _math.log2(c / file_size)
                    for c in freq if c > 0
                )
            else:
                entropy = 0.0
        except Exception as _e:
            logger.warning(f"Could not compute file metrics: {_e}")
            file_size = None
            entropy   = None

        #  Step 3: Record start time just before launching SHAREM 
        # Subtract 1 second of slack to handle filesystem timestamp granularity
        run_start_time = _time.time() - 1.0

        #  Step 4: Run SHAREM headless 
        arch_flag = f"-r{architecture}"
        cmd = [
            sys.executable,
            str(self.sharem_cli / "main.py"),
            arch_flag,
            str(shellcode_path)
        ]

        logger.info(f"Running SHAREM headless on {shellcode_path}...")
        logger.info(f"Architecture: {architecture}-bit")
        logger.info(f"Command: {' '.join(cmd)}")
        logger.info(f"JSON output dir: {self._headless_logs_dir}")

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.sharem_cli)
            )

            #  Step 5: Load and merge JSON files from this run only 
            analysis_results = self._collect_headless_json_reports(run_start_time)

            if not analysis_results:
                logger.error(
                    f"No JSON output found in {self._headless_logs_dir} "
                    "after SHAREM completed. Check that SHAREM ran successfully "
                    "and that startup_enabled = True in config.cfg."
                )
                return {
                    "status": "error",
                    "error": "SHAREM produced no JSON output",
                    "logs_dir": str(self._headless_logs_dir)
                }

            #  Step 6: Inject computed file metrics 
            analysis_results["basic_info"]["file_size"] = file_size
            analysis_results["basic_info"]["entropy"]   = entropy
            analysis_results["emulation_summary"]["file_size"] = file_size
            analysis_results["emulation_summary"]["entropy"]   = (
                round(entropy, 4) if entropy is not None else None
            )

            #  Step 6b: Build normalized pipeline document 
            # Load the raw SHAREM JSON files that were just written so we can
            # pass them directly to the normalizer (avoids re-parsing stdout).
            logs_dir = self._headless_logs_dir
            _jd_path  = logs_dir / "jsondefault.json"
            _jdd_path = logs_dir / "jsondefaultdisasm.json"

            normalized: Optional[dict] = None
            if _jd_path.exists() and _jdd_path.exists():
                try:
                    # Determine output path: ./results/<sha256>.json
                    # Prefer known_sha256 (from ingest), else use sha256 from the main report, else md5, else filename stem.
                    _file_hash = (
                        known_sha256
                        or analysis_results.get("basic_info", {}).get("sha256")
                        or analysis_results.get("basic_info", {}).get("md5")
                        or shellcode_path.stem
                    )
                    _results_dir = Path("results")
                    _results_dir.mkdir(parents=True, exist_ok=True)
                    _output_path = _results_dir / f"{_file_hash}.json"

                    normalized = normalize_sharem_files(
                        str(_jd_path),
                        str(_jdd_path),
                        file_path=str(shellcode_path),
                        file_size=file_size,
                        entropy=entropy,
                        output_path=str(_output_path),
                        override_sha256=known_sha256,  # Pass the ingest hash for override
                    )
                    analysis_results["normalized"] = normalized
                    # Also synthesize a top-level `disassembly` block in the
                    # normalized document by processing available disassembly
                    # sources through the canonical `normalize_op_str`.
                    try:
                        sa = normalized.get('static_analysis', {}) or {}
                        top_disasm = {"functions": []}

                        # Prefer explicit functions if present (PE/ELF style)
                        sa_funcs = sa.get('functions') or []

                        def _norm_from_instr_list(instrs, base_name=None, base_offset='0x0'):
                            normalized_ops = []
                            for ins in instrs:
                                try:
                                    nd = normalize_op_str({'disasm': ins.get('instruction') or ins.get('disasm') or ''})
                                except Exception:
                                    t = ins.get('instruction') or ins.get('disasm') or ''
                                    nd = re.sub(r'0x[0-9a-fA-F]+|\b\d+\b', 'CONST', t)
                                    nd = nd.replace(',', ' ').strip().lower()
                                    nd = re.sub(r'\s+', ' ', nd)
                                normalized_ops.append(nd)
                            func_hash = hashlib.sha256("\n".join(normalized_ops).encode('utf-8', errors='replace')).hexdigest() if normalized_ops else None
                            name = base_name or f"fcn.{str(base_offset)[2:].rjust(8,'0') if str(base_offset).startswith('0x') else str(base_offset).rjust(8,'0')}"
                            size = None
                            try:
                                size = sum(int(i.get('size') or 0) for i in instrs)
                            except Exception:
                                size = len(instrs)
                            return {
                                "name": name,
                                "offset": base_offset,
                                "size": size,
                                "func_hash": func_hash,
                                "mnemonics": normalized_ops,
                                "strings_referenced": [],
                                "similar_occurrences": []
                            }

                        if sa_funcs:
                            for f in sa_funcs:
                                instrs = f.get('instructions') or []
                                off = f.get('offset') or (instrs[0].get('offset') if instrs else '0x0')
                                name = None
                                if f.get('name') and not f.get('name').startswith('shellcode_entry'):
                                    name = f.get('name')
                                func_entry = _norm_from_instr_list(instrs, base_name=name, base_offset=off)
                                # preserve any referenced strings from original if present
                                func_entry['strings_referenced'] = f.get('strings_referenced', []) or []
                                func_entry['similar_occurrences'] = f.get('similar_occurrences', []) or []
                                top_disasm['functions'].append(func_entry)
                        else:
                            # Fall back to format_specific.disassembly.instructions
                            fs_disasm = (sa.get('format_specific') or {}).get('disassembly', {}) or {}
                            instrs = fs_disasm.get('instructions') or normalized.get('disassembly', {}).get('instructions') or []
                            if instrs:
                                off = instrs[0].get('offset') or '0x0'
                                func_entry = _norm_from_instr_list(instrs, base_name=None, base_offset=off)
                                top_disasm['functions'].append(func_entry)

                        # Attach processed disassembly to the normalized document
                        # and expose it at the top-level under a distinct key to
                        # avoid overwriting the raw `analysis_results['disassembly']`.
                        normalized['disassembly'] = top_disasm
                        analysis_results['disassembly_normalized'] = top_disasm

                        # Persist the updated normalized file so results on disk match
                        try:
                            with open(str(_output_path), 'w', encoding='utf-8') as _outf:
                                json.dump(normalized, _outf, indent=2)
                        except Exception as _werr:
                            logger.warning(f"Failed to write updated normalized file: {_werr}")
                    except Exception as _e:
                        logger.warning(f"Failed to synthesize top-level disassembly: {_e}")
                    analysis_results["normalized_output_path"] = str(_output_path)
                    logger.info(f"Normalized pipeline document written to: {_output_path}")
                    logger.info("Normalized pipeline document attached as results['normalized']")
                    #  Persist a disassembly text file for easy viewing/searching
                    try:
                        # Build a friendly disassembly text and write next to normalized JSON
                        dis_text_path = _results_dir / f"{_file_hash}-disassembly.txt"
                        try:
                            func = (normalized.get('disassembly', {})
                                    .get('functions', []) or [None])[0]
                        except Exception:
                            func = None

                        def _format_disasm_text(func_block):
                            if not func_block:
                                return ""
                            lines = []
                            instrs = func_block.get('instructions', [])
                            for ins in instrs:
                                off = ins.get('offset') or ''
                                instr = ins.get('instruction') or ''
                                bytes_hex = ins.get('bytes') or ''
                                ascii_repr = ins.get('ascii_repr') or ''
                                # Pad columns for readability
                                instr_col = instr.ljust(40)
                                bytes_col = bytes_hex.ljust(24)
                                lines.append(f"{off} {instr_col} {bytes_col} {ascii_repr}")
                                # Add annotation/comment lines if present
                                ann = ins.get('annotation')
                                if ann:
                                    lines.append(f"     ; {ann}")
                                call_args = ins.get('call_args') or []
                                if call_args:
                                    lines.append(f"     ; ({', '.join(call_args)})")
                            return "\n".join(lines)

                        disasm_text = _format_disasm_text(func)
                        if disasm_text:
                            with open(dis_text_path, 'w', encoding='utf-8') as _f:
                                _f.write(disasm_text)
                            logger.info(f"Wrote disassembly text to: {dis_text_path}")
                    except Exception as _werr:
                        logger.warning(f"Failed to write disassembly text: {_werr}")

                except Exception as _norm_err:
                    logger.warning(f"Normalization step failed (non-fatal): {_norm_err}")
            else:
                logger.warning(
                    "Could not find jsondefault.json / jsondefaultdisasm.json for normalization "
                    f"in {logs_dir}"
                )

            #  Step 7: Print combined JSON to terminal 
            if output_json:
                print(json.dumps(analysis_results, indent=2, default=str))

            return analysis_results

        except subprocess.TimeoutExpired:
            logger.error(f"Analysis timed out after {timeout} seconds")
            return {"status": "timeout", "error": f"Analysis exceeded {timeout}s timeout"}
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"status": "error", "error": str(e)}

    def _find_json_report(self, shellcode_name: str, known_md5: Optional[str] = None) -> Optional[Dict]:
        """
        Find and load JSON report generated by SHAREM.
        """
        # Ensure the primary logs directory exists so SHAREM can write into it
        primary_logs = self.sharem_cli / "logs"
        try:
            primary_logs.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        candidate_dirs = [
            self.sharem_cli / "logs",
            self.sharem_cli / "output",
            self.sharem_cli / "results",
            self.sharem_cli,
            self.sharem_repo / "sharem_cli" / "logs",
            self.sharem_repo / "logs",
            Path.home() / ".sharem" / "logs",
            Path.cwd() / "logs",
            Path.cwd(),
        ]

        json_files = []
        searched = []
        for d in candidate_dirs:
            if not d.exists():
                continue
            searched.append(str(d))
            # Prefer files whose name contains the shellcode stem
            matches = list(d.glob(f"*{shellcode_name}*.json"))
            if matches:
                json_files = matches
                logger.info(f"Found JSON report(s) matching '{shellcode_name}' in {d}")
                break
            # Fallback: any JSON in the directory
            all_json = list(d.glob("*.json"))
            if all_json and not json_files:
                json_files = all_json
                logger.info(f"Found JSON report(s) in {d} (no name match)")

        if not json_files:
            logger.warning(f"No JSON reports found. Searched: {searched}")
            return None

        latest_json = max(json_files, key=lambda p: p.stat().st_mtime)
        logger.info(f"Using JSON report: {latest_json}")
        try:
            with open(latest_json, 'r', encoding='utf-8', errors='ignore') as f:
                report_data = json.load(f)

            #  MD5 verification 
            # If we have a known MD5, check that it appears somewhere in the
            # report JSON.  SHAREM saves the shellcode MD5 in its report;
            # if the MD5 doesn't match we've picked up an unrelated file
            # (e.g. a CAPE/Cuckoo report sitting in cwd).
            if known_md5:
                report_str = json.dumps(report_data).lower()
                if known_md5.lower() not in report_str:
                    logger.warning(
                        f"JSON report {latest_json} does not contain MD5 "
                        f"{known_md5} — skipping (likely an unrelated report)"
                    )
                    return None

            return {
                "file": str(latest_json),
                "data": report_data
            }
        except Exception as e:
            logger.warning(f"Failed to load JSON report {latest_json}: {e}")
            return None
    
    def get_detailed_report(self, shellcode_name: str) -> Optional[Dict]:
        """
        Retrieve the detailed JSON report for a shellcode analysis.
        
        Args:
            shellcode_name: Name of the shellcode file (without extension)
            
        Returns:
            Dictionary containing the detailed report, or None if not found
        """
        return self._find_json_report(shellcode_name)
    
    def _convert_shellcode_format(self, content: str) -> str:
        """
        Convert various shellcode formats to plain hex.
        """
        # Remove quotes if present
        content = content.strip().strip('"').strip("'")
        
        # Check if it's in \x format
        if "\\x" in content:
            # Extract hex bytes
            hex_bytes = content.split("\\x")[1:]  # Skip first empty element
            hex_string = "".join(hex_bytes)
            # Remove any remaining non-hex characters
            hex_string = "".join(c for c in hex_string if c in "0123456789ABCDEFabcdef")
            return hex_string
        
        # Already plain hex or has some formatting
        hex_string = "".join(c for c in content if c in "0123456789ABCDEFabcdef")
        return hex_string
    
    def analyze_from_text(
        self,
        shellcode_hex: str,
        architecture: str = "32",
        analysis_mode: str = "full"
    ) -> Dict:
        """
        Analyze shellcode from hex string.
        """
        # Convert to plain hex format
        plain_hex = self._convert_shellcode_format(shellcode_hex)
        
        # Create temporary file with hex content
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.txt',
            delete=False
        ) as tmp:
            tmp.write(plain_hex)
            tmp_path = tmp.name
        
        try:
            results = self.analyze_shellcode(tmp_path, architecture, analysis_mode=analysis_mode)
            return results
        finally:
            # Cleanup
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def analyze_file_or_upload(
        self,
        file_input: Union[str, bytes, object],
        architecture: str = "32",
        analysis_mode: str = "full",
        auto_convert: bool = True
    ) -> Dict:
        """
        Analyze shellcode from file path, file object, or bytes.
        
        Args:
            file_input: Can be:
                - String path to file
                - File-like object with read() method
                - Bytes object
            architecture: "32" for 32-bit or "64" for 64-bit
            analysis_mode: "full", "emulate", "disassemble", "quick", "strings", or "info"
            auto_convert: Automatically convert shellcode format if needed
            
        Returns:
            Dictionary containing analysis results
        """
        # If it's a string, treat as file path
        if isinstance(file_input, str):
            if os.path.exists(file_input):
                # Check if we need to convert the format
                if auto_convert and file_input.endswith('.txt'):
                    with open(file_input, 'r') as f:
                        content = f.read()
                    
                    # Check if it needs conversion
                    if '\\x' in content or '"' in content or "'" in content:
                        logger.info("Detected escaped hex format, converting to plain hex...")
                        return self.analyze_from_text(content, architecture, analysis_mode)
                
                return self.analyze_shellcode(file_input, architecture, analysis_mode=analysis_mode)
            else:
                raise FileNotFoundError(f"File not found: {file_input}")
        
        # If it's bytes or file object, save to temp file
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='wb',
                suffix='.txt',
                delete=False
            ) as tmp:
                if isinstance(file_input, bytes):
                    tmp.write(file_input)
                elif hasattr(file_input, 'read'):
                    content = file_input.read()
                    if isinstance(content, str):
                        tmp.write(content.encode())
                    else:
                        tmp.write(content)
                else:
                    raise ValueError("Unsupported file_input type")
                temp_path = tmp.name
            
            return self.analyze_shellcode(temp_path, architecture, analysis_mode=analysis_mode)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def verify_installation(self, verbose: bool = True) -> Dict:
        """
        Comprehensive installation verification.
        
        Args:
            verbose: Print detailed status
            
        Returns:
            Dictionary with installation status
        """
        status = {
            "package_installed": False,
            "repo_cloned": False,
            "installers_exist": False,
            "bat_file_exists": False,
            "setup_py_exists": False,
            "sharem_cli_exists": False,
            "dll_status": {},
            "issues": []
        }
        
        # Check if package is installed
        status["package_installed"] = self._check_installation()
        
        # Check if repo is cloned
        status["repo_cloned"] = self.sharem_repo.exists()
        
        if status["repo_cloned"]:
            # Check installer directory
            installer_dir = self.sharem_repo / "installers"
            status["installers_exist"] = installer_dir.exists()
            
            if status["installers_exist"]:
                bat_file = installer_dir / "windows_installer.bat"
                status["bat_file_exists"] = bat_file.exists()
            
            # Check setup.py
            setup_py = self.sharem_repo / "setup.py"
            status["setup_py_exists"] = setup_py.exists()
            
            # Check sharem_cli
            status["sharem_cli_exists"] = self.sharem_cli.exists()
        
        # Check DLL status
        try:
            status["dll_status"] = self.check_dll_status()
        except Exception as e:
            logger.warning(f"Could not check DLL status: {e}")
            status["dll_status"] = {"x86_count": 0, "x64_count": 0}
        
        # Identify issues
        if not status["package_installed"]:
            status["issues"].append("SHAREM not installed as Python package")
        if not status["repo_cloned"]:
            status["issues"].append("Repository not cloned")
        if not status["sharem_cli_exists"]:
            status["issues"].append("sharem_cli directory not found")
        if status["dll_status"].get("x86_count", 0) == 0:
            status["issues"].append("No x86 DLLs found - first emulation will harvest them")
        if status["dll_status"].get("x64_count", 0) == 0:
            status["issues"].append("No x64 DLLs found - first 64-bit emulation will harvest them")
        
        if verbose:
            print("=" * 70)
            print("SHAREM INSTALLATION STATUS")
            print("=" * 70)
            print(f"Package Installed: {'✓' if status['package_installed'] else '✗'}")
            print(f"Repository Cloned: {'✓' if status['repo_cloned'] else '✗'}")
            print(f"Installers Directory: {'✓' if status['installers_exist'] else '✗'}")
            print(f"Windows .bat File: {'✓' if status['bat_file_exists'] else '✗'}")
            print(f"setup.py: {'✓' if status['setup_py_exists'] else '✗'}")
            print(f"sharem_cli Directory: {'✓' if status['sharem_cli_exists'] else '✗'}")
            print(f"\nDLL Database:")
            print(f"  x86 DLLs: {status['dll_status'].get('x86_count', 0)}")
            print(f"  x64 DLLs: {status['dll_status'].get('x64_count', 0)}")
            
            if status["issues"]:
                print(f"\nIssues Found ({len(status['issues'])}):")
                for issue in status["issues"]:
                    print(f"  ⚠ {issue}")
            else:
                print("\n✓ No issues found!")
            
            print("=" * 70)
        
        return status
    
    def check_dll_status(self) -> Dict:
        """
        Check the status of SHAREM's DLL database.
        
        Returns:
            Dictionary with DLL status information
        """
        status = {
            "x86_dlls": [],
            "x64_dlls": [],
            "x86_count": 0,
            "x64_count": 0,
            "address_databases": []
        }
        
        # Check for DLL directories
        dll_base = self.sharem_repo / "sharem" / "sharem" / "DLLs"
        
        x86_dir = dll_base / "x86"
        x64_dir = dll_base / "x64"
        
        if x86_dir.exists():
            x86_dlls = list(x86_dir.glob("*.dll"))
            status["x86_dlls"] = [d.name for d in x86_dlls]
            status["x86_count"] = len(x86_dlls)
        
        if x64_dir.exists():
            x64_dlls = list(x64_dir.glob("*.dll"))
            status["x64_dlls"] = [d.name for d in x64_dlls]
            status["x64_count"] = len(x64_dlls)
        
        # Check for address database files
        sharem_base = self.sharem_repo / "sharem" / "sharem"
        addr_files = ["foundDLLAddresses32.json", "FoundDLLAddresses64.json"]
        
        for addr_file in addr_files:
            addr_path = sharem_base / addr_file
            if addr_path.exists():
                status["address_databases"].append({
                    "file": addr_file,
                    "exists": True,
                    "size": addr_path.stat().st_size
                })
            else:
                status["address_databases"].append({
                    "file": addr_file,
                    "exists": False
                })
        
        return status

    def get_config_path(self) -> Path:
        """Get path to SHAREM config file."""
        return self.sharem_repo / "sharem" / "sharem" / "config.cfg"
    
    def update_config(self, settings: Dict):
        """
        Update SHAREM configuration settings.
        
        Args:
            settings: Dictionary of config key-value pairs
        """
        config_path = self.get_config_path()
        
        if not config_path.exists():
            logger.warning(f"Config file not found: {config_path}")
            return
        
        # Read current config
        with open(config_path, 'r') as f:
            lines = f.readlines()
        
        # Update settings
        updated_lines = []
        for line in lines:
            modified = False
            for key, value in settings.items():
                if line.strip().startswith(f"{key}="):
                    updated_lines.append(f"{key}={value}\n")
                    modified = True
                    logger.info(f"Updated config: {key}={value}")
                    break
            
            if not modified:
                updated_lines.append(line)
        
        # Write back
        with open(config_path, 'w') as f:
            f.writelines(updated_lines)
        
        logger.info(f"Config updated: {config_path}")

    def format_results(self, analysis_results: Dict) -> str:
        """
        Format analysis results as JSON string.

        Args:
            analysis_results: Results from analyze_shellcode()

        Returns:
            JSON formatted string
        """
        return json.dumps(analysis_results, indent=2)
    
    def generate_summary_report(self, analysis_results: Dict) -> str:
        """Generate a human-readable summary report."""
        report = []
        report.append("=" * 70)
        report.append("SHAREM SHELLCODE ANALYSIS REPORT")
        report.append("=" * 70)
        report.append("")

        meta    = analysis_results.get("analysis_metadata", {})
        info    = analysis_results.get("basic_info", {})
        report.append("ANALYSIS METADATA:")
        report.append(f"  Status:                {analysis_results.get('status', 'unknown')}")
        report.append(f"  Classification:        {meta.get('shellcode_type', 'unknown')}")
        if meta.get("classification_reason"):
            report.append(f"  Reason:                {meta['classification_reason']}")
        report.append(f"  Architecture:          {meta.get('architecture', 'unknown')}")
        report.append(f"  Emulation Status:      {meta.get('emulation_status', 'unknown')}")
        report.append(f"  CPU Instructions:      {meta.get('cpu_instructions', 0)}")
        if info.get("md5"):
            report.append(f"  MD5:                   {info['md5']}")
        if info.get("sha256"):
            report.append(f"  SHA256:                {info['sha256']}")
        if info.get("ssdeep"):
            report.append(f"  ssdeep:                {info['ssdeep']}")
        if info.get("file_size") is not None:
            report.append(f"  File Size:             {info['file_size']} bytes")
        if info.get("entropy") is not None:
            ent = info['entropy']
            tag = "  [high — possible encryption/packing]" if ent > 7.0 else ""
            report.append(f"  Entropy:               {ent:.4f}{tag}")
        if meta.get("notes"):
            report.append(f"  Notes:                 {meta['notes']}")
        report.append("")

        features = meta.get("features_detected", [])
        if features:
            report.append("FEATURES DETECTED:")
            for f in features:
                report.append(f"  ✓ {f}")
            report.append("")

        summary = analysis_results.get("emulation_summary", {})
        report.append("EMULATION SUMMARY:")
        report.append(f"  APIs Called:           {summary.get('total_apis', 0)}")
        report.append(f"  Syscalls:              {summary.get('total_syscalls', 0)}")
        report.append(f"  DLLs Loaded:           {summary.get('dlls_loaded', 0)}")
        report.append(f"  Artifacts Found:       {summary.get('artifacts_found', 0)}")
        report.append(f"  Disasm Instructions:   {summary.get('disassembly_instructions', 0)}")
        report.append(f"  Strings Found:         {summary.get('strings_found', 0)}  ({summary.get('meaningful_strings', 0)} meaningful)")
        report.append(f"  Network Activity:      {'Yes' if summary.get('network_activity') else 'No'}")
        report.append(f"  File Activity:         {'Yes' if summary.get('file_activity') else 'No'}")
        report.append(f"  Registry Activity:     {'Yes' if summary.get('registry_activity') else 'No'}")
        report.append("")

        apis = analysis_results.get("apis_called", [])
        if apis:
            report.append("API CALLS DETECTED:")
            for api in apis[:20]:
                if isinstance(api, dict):
                    report.append(f"  • [{api.get('address','')}] {api.get('name','')}()")
                    for arg in api.get("arguments", []):
                        report.append(f"      {arg['type']} {arg['name']} = {arg['value']}")
                    if api.get("return_value"):
                        report.append(f"      => {api['return_value']}")
                else:
                    report.append(f"  • {api}")
            if len(apis) > 20:
                report.append(f"  ... and {len(apis) - 20} more")
            report.append("")

        dlls = analysis_results.get("dlls_loaded", [])
        if dlls:
            report.append("DLLS LOADED:")
            for dll in dlls:
                report.append(f"  • {dll}")
            report.append("")

        artifacts = analysis_results.get("artifacts", {})
        if artifacts.get("files") or artifacts.get("executables"):
            report.append("ARTIFACTS:")
            for f in artifacts.get("files", []):
                report.append(f"  [file]    {f}")
            for e in artifacts.get("executables", []):
                report.append(f"  [exe/dll] {e}")
            report.append("")

        strings = analysis_results.get("strings_found", [])
        if strings:
            report.append("STRINGS FOUND:")
            for s in strings[:30]:
                ref  = s.get("disasm_ref")
                flag = "" if s.get("meaningful", True) else "  [fragment]"
                ref_str = f"  <- {ref['instruction']}" if ref else ""
                report.append(f"  [{s['type']}] {s['value']}  (offset {s['offset']}){ref_str}{flag}")
            if len(strings) > 30:
                report.append(f"  ... and {len(strings) - 30} more")
            report.append("")

        disasm = analysis_results.get("disassembly", [])
        if disasm:
            report.append("DISASSEMBLY:")
            for instr in disasm:
                if isinstance(instr, dict):
                    line = f"  {instr['offset']:>6}  {instr['instruction']}"
                    if instr.get("bytes"):
                        line += f"  [{instr['bytes']}]"
                    report.append(line)
                    if instr.get("annotation"):
                        report.append(f"          ; {instr['annotation']}")
                    if instr.get("call_args"):
                        report.append(f"          args: ({', '.join(instr['call_args'])})")
                else:
                    report.append(f"  {instr}")
            report.append("")

        network = analysis_results.get("network_indicators", [])
        if network:
            report.append("NETWORK INDICATORS:")
            for n in network:
                report.append(f"  ⚠ {n}")
            report.append("")

        files = analysis_results.get("file_operations", [])
        if files:
            report.append("FILE OPERATIONS:")
            for fo in files:
                report.append(f"  • {fo}")
            report.append("")

        registry = analysis_results.get("registry_operations", {})
        # Only report registry activity if there are actual entries.
        # actions/techniques/hierarchy are SHAREM template fields always present.
        reg_entries = registry.get("entries", []) if isinstance(registry, dict) else registry
        if reg_entries:
            report.append("REGISTRY OPERATIONS:")
            for ro in reg_entries:
                report.append(f"  • {ro}")
            techniques = registry.get("techniques", [])
            if techniques:
                report.append(f"  Techniques: {', '.join(techniques)}")
            report.append("")
        elif isinstance(registry, list) and registry:
            # Legacy flat list format
            report.append("REGISTRY OPERATIONS:")
            for ro in registry:
                report.append(f"  • {ro}")
            report.append("")

        # Sandbox verdict (from merged json_report)
        sandbox = analysis_results.get("sandbox_verdict", {})
        if sandbox:
            report.append("SANDBOX VERDICT:")
            report.append(f"  Score:    {sandbox.get('score', 'N/A')}")
            report.append(f"  Label:    {sandbox.get('label', 'N/A')}")
            if sandbox.get("families"):
                report.append(f"  Families: {', '.join(sandbox['families'])}")
            report.append("")

        # Malware config extractions (CAPE)
        configs = analysis_results.get("malware_config", [])
        if configs:
            report.append("MALWARE CONFIG (CAPE EXTRACTION):")
            for item in configs:
                report.append(f"  Family: {item['family']}")
                for key, vals in item.get("config", {}).items():
                    if key.startswith("TLS"):   # skip noisy TLS certs
                        continue
                    if isinstance(vals, list) and vals and vals[0]:
                        report.append(f"    {key}: {', '.join(str(v) for v in vals)}")
            report.append("")

        # Mutexes
        mutexes = analysis_results.get("mutexes", [])
        if mutexes:
            report.append("MUTEXES:")
            for m in mutexes:
                report.append(f"  • {m}")
            report.append("")

        # YARA
        yara = analysis_results.get("yara_matches", [])
        if yara:
            report.append("YARA MATCHES:")
            for y in yara:
                report.append(f"  • {y}")
            report.append("")

        # Suricata
        suricata = analysis_results.get("suricata_alerts", [])
        if suricata:
            report.append("SURICATA ALERTS:")
            for s in suricata:
                report.append(f"  ⚠ {s}")
            report.append("")

        report.append("=" * 70)
        return "\n".join(report)



def normalize_sharem_to_pipeline(
    jsondefault: dict,
    jsondefaultdisasm: dict,
    *,
    file_path: Optional[str] = None,
    file_size: Optional[int] = None,
    entropy: Optional[float] = None,
) -> dict:
    """
    Convert the two raw SHAREM JSON outputs into the unified pipeline schema.
    """
    import math as _math
    import os as _os
    from datetime import datetime, timezone

    main   = jsondefault        or {}
    disasm = jsondefaultdisasm  or {}

    sha256 = main.get("sha256") or ""
    md5    = main.get("md5")    or ""
    ssdeep = main.get("ssdeep") or ""
    bits   = main.get("bits")

    #  Ingest analysis 
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    fname = None
    if file_path:
        fname = _os.path.basename(file_path)

    ingest_analysis = {
        "original_path":         file_path,
        "ingested_path":         file_path,
        "filename":              fname,
        "size_bytes":            file_size,
        "original_mtime":        None,
        "ingest_timestamp":      now_iso,
        "extension":             _os.path.splitext(fname)[1].lstrip(".") if fname else None,
        "claimed_type":          "Shellcode",
        "detected_type":         main.get("fileType", "Shellcode"),
        "matched_signature_hex": None,
        "magic_header_hex":      None,
        "sha256":                sha256,
        "mime_type_guess":       "application/octet-stream",
        "types_match":           True,
        "can_contain_vba_macros": False,
    }

    #  Analysis timestamps 
    analysis_timestamps = {
        "sharem": main.get("dateAnalyzed"),
    }

    #  Static analysis 
    # Hashes
    hashes = {
        "md5":    md5,
        "sha1":   None,
        "sha256": sha256,
        "ssdeep": ssdeep,
    }

    # Basic info
    arch_str = f"x86 ({bits}-bit)" if bits else "shellcode"
    basic_info = {
        "filename":  fname,
        "file_size": file_size,
        "file_type": "shellcode",
        "bits":      bits,
        "arch":      arch_str,
        "entry_point": main.get("entryPoint"),
        "entropy":   round(entropy, 4) if entropy is not None else None,
    }

    # Shellcode hex payload
    sc_block = main.get("shellcode", {}) or {}
    shellcode_info = {
        "rawhex":  sc_block.get("rawhex"),
        "strlit":  sc_block.get("strlit"),
    }

    # Strings — deduplicate by (value, offset, type)
    seen: set = set()
    strings_ascii:   list = []
    strings_unicode: list = []
    strings_push:    list = []
    for s in main.get("strings", []):
        key = (s.get("value", ""), s.get("offset", ""), s.get("type", ""))
        if key in seen:
            continue
        seen.add(key)
        entry = {
            "value":  s.get("value"),
            "offset": s.get("offset"),
            "length": s.get("length"),
            "type":   s.get("type"),
            "source": s.get("source"),
        }
        stype = (s.get("type") or "").lower()
        if stype == "pushstring":
            strings_push.append(entry)
        elif stype in ("unicode", "wide"):
            strings_unicode.append(entry)
        else:
            strings_ascii.append(entry)

    # SHAREM features detected
    feature_map = [
        ("pushret",     "Push/Ret"),
        ("callpop",     "Call/Pop"),
        ("PEB",         "PEB Walking"),
        ("fstenv",      "FSTENV (GetEIP)"),
        ("heavensGate", "Heaven's Gate (WoW64)"),
        ("syscall",     "Windows Syscalls"),
    ]
    features_detected = []
    for key, label in feature_map:
        if main.get(key):
            features_detected.append(label)

    # Deobfuscation
    deobfuscation = main.get("deobfuscation", {}) or {}

    # MITRE mapping placeholder — populated later if MITRE module runs
    mitre_mapping: list = []

    # YARA placeholder
    yara_matches: list = []

    static_analysis = {
        "metadata": {
            "timestamp":        now_iso,
            "analyzer_version": "sharem",
            "file_path":        file_path,
        },
        "hashes":    hashes,
        "basic_info": basic_info,
        # PE-specific fields — null/empty for shellcode
        "sections":  [],
        "imports":   [],
        "symbols":   [],
        "security_features": {
            "ASLR":           None,
            "DEP":            None,
            "SEH":            None,
            "CFG":            None,
            "SafeSEH":        None,
            "HighEntropyVA":  None,
            "ForceIntegrity": None,
            "Signed":         None,
        },
        "strings": {
            "ascii":   [s["value"] for s in strings_ascii],
            "unicode": [s["value"] for s in strings_unicode],
        },
        "yara_matches":  yara_matches,
        "mitre_mapping": mitre_mapping,
        # Shellcode-specific fields
        "shellcode": {
            "classification":       main.get("classification"),
            "classification_reason": main.get("reason"),
            "shellcode_hex":        shellcode_info,
            "features_detected":    features_detected,
            "strings_detailed": {
                "ascii":      strings_ascii,
                "unicode":    strings_unicode,
                "push_stack": strings_push,
            },
            "deobfuscation":        deobfuscation,
            # Evasion technique indicators
            "indicators": {
                "pushret":      main.get("pushret",      []),
                "callpop":      main.get("callpop",      []),
                "PEB":          main.get("PEB",          []),
                "fstenv":       main.get("fstenv",       []),
                "heavensGate":  main.get("heavensGate",  []),
                "syscall":      main.get("syscall",      []),
            },
        },
    }

    #  Disassembly 
    # Mirror the PE schema: {"functions": [...], "function_count": N, ...}
    # For shellcode there are no named functions — we wrap the flat instruction
    # list in a single synthetic function entry so consumers see a consistent
    # shape.
    raw_instrs = disasm.get("disassembly", []) or []
    mnemonics = []
    instructions = []
    for instr in raw_instrs:
        op = instr.get("instruction", "")
        mnemonics.append(op)
        comment = instr.get("comment", "") or ""
        comment_lines = [c.strip() for c in comment.splitlines() if c.strip()]
        annotation  = comment_lines[0].lstrip("; ") if comment_lines else None
        call_args   = [cl.strip().strip("()") for cl in comment_lines[1:] if cl.strip()]
        instructions.append({
            "offset":      instr.get("address"),
            "instruction": op,
            "bytes":       instr.get("hex"),
            "size":        instr.get("size"),
            "ascii_repr":  instr.get("string"),
            "data_type":   instr.get("dataType"),
            "data_accessed": instr.get("dataAccessed"),
            "annotation":  annotation,
            "call_args":   call_args,
            "label":       instr.get("label") or None,
        })

    entry_point = main.get("entryPoint", "0x0")
    # Use the canonical normalize_op_str from static_analysis.disassembly
    normalized_ops = []
    for instr in raw_instrs:
        try:
            norm = normalize_op_str({'disasm': instr.get('instruction') or instr.get('disasm') or ''})
        except Exception:
            # Fallback to local simple normalisation
            t = instr.get('instruction') or instr.get('disasm') or ''
            norm = re.sub(r'0x[0-9a-fA-F]+|\b\d+\b', 'CONST', t)
            norm = norm.replace(',', ' ').strip().lower()
            norm = re.sub(r'\s+', ' ', norm)
        normalized_ops.append(norm)

    func_hash = hashlib.sha256("\n".join(normalized_ops).encode("utf-8", errors="replace")).hexdigest() if normalized_ops else None

    total_size = 0
    for instr in instructions:
        size_val = instr.get("size") or instr.get("length") or 0
        try:
            total_size += int(size_val)
        except Exception:
            pass

    shellcode_function = {
        "name":        "shellcode_entry",
        "offset":      entry_point,
        "size":        total_size or file_size,
        "func_hash":   func_hash,
        "mnemonics":   normalized_ops,
        "instructions": instructions,   # full detail, absent from PE schema but additive
        "strings_referenced": [],
        "similar_occurrences": [],
    }

    disassembly_block = {
        "functions":      [shellcode_function],
        "function_count": 1,
        "instruction_count": len(instructions),
        "similar_binaries": [],
        "raw_disassembly_sections": [
            {
                "name": "shellcode",
                "instructions": raw_instrs,
            }
        ],
    }

    #  Emulation / threat intelligence 
    # The pipeline's threat_intelligence block holds external OSINT results.
    # SHAREM's emulation data is richer than typical OSINT, so we embed it
    # under a dedicated "sharem_emulation" key while keeping the standard
    # VirusTotal / AbuseCH / MITRE_ATTACK stubs so schemas stay compatible.

    emu = main.get("emulation", {}) or {}

    # Normalize API calls
    apis_called = []
    for call in emu.get("api_calls", []):
        args = []
        for param in call.get("parameters", []):
            for val_entry in param.get("value", []):
                args.append({
                    "type":  val_entry.get("type", ""),
                    "name":  param.get("type", ""),
                    "value": val_entry.get("value", ""),
                })
        apis_called.append({
            "address":      call.get("address"),
            "name":         call.get("api_name"),
            "dll":          call.get("dll_name"),
            "return_value": call.get("return_value"),
            "arguments":    args,
        })

    # File artefacts
    file_artifacts = list(dict.fromkeys(
        emu.get("file_misc",   []) +
        emu.get("file_create", []) +
        emu.get("file_write",  [])
    ))
    file_operations = []
    for op_key in ("file_read", "file_write", "file_create", "file_delete",
                   "file_copy", "file_move", "file_hash"):
        for entry in emu.get(op_key, []):
            file_operations.append({"operation": op_key, "path": entry})

    sharem_emulation = {
        "api_calls":           apis_called,
        "syscalls":            emu.get("syscalls_emulation", []),
        "dlls_loaded":         list(dict.fromkeys(emu.get("dlls", []))),
        "artifacts": {
            "files":        file_artifacts,
            "executables":  list(dict.fromkeys(emu.get("exe_dll_artifacts", []))),
            "web":          list(dict.fromkeys(emu.get("web_artifacts",     []))),
            "command_line": list(dict.fromkeys(emu.get("commandLine_artifacts", []))),
        },
        "file_operations":     file_operations,
        "network_indicators":  list(dict.fromkeys(emu.get("web_artifacts", []))),
        "registry": {
            "actions":    emu.get("registry_actions",     []),
            "techniques": emu.get("registry_techniques",  []),
            "hierarchy":  emu.get("registry_hierarchy",   []),
            "entries":    emu.get("registry_miscellaneous", []),
        },
        "path_copy":  emu.get("path_copy",  []),
        "path_move":  emu.get("path_move",  []),
        "path_misc":  emu.get("path_misc",  []),
        "commandline_artifacts": emu.get("commandLine_artifacts", []),
    }

    threat_intelligence = {
        "VirusTotal":    {},
        "AbuseIPDB":     {},
        "AbuseCH":       {},
        "GoogleSearch":  {},
        "MITRE_ATTACK":  {},
        "sharem_emulation": sharem_emulation,
    }

    #  Assemble final normalized document 
    return {
        "format_type":         "shellcode",
        "ingest_analysis":     ingest_analysis,
        "analysis_timestamps": analysis_timestamps,
        "static_analysis":     static_analysis,
        "disassembly":         disassembly_block,
        "threat_intelligence": threat_intelligence,
    }


def normalize_sharem_files(
    jsondefault_path: str,
    jsondefaultdisasm_path: str,
    *,
    file_path: Optional[str] = None,
    file_size: Optional[int] = None,
    entropy: Optional[float] = None,
    output_path: Optional[str] = None,
    override_sha256: Optional[str] = None,
) -> dict:
    """
    Load the two SHAREM output files from disk and return the normalized doc.
    """
    with open(jsondefault_path, "r", encoding="utf-8", errors="ignore") as f:
        jsondefault = json.load(f)
    with open(jsondefaultdisasm_path, "r", encoding="utf-8", errors="ignore") as f:
        jsondefaultdisasm = json.load(f)

    normalized = normalize_sharem_to_pipeline(
        jsondefault,
        jsondefaultdisasm,
        file_path=file_path,
        file_size=file_size,
        entropy=entropy,
    )

    # Override SHA256 if provided (to maintain consistency with ingest hash)
    if override_sha256:
        if "ingest_analysis" in normalized:
            normalized["ingest_analysis"]["sha256"] = override_sha256
        if "static_analysis" in normalized and "hashes" in normalized["static_analysis"]:
            normalized["static_analysis"]["hashes"]["sha256"] = override_sha256

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2, default=str)
        logger.info(f"Normalized shellcode report written to: {output_path}")

    return normalized



def _merge_sharem_json_report(results: dict, report_data: dict) -> None:
    """Surface useful fields from SHAREM's saved JSON report into top-level results.

    SHAREM's saved JSON contains richer static analysis data than stdout alone.
    This function extracts the most pipeline-relevant fields and merges them in
    without overwriting anything already captured from stdout parsing.
    """
    if not isinstance(report_data, dict):
        return

    #  Hashes (may be more complete than stdout parse) 
    file_info = report_data.get("file", {})
    bi = results.setdefault("basic_info", {})
    for key in ("md5", "sha1", "sha256", "sha512", "ssdeep"):
        if file_info.get(key) and not bi.get(key):
            bi[key] = file_info[key]

    #  Verdict / classification from sandbox 
    verdict = report_data.get("verdict", {})
    if verdict:
        results.setdefault("sandbox_verdict", {}).update({
            "score":    verdict.get("score"),
            "label":    verdict.get("label"),
            "families": verdict.get("families", [])
        })

    #  CAPE config extractions (e.g. Remcos C2, mutex, install paths) 
    cape = report_data.get("cape_config_extractions", [])
    if cape:
        extracted = []
        for entry in cape:
            # Each entry is a dict; skip internal hash keys
            for family, config in entry.items():
                if family.startswith("_"):
                    continue
                if isinstance(config, dict):
                    extracted.append({"family": family, "config": config})
        if extracted:
            results["malware_config"] = extracted
            # Pull C2s and mutex into network/summary for easy access
            for item in extracted:
                cfg = item.get("config", {})
                for c2_key in ("Control", "C2", "Server", "Host"):
                    for c2 in cfg.get(c2_key, []):
                        if c2 and c2 not in results.get("network_indicators", []):
                            results.setdefault("network_indicators", []).append(c2)
                for mutex in cfg.get("Mutex", []):
                    if mutex:
                        results.setdefault("mutexes", []).append(mutex)

    #  YARA matches 
    yara = report_data.get("yara_matches", [])
    if yara:
        results["yara_matches"] = yara

    #  Suricata / network alerts 
    suricata = report_data.get("suricata", {})
    if suricata.get("alerts"):
        results.setdefault("suricata_alerts", []).extend(suricata["alerts"])

    #  Static PE analysis 
    static = report_data.get("static_analysis", {})
    if any(static.values()):
        results["static_pe"] = {k: v for k, v in static.items() if v is not None}

    #  Update emulation_summary with sandbox verdict 
    if verdict.get("label"):
        results["emulation_summary"]["sandbox_verdict"] = verdict["label"]
    if verdict.get("score") is not None:
        results["emulation_summary"]["sandbox_score"] = verdict["score"]
    malware_families = verdict.get("families", [])
    if not malware_families:
        # Check cape config family names
        malware_families = [item["family"] for item in results.get("malware_config", [])]
    if malware_families:
        results["emulation_summary"]["malware_families"] = malware_families


# Example usage function
def analyze_shellcode_file(filepath: str, architecture: str = "32") -> Dict:
    """
    Convenience function to analyze a shellcode file.
    
    Args:
        filepath: Path to shellcode file
        architecture: "32" or "64"
        
    Returns:
        Analysis results as dictionary
    """
    analyzer = SharemAnalyzer(auto_setup=True)
    return analyzer.analyze_shellcode(filepath, architecture)


def analyze_uploaded_shellcode(file_input: Union[str, bytes, object], 
                               architecture: str = "32",
                               analysis_mode: str = "full") -> Dict:
    """
    Convenience function to analyze uploaded shellcode.
    Works with file paths, file objects, or bytes.
    
    Args:
        file_input: File path string, file object, or bytes
        architecture: "32" or "64"
        analysis_mode: "full" (default - complete analysis), 
                      "emulate" (emulation only),
                      "disassemble" (disassembly only),
                      "quick" (quick scan),
                      "strings" (extract strings),
                      "info" (basic info)
        
    Returns:
        Analysis results as dictionary
    """
    analyzer = SharemAnalyzer(auto_setup=True)
    return analyzer.analyze_file_or_upload(file_input, architecture, analysis_mode)


if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="SHAREM Shellcode Analyzer")
    parser.add_argument("shellcode", help="Path to shellcode file")
    parser.add_argument("--arch", choices=["32", "64"], default="32",
                       help="Architecture (32 or 64 bit)")
    parser.add_argument("--setup-only", action="store_true",
                       help="Only setup SHAREM, don't analyze")
    
    args = parser.parse_args()
    
    analyzer = SharemAnalyzer(auto_setup=True)
    
    if args.setup_only:
        print("SHAREM setup completed!")
    else:
        results = analyzer.analyze_shellcode(args.shellcode, args.arch)
        print(json.dumps(results, indent=2))
