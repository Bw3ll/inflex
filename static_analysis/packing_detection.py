from __future__ import annotations

import math
from collections import Counter
from typing import Any


#  Thresholds 

ENTROPY_HIGH      = 7.0   # strong packing signal
ENTROPY_ELEVATED  = 6.5   # moderate signal
ENTROPY_MEDIUM    = 6.0   # weak signal worth noting

# Import count below this in a non-trivial binary is suspicious
MIN_IMPORT_COUNT_PE  = 3

# Weights must sum to 1.0
WEIGHTS = {
    "entropy":           0.30,
    "section_structure": 0.20,
    "import_table":      0.20,
    "known_signatures":  0.15,
    "header_anomalies":  0.10,
    "security_absence":  0.05,
}

# Named packer section signatures (case-insensitive prefix/substring match)
PACKER_SECTION_SIGS: dict[str, list[str]] = {
    "UPX":        ["upx0", "upx1", "upx2", ".upx"],
    "ASPack":     [".aspack", ".adata"],
    "PECompact":  [".pec1", ".pec2", "pec2"],
    "Petite":     [".petite"],
    "WinUpack":   [".winup"],
    "FSG":        [".fsgs"],
    "MPRESS":     [".mpress1", ".mpress2"],
    "Themida":    [".themida", ".thmida"],
    "VMProtect":  [".vmp0", ".vmp1", ".vmp2"],
    "Armadillo":  [".arma"],
    "Obsidium":   [".obsidium"],
    "Enigma":     [".enigma1", ".enigma2"],
    "ExeStealth": [".exes"],
    "Morphine":   [".morphine"],
    "NsPack":     ["nsp0", "nsp1", "nsp2"],
}

# ELF packer/protection section names
PACKER_SECTION_SIGS_ELF: dict[str, list[str]] = {
    "UPX":       ["upx!", ".upxinfo"],
    "Burneye":   [".burn"],
    "Shiva":     [".shiva"],
    "Midgetpack": [".midget"],
    "Packed":    [".packed"],
}

# Suspicious standard-sounding names that are abused by packers
SUSPICIOUS_SECTION_NAMES = {
    ".textbss", ".ndata", ".enigma1", ".enigma2", ".themida",
    ".boot", "INIT", ".rsrc1",
}

# Imports whose presence is nearly useless without others — classic packed stub IAT
PACKED_STUB_ONLY_IMPORTS = {
    "loadlibrarya", "loadlibraryw", "getprocaddress", "virtualalloc",
    "virtualprotect", "exitprocess",
}


#  Entropy helpers 

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _entropy_score(value: float) -> float:
    """Map a single entropy value to a [0.0, 1.0] suspicion score."""
    if value >= ENTROPY_HIGH:
        return 1.0
    if value >= ENTROPY_ELEVATED:
        return 0.6
    if value >= ENTROPY_MEDIUM:
        return 0.3
    return 0.0


#  PE assessment 

def assess_packing_pe(analyzer) -> dict[str, Any]:
    """
    Assess packing/protection for a PE binary.

    Args:
        analyzer: A fully-analysed PEStaticAnalyzer instance
                  (analyzer.analyze() must have been called).

    Returns:
        Structured packing assessment dict.
    """
    pe   = analyzer.pe
    data = analyzer.analysis_data

    signals: dict[str, dict] = {k: {"raw_score": 0.0, "weight": WEIGHTS[k], "weighted": 0.0, "evidence": []} for k in WEIGHTS}
    packer_names: list[str] = []

    #  1. Entropy 
    section_scores = []
    for sec in data.get("sections", []):
        name    = sec.get("Name", "?")
        entropy = sec.get("Entropy", 0.0)
        s       = _entropy_score(entropy)
        section_scores.append(s)
        if entropy >= ENTROPY_HIGH:
            signals["entropy"]["evidence"].append(
                f"Section '{name}' entropy {entropy:.3f} >= {ENTROPY_HIGH} (packed/encrypted)"
            )
        elif entropy >= ENTROPY_ELEVATED:
            signals["entropy"]["evidence"].append(
                f"Section '{name}' entropy {entropy:.3f} — elevated"
            )

    # Resource entropy
    for res in data.get("resources", []):
        entropy = res.get("entropy", 0.0)
        if entropy >= ENTROPY_HIGH:
            signals["entropy"]["evidence"].append(
                f"Resource id={res.get('id')} entropy {entropy:.3f} — possible embedded payload"
            )
            section_scores.append(1.0)

    # Overlay entropy
    overlay = data.get("overlay", {})
    if overlay and overlay.get("entropy", 0) >= ENTROPY_HIGH:
        signals["entropy"]["evidence"].append(
            f"Overlay ({overlay['size']} bytes) entropy {overlay['entropy']:.3f} — likely encrypted payload"
        )
        section_scores.append(1.0)

    if section_scores:
        # Weight: at least one very-high section is a strong signal
        max_s = max(section_scores)
        mean_s = sum(section_scores) / len(section_scores)
        signals["entropy"]["raw_score"] = round(min(1.0, 0.6 * max_s + 0.4 * mean_s), 4)

    #  2. Section structure 
    sections  = data.get("sections", [])
    sec_names = [s.get("Name", "").lower() for s in sections]

    # Entry point not in .text
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in pe.sections:
            if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                ep_sec = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                if ".text" not in ep_sec.lower() and "code" not in ep_sec.lower():
                    signals["section_structure"]["evidence"].append(
                        f"Entry point in non-code section '{ep_sec}' (packer stub)"
                    )
                    signals["section_structure"]["raw_score"] = max(
                        signals["section_structure"]["raw_score"], 0.8
                    )
                break
    except Exception:
        pass

    # Executable + writable sections (W^X violation)
    for sec in sections:
        flags = sec.get("Characteristics", {}).get("flags", [])
        if "MEM_EXECUTE" in flags and "MEM_WRITE" in flags:
            signals["section_structure"]["evidence"].append(
                f"Section '{sec['Name']}' is both writable and executable (W^X violation)"
            )
            signals["section_structure"]["raw_score"] = max(
                signals["section_structure"]["raw_score"], 0.7
            )

    # Zero raw-size sections
    for sec in sections:
        if sec.get("RawSize", 1) == 0 and sec.get("Name", "") not in [".bss"]:
            signals["section_structure"]["evidence"].append(
                f"Section '{sec['Name']}' has zero raw size — unpacked at runtime"
            )
            signals["section_structure"]["raw_score"] = max(
                signals["section_structure"]["raw_score"], 0.6
            )

    # Suspicious section names
    for name in sec_names:
        if name in SUSPICIOUS_SECTION_NAMES:
            signals["section_structure"]["evidence"].append(
                f"Suspicious section name '{name}'"
            )
            signals["section_structure"]["raw_score"] = max(
                signals["section_structure"]["raw_score"], 0.5
            )

    # Very few sections (packed stubs often use 1-2)
    if len(sections) <= 2 and len(sections) > 0:
        signals["section_structure"]["evidence"].append(
            f"Only {len(sections)} section(s) — typical of packed stubs"
        )
        signals["section_structure"]["raw_score"] = max(
            signals["section_structure"]["raw_score"], 0.4
        )

    # Virtual size >> raw size (common unpacking pattern)
    for sec in sections:
        try:
            raw  = sec.get("RawSize", 0)
            virt = int(sec.get("VirtualSize", "0x0"), 16) if isinstance(sec.get("VirtualSize"), str) else sec.get("VirtualSize", 0)
            if raw > 0 and virt > raw * 5:
                signals["section_structure"]["evidence"].append(
                    f"Section '{sec['Name']}': virtual size {virt} >> raw size {raw} (in-memory unpacking expected)"
                )
                signals["section_structure"]["raw_score"] = max(
                    signals["section_structure"]["raw_score"], 0.7
                )
        except Exception:
            pass

    signals["section_structure"]["raw_score"] = round(
        min(1.0, signals["section_structure"]["raw_score"]), 4
    )

    #  3. Import table 
    imports     = data.get("imports", [])
    total_funcs = sum(len(dll.get("functions", [])) for dll in imports)
    all_names   = {
        f.get("name", "").lower()
        for dll in imports
        for f in dll.get("functions", [])
        if f.get("name")
    }

    if total_funcs == 0:
        signals["import_table"]["raw_score"] = 1.0
        signals["import_table"]["evidence"].append(
            "No imports found — binary almost certainly packed or manually mapped"
        )
    elif total_funcs <= MIN_IMPORT_COUNT_PE:
        signals["import_table"]["raw_score"] = 0.85
        signals["import_table"]["evidence"].append(
            f"Only {total_funcs} import(s) — packed stub IAT"
        )
    elif all_names and all_names.issubset(PACKED_STUB_ONLY_IMPORTS):
        signals["import_table"]["raw_score"] = 0.9
        signals["import_table"]["evidence"].append(
            f"IAT contains only loader primitives: {', '.join(sorted(all_names))} — packed stub"
        )
    elif total_funcs < 10:
        signals["import_table"]["raw_score"] = 0.5
        signals["import_table"]["evidence"].append(
            f"Sparse IAT ({total_funcs} imports) — possible packing"
        )

    #  4. Known signatures 
    for packer, sigs in PACKER_SECTION_SIGS.items():
        for sig in sigs:
            if any(sig in name for name in sec_names):
                if packer not in packer_names:
                    packer_names.append(packer)
                signals["known_signatures"]["evidence"].append(
                    f"Section name matches {packer} signature: '{sig}'"
                )

    # Check pefile's own packer detection warnings
    for warning in data.get("pe_warnings", []):
        if isinstance(warning, str) and any(
            kw in warning.lower() for kw in ["upx", "packer", "packed", "aspack"]
        ):
            signals["known_signatures"]["evidence"].append(f"pefile warning: {warning}")

    if packer_names:
        signals["known_signatures"]["raw_score"] = 1.0
    signals["known_signatures"]["raw_score"] = round(
        min(1.0, signals["known_signatures"]["raw_score"]), 4
    )

    #  5. Header anomalies 
    anomaly_score = 0.0

    # Timestamp
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        import time
        if ts == 0:
            signals["header_anomalies"]["evidence"].append("Timestamp is zero (wiped)")
            anomaly_score = max(anomaly_score, 0.5)
        elif ts > time.time():
            signals["header_anomalies"]["evidence"].append("Timestamp is in the future (forged)")
            anomaly_score = max(anomaly_score, 0.6)
    except Exception:
        pass

    # Overlay present
    if overlay and overlay.get("size", 0) > 0:
        signals["header_anomalies"]["evidence"].append(
            f"Overlay present: {overlay['size']} bytes at offset {overlay.get('offset')}"
        )
        anomaly_score = max(anomaly_score, 0.4)

    # Checksum zero on a non-driver
    try:
        if pe.OPTIONAL_HEADER.CheckSum == 0 and not data.get("basic_info", {}).get("is_driver"):
            signals["header_anomalies"]["evidence"].append("CheckSum is zero")
            anomaly_score = max(anomaly_score, 0.2)
    except Exception:
        pass

    # No debug directory (legitimate software almost always has one)
    if not data.get("debug_info"):
        signals["header_anomalies"]["evidence"].append(
            "No debug directory — stripped binary (common in packed/crimeware)"
        )
        anomaly_score = max(anomaly_score, 0.2)

    # No version info
    if not data.get("version_info"):
        signals["header_anomalies"]["evidence"].append(
            "No version info — common in malware and packed binaries"
        )
        anomaly_score = max(anomaly_score, 0.15)

    # TLS callbacks (pre-entry execution, anti-debug)
    tls = data.get("tls_callbacks", {})
    if tls and tls.get("callbacks"):
        signals["header_anomalies"]["evidence"].append(
            f"TLS callbacks present: {tls['callbacks']} — pre-entry execution (anti-debug)"
        )
        anomaly_score = max(anomaly_score, 0.5)

    signals["header_anomalies"]["raw_score"] = round(min(1.0, anomaly_score), 4)

    #  6. Security absence 
    sec_feats = data.get("security_features", {})
    missing = []
    if not sec_feats.get("ASLR"):
        missing.append("ASLR")
    if not sec_feats.get("DEP"):
        missing.append("DEP")
    if not sec_feats.get("CFG"):
        missing.append("CFG")

    if len(missing) >= 3:
        signals["security_absence"]["raw_score"] = 0.8
        signals["security_absence"]["evidence"].append(
            f"All major mitigations absent: {', '.join(missing)} — consistent with packed/handcrafted binary"
        )
    elif len(missing) >= 2:
        signals["security_absence"]["raw_score"] = 0.5
        signals["security_absence"]["evidence"].append(
            f"Multiple mitigations absent: {', '.join(missing)}"
        )
    elif missing:
        signals["security_absence"]["raw_score"] = 0.2
        signals["security_absence"]["evidence"].append(
            f"Missing: {', '.join(missing)}"
        )

    return _build_verdict(signals, packer_names)


#  ELF assessment 

def assess_packing_elf(elf_data: dict[str, Any]) -> dict[str, Any]:
    """
    Assess packing/protection for an ELF binary.

    Args:
        elf_data: The dict returned by elf_parser.extract_elf().

    Returns:
        Structured packing assessment dict.
    """
    signals: dict[str, dict] = {k: {"raw_score": 0.0, "weight": WEIGHTS[k], "weighted": 0.0, "evidence": []} for k in WEIGHTS}
    packer_names: list[str] = []

    #  1. Entropy 
    entropy_summary = elf_data.get("entropy", {})
    section_entropies = entropy_summary.get("section_entropies", [])

    section_scores = []
    for sec in section_entropies:
        name    = sec.get("name", "?")
        value   = sec.get("entropy", 0.0)
        s       = _entropy_score(value)
        section_scores.append(s)
        if value >= ENTROPY_HIGH:
            signals["entropy"]["evidence"].append(
                f"Section '{name}' entropy {value:.3f} >= {ENTROPY_HIGH} (packed/encrypted)"
            )
        elif value >= ENTROPY_ELEVATED:
            signals["entropy"]["evidence"].append(
                f"Section '{name}' entropy {value:.3f} — elevated"
            )

    file_entropy = entropy_summary.get("file_entropy", 0.0)
    if file_entropy >= ENTROPY_HIGH:
        signals["entropy"]["evidence"].append(
            f"Whole-file entropy {file_entropy:.3f} — strongly suggests packing"
        )
        section_scores.append(1.0)
    elif file_entropy >= ENTROPY_ELEVATED:
        signals["entropy"]["evidence"].append(
            f"Whole-file entropy {file_entropy:.3f} — elevated"
        )
        section_scores.append(0.6)

    if section_scores:
        max_s  = max(section_scores)
        mean_s = sum(section_scores) / len(section_scores)
        signals["entropy"]["raw_score"] = round(min(1.0, 0.6 * max_s + 0.4 * mean_s), 4)

    #  2. Section structure 
    section_headers = elf_data.get("section_headers", [])
    sec_names       = [s.get("name", "").lower() for s in section_headers]

    # Executable + writable segment (W^X)
    for seg in elf_data.get("program_headers", []):
        hdr   = seg.get("header", {})
        flags = hdr.get("p_flags", 0)
        ptype = hdr.get("p_type", "")
        if ptype == "PT_LOAD" and (flags & 0x1) and (flags & 0x2):  # PF_X | PF_W
            signals["section_structure"]["evidence"].append(
                "PT_LOAD segment is both writable and executable (W^X violation)"
            )
            signals["section_structure"]["raw_score"] = max(
                signals["section_structure"]["raw_score"], 0.8
            )

    # No section headers (stripped — UPX and others remove them)
    non_null_sections = [s for s in sec_names if s and s != ""]
    if len(non_null_sections) == 0:
        signals["section_structure"]["evidence"].append(
            "No section headers — likely stripped by packer (UPX does this)"
        )
        signals["section_structure"]["raw_score"] = max(
            signals["section_structure"]["raw_score"], 0.9
        )

    # Single PT_LOAD segment (minimal packed binary)
    load_segs = [
        seg for seg in elf_data.get("program_headers", [])
        if seg.get("header", {}).get("p_type") == "PT_LOAD"
    ]
    if len(load_segs) == 1:
        signals["section_structure"]["evidence"].append(
            "Only one PT_LOAD segment — minimal/packed binary layout"
        )
        signals["section_structure"]["raw_score"] = max(
            signals["section_structure"]["raw_score"], 0.5
        )

    # Suspicious section names
    for name in sec_names:
        if name in SUSPICIOUS_SECTION_NAMES:
            signals["section_structure"]["evidence"].append(
                f"Suspicious section name '{name}'"
            )
            signals["section_structure"]["raw_score"] = max(
                signals["section_structure"]["raw_score"], 0.5
            )

    signals["section_structure"]["raw_score"] = round(
        min(1.0, signals["section_structure"]["raw_score"]), 4
    )

    #  3. Import table 
    dynamic = elf_data.get("dynamic") or []
    needed  = [tag.get("needed", "") for tag in dynamic if tag.get("tag") == "DT_NEEDED"]

    # Symbols
    all_syms = []
    for table in elf_data.get("symbols", []):
        all_syms.extend(table.get("symbols", []))

    imported_syms = [
        s["name"] for s in all_syms
        if s.get("bind") == "STB_GLOBAL" and s.get("section_index") == "SHN_UNDEF" and s.get("name")
    ]

    if len(imported_syms) == 0 and len(needed) == 0:
        signals["import_table"]["raw_score"] = 0.9
        signals["import_table"]["evidence"].append(
            "No dynamic imports or needed libraries — statically packed or self-contained stub"
        )
    elif len(imported_syms) <= 3:
        signals["import_table"]["raw_score"] = 0.6
        signals["import_table"]["evidence"].append(
            f"Only {len(imported_syms)} imported symbol(s) — very sparse for a real binary"
        )
    elif len(needed) == 0 and len(imported_syms) > 0:
        signals["import_table"]["raw_score"] = 0.4
        signals["import_table"]["evidence"].append(
            "No DT_NEEDED entries despite imported symbols — unusual"
        )

    #  4. Known signatures 
    for packer, sigs in PACKER_SECTION_SIGS_ELF.items():
        for sig in sigs:
            if any(sig in name for name in sec_names):
                if packer not in packer_names:
                    packer_names.append(packer)
                signals["known_signatures"]["evidence"].append(
                    f"Section name matches {packer} signature: '{sig}'"
                )

    # UPX leaves a note in the PT_NOTE segment data
    for note in elf_data.get("notes", []):
        raw = note.get("raw", "")
        if "55505821" in raw.lower():  # "UPX!" magic bytes
            if "UPX" not in packer_names:
                packer_names.append("UPX")
            signals["known_signatures"]["evidence"].append(
                "UPX magic bytes found in notes section"
            )

    # Check string content for packer markers
    for s in elf_data.get("strings", {}).get("ascii", [])[:500]:
        sl = s.lower()
        if "upx!" in sl or "$info: this file is packed" in sl:
            if "UPX" not in packer_names:
                packer_names.append("UPX")
            signals["known_signatures"]["evidence"].append(
                f"UPX marker string found: '{s[:60]}'"
            )

    if packer_names:
        signals["known_signatures"]["raw_score"] = 1.0
    signals["known_signatures"]["raw_score"] = round(
        min(1.0, signals["known_signatures"]["raw_score"]), 4
    )

    #  5. Header anomalies 
    anomaly_score = 0.0
    elf_hdr = elf_data.get("elf_header", {})

    # Stripped binary (no symbol table is normal for release, but combined
    # with other signals it strengthens the case)
    has_symtab = any(
        s.get("name") == ".symtab"
        for s in elf_data.get("section_headers", [])
    )
    if not has_symtab:
        signals["header_anomalies"]["evidence"].append(
            "Symbol table (.symtab) absent — stripped binary"
        )
        anomaly_score = max(anomaly_score, 0.2)

    # No DWARF (again, weak alone — strong in combination)
    if not elf_data.get("dwarf"):
        signals["header_anomalies"]["evidence"].append(
            "No DWARF debug info"
        )
        anomaly_score = max(anomaly_score, 0.1)

    # Non-standard interpreter path
    interp = elf_data.get("interpreter", "")
    standard_interps = {
        "/lib/ld-linux.so.2",
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/arm-linux-gnueabihf/ld-linux.so.3",
        "/lib/ld-linux-armhf.so.3",
    }
    if interp and interp not in standard_interps:
        signals["header_anomalies"]["evidence"].append(
            f"Non-standard interpreter: '{interp}' — custom loader"
        )
        anomaly_score = max(anomaly_score, 0.6)

    signals["header_anomalies"]["raw_score"] = round(min(1.0, anomaly_score), 4)

    #  6. Security absence 
    sec = elf_data.get("security", {})
    missing = []
    if not sec.get("pie"):
        missing.append("PIE")
    if not sec.get("nx"):
        missing.append("NX")
    if sec.get("relro") == "none":
        missing.append("RELRO")
    if not sec.get("stack_canary"):
        missing.append("stack canary")

    if len(missing) >= 3:
        signals["security_absence"]["raw_score"] = 0.7
        signals["security_absence"]["evidence"].append(
            f"Multiple mitigations absent: {', '.join(missing)}"
        )
    elif len(missing) >= 2:
        signals["security_absence"]["raw_score"] = 0.4
        signals["security_absence"]["evidence"].append(
            f"Missing: {', '.join(missing)}"
        )
    elif missing:
        signals["security_absence"]["raw_score"] = 0.15
        signals["security_absence"]["evidence"].append(
            f"Missing: {', '.join(missing)}"
        )

    return _build_verdict(signals, packer_names)


#  Shared verdict builder 

def _build_verdict(
    signals: dict[str, dict],
    packer_names: list[str],
) -> dict[str, Any]:
    """
    Compute weighted confidence score, assign verdict tier, build summary.
    """
    final_score = 0.0
    for sig, data in signals.items():
        weighted = round(WEIGHTS[sig] * data["raw_score"], 6)
        data["weighted"] = weighted
        final_score += weighted

    final_score = round(min(1.0, final_score), 6)

    if packer_names or final_score >= 0.75:
        verdict = "packed"
    elif final_score >= 0.55:
        verdict = "likely_packed"
    elif final_score >= 0.35:
        verdict = "possibly_packed"
    else:
        verdict = "clean"

    # Build summary from highest-scoring signals
    summary_lines = []
    for sig in sorted(signals, key=lambda s: signals[s]["raw_score"], reverse=True):
        for ev in signals[sig]["evidence"][:2]:
            summary_lines.append(ev)
        if len(summary_lines) >= 6:
            break

    return {
        "verdict":      verdict,
        "confidence":   final_score,
        "packer_names": packer_names,
        "signals":      signals,
        "summary":      summary_lines,
    }
