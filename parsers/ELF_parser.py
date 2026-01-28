# TODO: Look at Subparse (https://github.com/jstrosch/subparse/blob/main/parser/src/parsers/ELFParser.py) for a starting
#       point in building out this parser to get everything we need for the static analysis and create an output JSON
#       with that information
"""
Structured ELF extractor using pyelftools.

Outputs a JSON document containing:
- ELF header
- Program headers (segments)
- Section headers
- Symbols
- Relocations
- Dynamic section
- Interpreter
- Notes
- DWARF summary
- Derived security features

Usage:
    python3 elf_dump_json.py <binary> [output.json]
"""

import sys
import json
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection


def json_safe(obj):
    """
    Recursively convert pyelftools objects into JSON-serializable types.
    """
    if obj is None:
        return None

    if isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, bytes):
        return obj.hex()

    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]

    # pyelftools enums / containers / fallback
    return str(obj)


def elf_header(elf):
    return dict(elf.header)


def program_headers(elf):
    segments = []
    for seg in elf.iter_segments():
        segments.append(dict(seg.header))
    return segments


def section_headers(elf):
    sections = []
    for sec in elf.iter_sections():
        sections.append({
            "name": sec.name,
            "header": dict(sec.header),
        })
    return sections


def symbols(elf):
    tables = []
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            table = {
                "name": sec.name,
                "symbols": []
            }
            for sym in sec.iter_symbols():
                table["symbols"].append({
                    "name": sym.name,
                    "value": sym["st_value"],
                    "size": sym["st_size"],
                    "type": sym["st_info"]["type"],
                    "bind": sym["st_info"]["bind"],
                    "visibility": sym["st_other"]["visibility"],
                    "section_index": sym["st_shndx"],
                })
            tables.append(table)
    return tables


def relocations(elf):
    relocs = []
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection):
            symtab = elf.get_section(sec["sh_link"])
            entries = []
            for rel in sec.iter_relocations():
                symbol = None
                if symtab and rel["r_info_sym"] != 0:
                    symbol = symtab.get_symbol(rel["r_info_sym"]).name
                entries.append({
                    "offset": rel["r_offset"],
                    "type": rel["r_info_type"],
                    "symbol": symbol,
                    "addend": rel["r_addend"] if rel.is_RELA() else None,
                })
            relocs.append({
                "section": sec.name,
                "entries": entries,
            })
    return relocs


def dynamic_section(elf):
    dyn = elf.get_section_by_name(".dynamic")
    if not dyn:
        return None

    entries = []
    for tag in dyn.iter_tags():
        entry = {"tag": tag.entry.d_tag}
        for k, v in tag.entry.items():
            if k != "d_tag":
                entry[k] = v
        if hasattr(tag, "needed"):
            entry["needed"] = tag.needed
        entries.append(entry)

    return entries


def interpreter(elf):
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_INTERP":
            return seg.data().rstrip(b"\x00").decode(errors="ignore")
    return None


def notes(elf):
    notes = []
    for sec in elf.iter_sections():
        if sec.name.startswith(".note"):
            notes.append({
                "section": sec.name,
                "raw": sec.data().hex(),
            })
    return notes


def dwarf_info(elf):
    if not elf.has_dwarf_info():
        return None

    dwarf = elf.get_dwarf_info()
    cus = []
    for cu in dwarf.iter_CUs():
        cus.append({
            "unit_length": cu["unit_length"],
            "version": cu["version"],
            "addr_size": cu["address_size"],
        })

    return {
        "compilation_units": cus
    }


def security_features(elf):
    features = {}

    # NX
    nx = True
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            nx = not (seg.header.p_flags & 0x1)
    features["nx"] = nx

    # PIE
    features["pie"] = elf.header.e_type == "ET_DYN"

    # RELRO
    has_relro = any(
        seg.header.p_type == "PT_GNU_RELRO"
        for seg in elf.iter_segments()
    )
    bind_now = False
    dyn = elf.get_section_by_name(".dynamic")
    if dyn:
        bind_now = any(
            tag.entry.d_tag == "DT_BIND_NOW"
            for tag in dyn.iter_tags()
        )
    features["relro"] = (
        "full" if has_relro and bind_now
        else "partial" if has_relro
        else "none"
    )

    # Stack canary (heuristic)
    canary = False
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if sym.name == "__stack_chk_fail":
                    canary = True
    features["stack_canary"] = canary

    return features


def extract_elf(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)

        return {
            "elf_header": elf_header(elf),
            "program_headers": program_headers(elf),
            "section_headers": section_headers(elf),
            "symbols": symbols(elf),
            "relocations": relocations(elf),
            "dynamic": dynamic_section(elf),
            "interpreter": interpreter(elf),
            "notes": notes(elf),
            "dwarf": dwarf_info(elf),
            "security": security_features(elf),
        }


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage: {sys.argv[0]} <elf_binary> [output.json]")
        sys.exit(1)

    binary = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) == 3 else None

    data = extract_elf(binary)
    json_output = json.dumps(json_safe(data), indent=2)

    if output:
        with open(output, "w") as f:
            f.write(json_output)
    else:
        print(json_output)


if __name__ == "__main__":
    main()
