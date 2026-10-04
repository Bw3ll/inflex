import os
import sys
import subprocess
import json
import hashlib
import re
import platform
import tempfile
from pathlib import Path

HEX_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')

# Which WSL distro to use when invoking wsl -d <distro>
WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")
try:
    print(f"[+] Using WSL distro: {WSL_DISTRO}")
except Exception:
    pass

# Format-aware filtering

# PE — MSVC CRT + runtime internals that get statically linked in.
# These all appear as plain sym.* (no imp./plt.) because they are baked in.
# We do NOT include "sym._" here — that would break any C++ PE compiled with
# a name-mangling compiler (clang-cl, mingw).
PE_SKIP_PREFIXES = (
    "sym.__scrt",           # MSVC startup/runtime scaffolding
    "sym.__vcrt",           # VC runtime internals
    "sym._RTC_",            # Runtime checks (debug builds)
    "sym.__security",       # Stack cookie: __security_check_cookie etc.
    "sym.__CxxFrame",       # C++ SEH frame handler
    "sym.__std_",           # STL internals exposed as symbols
    "sym.__acrt",           # AppCRT internals
    "sym.__p__",            # CRT per-process/thread state accessors
    "sym._invalid_",        # CRT invalid-parameter handler stubs
    "sym.__stdio_",         # CRT stdio init
    "sym.__crt_",           # Generic CRT helpers
    "sym.__mingw",          # MinGW runtime (kept from original)
    "sym.__",               # All double-underscore CRT/ABI symbols
)

# ELF — only genuine external stubs; C++ mangled names (sym._Z...) are user code.
ELF_SKIP_PREFIXES = (
    "sym.imp.",             # PLT import stubs
    "sym.plt.",             # PLT stubs (alternate naming)
    "method.std::",         # STL internals that r2 names as method.std::
    "method.void_std::",    # STL void-returning methods
    "method.unsigned_",     # STL unsigned type methods
    "method.__gnu_cxx::",   # GCC internal STL methods
    "method.__cxxabiv",     # C++ ABI methods
    "fcn.GLIBC",            # glibc versioned stubs
)

# Shared across both formats — always skip these
UNIVERSAL_SKIP_PREFIXES = (
    "imp.",                 # Generic import prefix
    "plt.",                 # Generic PLT prefix
    "sym.__imp",            # MSVC import thunks
    "sym.__imp_",
)

UNIVERSAL_SKIP_NAMES = (
    "entry0",
    "entry",
)

# Function size floor — below this a function is almost certainly a stub or
# padding, not real logic worth hashing.
PE_MIN_FUNC_SIZE  = 30   # PE: MSVC CRT stubs are 5-15 bytes; 30 is safe
ELF_MIN_FUNC_SIZE = 10   # ELF: user functions can be small; 10 avoids false drops

# If a .data section has entropy above this threshold we assume it contains
# embedded binary data (e.g. objcopy'd PNG) and tell r2 to skip it.
DATA_ENTROPY_SKIP_THRESHOLD = 7.5

# Maximum pdfj calls written into a single r2 script file per batch.
PDFJ_BATCH_SIZE = 200


# Environment detection

def detect_environment() -> str:
    """
    Detect if we're running on WSL, native Linux, or Windows.
    Returns: 'WSL', 'Linux', 'Windows', or 'Other'
    """
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/version", "r") as f:
                version = f.read().lower()
                if "microsoft" in version or "wsl" in version:
                    return "WSL"
                return "Linux"
        except Exception:
            return "Linux"
    elif system == "Windows":
        return "Windows"
    return "Other"


def check_radare2_available(env_type: str) -> bool:
    """Check if radare2 is available in the current environment."""
    try:
        if env_type in ["Linux", "WSL"]:
            result = subprocess.run(["r2", "-v"], capture_output=True, timeout=5)
            return result.returncode == 0
        elif env_type == "Windows":
            result = subprocess.run(
                ["wsl", "-d", WSL_DISTRO, "which", "r2"],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        return False
    except Exception as e:
        print(f"[-] Error checking radare2: {e}")
        return False


def to_wsl_path(win_path: str) -> str:
    """Convert a Windows path to a WSL /mnt/<drive>/... path."""
    try:
        p = Path(win_path).resolve()
    except Exception:
        p = Path(win_path)

    drive, tail = os.path.splitdrive(str(p))
    if not drive:
        return str(p).replace('\\', '/')

    drive_letter = drive.rstrip(":").lower()
    tail_posix = tail.replace('\\', '/')
    if not tail_posix.startswith('/'):
        tail_posix = '/' + tail_posix
    return f"/mnt/{drive_letter}{tail_posix}"


# Binary format detection

def detect_binary_format(binary_path: str) -> str:
    """
    Detect binary format from magic bytes.
    Returns: 'PE', 'ELF', 'MACHO', or 'UNKNOWN'
    """
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"\x4D\x5A":
            return "PE"
        if magic == b"\x7F\x45\x4C\x46":
            return "ELF"
        if magic in (b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF",
                     b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"):
            return "MACHO"
    except Exception:
        pass
    return "UNKNOWN"


def _get_high_entropy_data_sections(binary_path: str) -> list[str]:
    """
    Read the static analysis section table from an already-parsed report if
    available, or fall back to reading the raw ELF section headers directly.

    Returns a list of section names whose entropy exceeds
    DATA_ENTROPY_SKIP_THRESHOLD and which are writable (i.e. data, not code).

    This is used to tell r2 to skip embedded binary blobs (e.g. a PNG baked
    in via objcopy) that would otherwise slow analysis and pollute string
    results.
    """
    # Fast path: parse ELF section headers directly using readelf-style
    # approach — read the raw bytes so we have no extra dependencies.
    # We only need section names + entropy, so we compute Shannon entropy
    # ourselves over each section's raw bytes.
    suspicious = []
    try:
        import math
        import struct

        with open(binary_path, "rb") as f:
            raw = f.read()

        # ELF header: e_shoff (8 bytes @ 0x28 for 64-bit), e_shentsize, e_shnum, e_shstrndx
        if raw[:4] != b"\x7F\x45\x4C\x46":
            return []

        ei_class = raw[4]  # 1=32bit, 2=64bit
        if ei_class == 2:  # 64-bit
            e_shoff     = struct.unpack_from("<Q", raw, 0x28)[0]
            e_shentsize = struct.unpack_from("<H", raw, 0x3A)[0]
            e_shnum     = struct.unpack_from("<H", raw, 0x3C)[0]
            e_shstrndx  = struct.unpack_from("<H", raw, 0x3E)[0]
            def read_shdr(i):
                base = e_shoff + i * e_shentsize
                sh_name    = struct.unpack_from("<I", raw, base + 0x00)[0]
                sh_type    = struct.unpack_from("<I", raw, base + 0x04)[0]
                sh_flags   = struct.unpack_from("<Q", raw, base + 0x08)[0]
                sh_offset  = struct.unpack_from("<Q", raw, base + 0x18)[0]
                sh_size    = struct.unpack_from("<Q", raw, base + 0x20)[0]
                return sh_name, sh_type, sh_flags, sh_offset, sh_size
        else:  # 32-bit
            e_shoff     = struct.unpack_from("<I", raw, 0x20)[0]
            e_shentsize = struct.unpack_from("<H", raw, 0x2E)[0]
            e_shnum     = struct.unpack_from("<H", raw, 0x30)[0]
            e_shstrndx  = struct.unpack_from("<H", raw, 0x32)[0]
            def read_shdr(i):
                base = e_shoff + i * e_shentsize
                sh_name    = struct.unpack_from("<I", raw, base + 0x00)[0]
                sh_type    = struct.unpack_from("<I", raw, base + 0x04)[0]
                sh_flags   = struct.unpack_from("<I", raw, base + 0x08)[0]
                sh_offset  = struct.unpack_from("<I", raw, base + 0x10)[0]
                sh_size    = struct.unpack_from("<I", raw, base + 0x14)[0]
                return sh_name, sh_type, sh_flags, sh_offset, sh_size

        # Read string table section
        strtab_name, _, _, strtab_off, strtab_size = read_shdr(e_shstrndx)
        strtab = raw[strtab_off: strtab_off + strtab_size]

        def get_name(sh_name):
            end = strtab.index(b'\x00', sh_name)
            return strtab[sh_name:end].decode("utf-8", errors="replace")

        SHF_WRITE   = 0x1
        SHF_EXECINSTR = 0x4

        for i in range(e_shnum):
            sh_name, sh_type, sh_flags, sh_offset, sh_size = read_shdr(i)
            if sh_size < 4096:
                continue
            is_writable   = bool(sh_flags & SHF_WRITE)
            is_executable = bool(sh_flags & SHF_EXECINSTR)
            if not is_writable or is_executable:
                continue  # only care about writable non-exec data sections

            name = get_name(sh_name)
            section_bytes = raw[sh_offset: sh_offset + sh_size]
            if not section_bytes:
                continue

            # Shannon entropy
            counts = [0] * 256
            for b in section_bytes:
                counts[b] += 1
            entropy = 0.0
            length = len(section_bytes)
            for c in counts:
                if c:
                    p = c / length
                    entropy -= p * math.log2(p)

            if entropy >= DATA_ENTROPY_SKIP_THRESHOLD:
                print(f"[+] High-entropy data section detected: {name} "
                      f"(entropy={entropy:.3f}, size={sh_size} bytes) — "
                      f"will exclude from r2 analysis")
                suspicious.append(name)

    except Exception as e:
        print(f"[!] Could not inspect ELF sections for entropy: {e}")

    return suspicious


# r2 command builders

def _build_r2_cmd_inline(env_type: str, binary_path: str, r2_cmds: str) -> list:
    """
    Build a radare2 command that passes commands via -c (inline string).

    IMPORTANT: We do NOT pass -A/-AA as a CLI flag.  When -A is a flag, r2
    runs aaa *before* processing any -c commands, so any configuration we put
    in r2_cmds (e bin.demangle, omf rw- ...) fires too late and can segfault.
    Instead, r2_cmds must embed the analysis command explicitly in the right
    order:
        e scr.pager=false; e bin.demangle=true; omf rw- .data; aaa; aflj; q
    This guarantees: configure -> map-edit -> analyse -> query.
    We pass -n (no analysis) so r2 opens the file without auto-analysing.
    """
    if env_type in ["Linux", "WSL"]:
        return ["r2", "-n", "-q", "-c", r2_cmds, binary_path]
    elif env_type == "Windows":
        wsl_path = to_wsl_path(binary_path)
        return ["wsl", "-d", WSL_DISTRO, "r2", "-n", "-q", "-c",
                r2_cmds, wsl_path]
    else:
        raise RuntimeError(f"Unsupported environment: {env_type}")


def _build_r2_cmd_script(env_type: str, binary_path: str, script_path: str) -> list:
    """
    Build a radare2 command that reads commands from a script file via -i.

    Same -n rationale as _build_r2_cmd_inline: the script file is responsible
    for running aaa at the right point in the sequence.  Every batch script
    must therefore include 'aaa' before any 'pdfj @' calls.
    """
    if env_type in ["Linux", "WSL"]:
        return ["r2", "-n", "-q", "-i", script_path, binary_path]
    elif env_type == "Windows":
        wsl_path = to_wsl_path(binary_path)
        return ["wsl", "-d", WSL_DISTRO, "r2", "-n", "-q", "-i",
                script_path, wsl_path]
    else:
        raise RuntimeError(f"Unsupported environment: {env_type}")


# r2 output parsers

def _parse_multiple_pdfj(raw: str) -> list:
    """
    Parse multiple top-level JSON objects from concatenated pdfj stdout.

    r2 emits one JSON object per pdfj call with no delimiter between them.
    Track brace depth manually to find each top-level object boundary.
    """
    results = []
    depth = 0
    start = None

    for i, ch in enumerate(raw):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                chunk = raw[start:i + 1]
                try:
                    obj = json.loads(chunk)
                    if "ops" in obj:
                        results.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None

    return results


def _parse_izj_output(raw: str) -> list[dict]:
    """
    Parse izj / izzj JSON output into normalised { va, va_int, string, size, type } records.
    """
    try:
        records = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if not isinstance(records, list):
        return []

    cleaned = []
    seen_vas: set[int] = set()

    for rec in records:
        vaddr  = rec.get("vaddr") or rec.get("paddr")
        string = rec.get("string", "")
        size   = rec.get("size", 0)
        stype  = rec.get("type", "ascii")

        if not string or not isinstance(string, str):
            continue
        if len(string.strip()) < 3:
            continue
        if vaddr is None:
            continue

        try:
            va_int = int(vaddr) if isinstance(vaddr, int) else int(str(vaddr), 16)
        except (ValueError, TypeError):
            continue

        if va_int == 0:
            continue
        if va_int in seen_vas:
            continue
        seen_vas.add(va_int)

        cleaned.append({
            "va":     hex(va_int),
            "va_int": va_int,
            "string": string,
            "size":   size,
            "type":   stype,
        })

    return cleaned


# Normalisation

def normalize_op_str(op: dict) -> str:
    """
    Normalise an r2 op dict by replacing all immediates with CONST.
    This makes function hashes format/address-independent.
    """
    disasm = op.get("disasm") or op.get("opcode") or ""
    norm = HEX_RE.sub("CONST", disasm)
    norm = norm.replace(",", " ").strip()
    return norm.lower()


# Temp script helpers (WSL-aware)

def _write_wsl_temp_script(script_content: str, env_type: str) -> str | None:
    """
    Write an r2 script to a temp file accessible from within WSL.

    On Windows, Python's tempfile module resolves '/tmp' to 'C:\\tmp' which
    does not exist in the WSL filesystem.  We ask WSL to create the file via
    'wsl mktemp' and write content via 'wsl tee' so the path is a real Linux
    path that r2 inside WSL can open.

    On Linux/WSL Python runs natively so tempfile works as expected.
    """
    if env_type == "Windows":
        try:
            mktemp_result = subprocess.check_output(
                ["wsl", "-d", WSL_DISTRO, "mktemp", "/tmp/inflex_pdfj_XXXXXX.r2"],
                encoding="utf-8", timeout=10,
            ).strip()
            subprocess.run(
                ["wsl", "-d", WSL_DISTRO, "tee", mktemp_result],
                input=script_content,
                encoding="utf-8",
                capture_output=True,
                timeout=15,
                check=True,
            )
            return mktemp_result
        except Exception as e:
            print(f"[-] Failed to create WSL temp script: {e}")
            return None
    else:
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".r2", prefix="inflex_pdfj_",
                dir="/tmp", delete=False, encoding="utf-8",
            ) as tf:
                tf.write(script_content)
                return tf.name
        except Exception as e:
            print(f"[-] Failed to create temp script: {e}")
            return None


def _delete_wsl_temp_script(script_path: str, env_type: str):
    """Delete a temp script created by _write_wsl_temp_script. Best-effort."""
    try:
        if env_type == "Windows":
            subprocess.run(
                ["wsl", "-d", WSL_DISTRO, "rm", "-f", script_path],
                capture_output=True, timeout=10,
            )
        else:
            if os.path.exists(script_path):
                os.remove(script_path)
    except Exception:
        pass


# r2 analysis passes

def run_radare2_aflj(binary_path: str, env_type: str,
                     fmt: str = "UNKNOWN",
                     skip_sections: list[str] | None = None) -> list:
    """
    Run a single radare2 session to collect the function list (aflj).

    Format-aware behaviour:
      PE  — uses -A (aaa).  MSVC binaries are well-structured; -AA adds
            little for static analysis and is much slower.
      ELF — uses -A (aaa) with demangling enabled.  High-entropy data
            sections (e.g. objcopy-embedded PNGs) are pre-marked non-exec
            so r2 does not waste time scanning them.

    Args:
        binary_path:   Path to the binary.
        env_type:      Environment type string.
        fmt:           'PE', 'ELF', or 'UNKNOWN'.
        skip_sections: List of section names to mark non-exec before analysis
                       (ELF only — ignored for PE).

    Returns:
        List of function dicts from aflj, or [] on failure.
    """
    # Build the command sequence in the correct order:
    #   1. configure  (pager off, demangling)
    #   2. omf rw-    (strip exec flag from blob sections — MUST precede aaa)
    #   3. aaa        (full analysis — runs after maps are edited)
    #   4. aflj       (dump function list as JSON)
    #   5. q          (quit)
    # We open r2 with -n (no auto-analysis) so step 3 fires at exactly the
    # right point and not before our omf edits.
    pre = ["e scr.pager=false"]

    if fmt == "ELF":
        pre.append("e bin.demangle=true")
        if skip_sections:
            # omf segfaults in r2 5.5.x on ELF maps. Use anal.datasec=false
            # instead — it tells aaa to skip data-flagged sections entirely,
            # which covers the objcopy-embedded .data blob (hill.png).
            pre.append("e anal.datasec=false")

    r2_cmds = "; ".join(pre) + "; aaa; aflj; q"

    try:
        cmd = _build_r2_cmd_inline(env_type, binary_path, r2_cmds)
        output = subprocess.check_output(cmd, encoding="utf-8", timeout=240)

        # r2 may emit warnings before the JSON — find the first '['
        json_start = output.find('[')
        if json_start == -1:
            print(f"[-] aflj returned no JSON array")
            return []
        return json.loads(output[json_start:])

    except subprocess.TimeoutExpired:
        print(f"[-] Radare2 aflj timed out for {binary_path}")
        return []
    except json.JSONDecodeError as e:
        print(f"[-] Failed to parse aflj output: {e}")
        return []
    except Exception as e:
        print(f"[-] Failed to run radare2 aflj: {e}")
        return []


def run_radare2_izj(binary_path: str, env_type: str,
                    fmt: str = "UNKNOWN",
                    skip_sections: list[str] | None = None) -> list[dict]:
    """
    Extract all strings with virtual addresses via izj + izzj in one r2 session.

    izj  — strings in data sections (.rdata / .rodata)
    izzj — strings in ALL sections including .text

    Both are needed because in compiled PE/ELF binaries:
      - String *literals* live in .rdata / .rodata (izj captures these)
      - Some string-like data lives inside .text (izzj captures these)
    The ptr-based attribution in _attribute_strings_to_functions uses the
    merged VA corpus from both passes.

    ELF-specific: demangling and section exclusions are applied here too so
    string VAs from high-entropy blobs do not pollute the lookup table.
    """
    SENTINEL = "__INFLEX_SPLIT__"

    # Same configure -> omf -> aaa ordering as aflj.
    # String extraction (izj/izzj) needs aaa to have run so that r2 has
    # mapped all sections and resolved relocations.
    pre = ["e scr.pager=false"]
    if fmt == "ELF":
        pre.append("e bin.demangle=true")
        if skip_sections:
            pre.append("e anal.datasec=false")

    r2_cmds = "; ".join(pre) + f'; aaa; izj; "!echo {SENTINEL}"; izzj; q'

    try:
        cmd = _build_r2_cmd_inline(env_type, binary_path, r2_cmds)
        raw = subprocess.check_output(cmd, encoding="utf-8", timeout=240)

        parts    = raw.split(SENTINEL, 1)
        izj_raw  = parts[0].strip() if parts else ""
        izzj_raw = parts[1].strip() if len(parts) > 1 else ""

        izj_records  = _parse_izj_output(izj_raw)
        izzj_records = _parse_izj_output(izzj_raw)

        existing_vas = {r["va_int"] for r in izj_records}
        merged = list(izj_records)
        for rec in izzj_records:
            if rec["va_int"] not in existing_vas:
                merged.append(rec)
                existing_vas.add(rec["va_int"])

        print(
            f"[+] String VA extraction: {len(izj_records)} from izj (data), "
            f"{len(izzj_records)} from izzj (all sections), "
            f"{len(merged)} unique total"
        )
        return merged

    except subprocess.TimeoutExpired:
        print(f"[-] Radare2 izj/izzj timed out for {binary_path}")
        return []
    except Exception as e:
        print(f"[-] Failed to run radare2 izj/izzj: {e}")
        return []


def run_radare2_all_pdfj(binary_path: str, filtered_funcs: list,
                          env_type: str,
                          fmt: str = "UNKNOWN",
                          skip_sections: list[str] | None = None) -> list:
    """
    Disassemble all filtered functions using batched r2 script-file sessions.

    Each batch writes its commands to a WSL-accessible temp file and invokes
    r2 with -n -i <script_path>.  The command line stays O(1) regardless of
    function count, resolving WinError 206.

    r2 is opened with -n (no auto-analysis).  Every batch script therefore
    embeds the full setup sequence:
        configure -> omf -> aaa -> pdfj calls -> q
    This is the same ordering used by aflj/izj and avoids the segfault caused
    by omf firing after aaa when -A is a CLI flag.
    """
    if not filtered_funcs:
        return []

    total         = len(filtered_funcs)
    total_batches = (total + PDFJ_BATCH_SIZE - 1) // PDFJ_BATCH_SIZE
    all_results   = []

    print(f"[+] Disassembling {total} functions in {total_batches} batch(es) "
          f"of up to {PDFJ_BATCH_SIZE} using r2 script files (-n -i)")

    # Preamble lines written at the top of every batch script.
    # configure -> omf -> aaa  — in that order.
    batch_pre = ["e scr.pager=false"]
    if fmt == "ELF":
        batch_pre.append("e bin.demangle=true")
        if skip_sections:
            batch_pre.append("e anal.datasec=false")
    batch_pre.append("aaa")   # analysis runs AFTER all config is applied

    for batch_idx, batch_start in enumerate(range(0, total, PDFJ_BATCH_SIZE), start=1):
        batch       = filtered_funcs[batch_start: batch_start + PDFJ_BATCH_SIZE]
        end_display = min(batch_start + PDFJ_BATCH_SIZE, total)

        print(f"[+] Batch {batch_idx}/{total_batches}: "
              f"functions {batch_start + 1}-{end_display} of {total}")

        script_lines  = list(batch_pre)
        script_lines += [f"pdfj @ {f['offset']}" for f in batch]
        script_lines.append("q")
        script_content = "\n".join(script_lines) + "\n"

        script_file = None
        try:
            script_file = _write_wsl_temp_script(script_content, env_type)
            if not script_file:
                print(f"[-] Batch {batch_idx}/{total_batches}: "
                      f"could not create temp script — skipping")
                continue

            cmd = _build_r2_cmd_script(env_type, binary_path, script_file)
            raw = subprocess.check_output(cmd, encoding="utf-8", timeout=300)
            batch_results = _parse_multiple_pdfj(raw)
            all_results.extend(batch_results)
            print(f"[+] Batch {batch_idx}/{total_batches}: "
                  f"got {len(batch_results)} function(s)")

        except subprocess.TimeoutExpired:
            print(f"[-] Batch {batch_idx}/{total_batches} timed out — skipping")
        except Exception as e:
            print(f"[-] Batch {batch_idx}/{total_batches} failed: {e}")
        finally:
            if script_file:
                _delete_wsl_temp_script(script_file, env_type)

    print(f"[+] All batches complete: {len(all_results)} function(s) disassembled total")
    return all_results


# String attribution

def _attribute_strings_to_functions(
    functions: list[dict],
    strings_with_va: list[dict],
    raw_ops_by_addr: dict[int, list[dict]],
) -> list[dict]:
    """
    Annotate each function with the strings it references via r2's 'ptr' field.

    In compiled PE/ELF binaries string data lives in a separate section
    (.rdata / .rodata).  VA-range containment therefore misses all of them.
    r2 records the resolved target address in the 'ptr' field of each op that
    loads or pushes an address — we use that to attribute strings correctly.

    This works identically for PE and ELF.
    """
    if not strings_with_va:
        return [{**f, "strings_referenced": []} for f in functions]

    va_to_string: dict[int, str] = {
        rec["va_int"]: rec["string"] for rec in strings_with_va
    }

    annotated = []
    for func in functions:
        try:
            func_addr = int(func["offset"], 16)
        except (KeyError, ValueError):
            annotated.append({**func, "strings_referenced": []})
            continue

        raw_ops = raw_ops_by_addr.get(func_addr, [])
        found: list[str] = []
        seen:  set[int]  = set()

        for op in raw_ops:
            ptr = op.get("ptr")
            if ptr is None:
                continue
            try:
                ptr_int = int(ptr) & 0xFFFFFFFFFFFFFFFF
            except (TypeError, ValueError):
                continue

            if ptr_int in seen:
                continue

            string_val = va_to_string.get(ptr_int)
            if string_val:
                found.append(string_val)
                seen.add(ptr_int)

        annotated.append({**func, "strings_referenced": found})

    total_refs        = sum(len(f["strings_referenced"]) for f in annotated)
    funcs_with_strings = sum(1 for f in annotated if f["strings_referenced"])
    print(f"[+] String attribution (ptr-based): {total_refs} reference(s) "
          f"across {funcs_with_strings}/{len(annotated)} function(s)")

    return annotated


# Format-aware function filtering

def _build_skip_prefixes(fmt: str) -> tuple:
    """
    Return the combined tuple of skip prefixes for the given format.

    PE:  MSVC CRT prefixes + universal prefixes
    ELF: ELF-specific prefixes (method.std:: etc.) + universal prefixes
         NOTE: "sym._" is intentionally excluded — sym._Z... are user C++
         functions in ELF and must not be filtered.
    """
    if fmt == "PE":
        return PE_SKIP_PREFIXES + UNIVERSAL_SKIP_PREFIXES
    elif fmt == "ELF":
        return ELF_SKIP_PREFIXES + UNIVERSAL_SKIP_PREFIXES
    else:
        # Unknown format: use a conservative union of both sets
        return PE_SKIP_PREFIXES + ELF_SKIP_PREFIXES + UNIVERSAL_SKIP_PREFIXES


def _is_library_function(func: dict, fmt: str) -> bool:
    """
    Return True if this function should be excluded from analysis.

    Checks:
      1. r2 'type' field — anything other than 'fcn' is a stub/import/loc.
      2. Name prefix against the format-appropriate skip list.
      3. Exact name against UNIVERSAL_SKIP_NAMES.

    The key fix vs the original: "sym._" is NOT in the ELF skip list, so
    C++ mangled names like sym._ZN...main... are correctly kept.
    """
    func_type = func.get("type")
    if func_type and func_type != "fcn":
        return True

    name = func.get("name") or func.get("demname") or ""
    if not isinstance(name, str):
        return False

    if name in UNIVERSAL_SKIP_NAMES:
        return True

    skip_prefixes = _build_skip_prefixes(fmt)
    if name.startswith(skip_prefixes):
        return True

    return False


# Main extraction pipeline

def extract_function_hashes(binary_path: str, env_type: str):
    """
    Extract function hashes from a binary using radare2.

    Workflow:
        1. Detect binary format (PE / ELF)
        2. ELF only: identify high-entropy data sections to exclude
        3. One r2 -A session  ->  aflj  (full analysis + function list)
        4. Filter functions (format-aware — see _is_library_function)
        5. One r2 -A session  ->  izj + izzj  (strings with VAs)
        6. Batched r2 -A -i <script> sessions  ->  pdfj per batch
        7. Normalise opcodes and hash each function
        8. Attribute strings to functions via ptr cross-references

    Returns:
        Dict with disassembly data, or None on failure.
    """
    print(f"[+] Running radare2 analysis on: {binary_path}")
    print(f"[+] Environment: {env_type}")

    if not check_radare2_available(env_type):
        print(f"[-] radare2 is not available in {env_type} environment")
        return None

    #  Step 1: detect format 
    fmt = detect_binary_format(binary_path)
    print(f"[+] Detected binary format: {fmt}")

    min_func_size = PE_MIN_FUNC_SIZE if fmt == "PE" else ELF_MIN_FUNC_SIZE

    #  Step 2: ELF — find high-entropy sections to exclude 
    skip_sections: list[str] = []
    if fmt == "ELF":
        skip_sections = _get_high_entropy_data_sections(binary_path)
        if skip_sections:
            print(f"[+] Will exclude {len(skip_sections)} high-entropy section(s) "
                  f"from r2 analysis: {skip_sections}")

    #  Step 3: full analysis + function list 
    print(f"[+] Step 1/3: Collecting function list via aflj (-A)...")
    aflj_out = run_radare2_aflj(binary_path, env_type, fmt, skip_sections)
    if not aflj_out:
        print(f"[-] No functions found or analysis failed")
        return None

    print(f"[+] r2 returned {len(aflj_out)} raw function entries")

    #  Step 4: format-aware filtering 
    filtered = []
    skipped_library = 0
    skipped_size    = 0

    for f in aflj_out:
        addr = f.get("offset")
        name = f.get("name") or f.get("demname") or f"func_{addr:x}"
        size = f.get("size", 0)

        if _is_library_function(f, fmt):
            skipped_library += 1
            continue
        if size < min_func_size:
            skipped_size += 1
            continue

        filtered.append({
            "offset": addr,
            "name":   name,
            "size":   size,
        })

    print(f"[+] {len(filtered)} functions remain after filtering "
          f"({skipped_library} library/stub, {skipped_size} below {min_func_size}b size threshold)")

    if not filtered:
        print(f"[-] No functions passed the filter")
        return None

    #  Step 5: extract strings with virtual addresses 
    print(f"[+] Step 2/3: Extracting strings with VAs via izj + izzj (-A)...")
    strings_with_va = run_radare2_izj(binary_path, env_type, fmt, skip_sections)

    #  Step 6: batched pdfj 
    print(f"[+] Step 3/3: Disassembling {len(filtered)} functions "
          f"in batched script-file sessions (-A -i)...")
    pdfj_results = run_radare2_all_pdfj(
        binary_path, filtered, env_type, fmt, skip_sections
    )

    if not pdfj_results:
        print(f"[-] Disassembly returned no results")
        return None

    offset_to_meta = {f["offset"]: f for f in filtered}

    #  Step 7: normalise + hash; preserve raw ops for string attribution 
    results: list[dict]              = []
    raw_ops_by_addr: dict[int, list] = {}

    for fj in pdfj_results:
        ops = fj.get("ops") or []
        if not ops:
            continue

        addr = fj.get("addr", 0)
        meta = offset_to_meta.get(addr, {})
        name = meta.get("name") or f"func_{addr:x}"
        size = meta.get("size", 0)

        raw_ops_by_addr[addr] = ops

        normalized_ops = [normalize_op_str(op) for op in ops]
        normalized_ops = [ln for ln in normalized_ops if ln.strip()]

        if not normalized_ops:
            continue

        opcode_blob = "\n".join(normalized_ops)
        func_hash   = hashlib.sha256(opcode_blob.encode("utf-8")).hexdigest()

        results.append({
            "name":      name,
            "offset":    hex(addr),
            "size":      size,
            "func_hash": func_hash,
            "mnemonics": normalized_ops,
        })

    print(f"[+] Extracted {len(results)} functions with hashes")

    #  Step 8: attribute strings via ptr cross-references 
    results = _attribute_strings_to_functions(results, strings_with_va, raw_ops_by_addr)

    return {
        "functions":        results,
        "function_count":   len(results),
        "strings_with_va":  strings_with_va,
        "similar_binaries": [],
        "binary_format":    fmt,
    }


# Shellcode / non-PE/ELF file support

def extract_shellcode_from_text(file_path: str) -> bytes | None:
    r"""Extract shellcode bytes from a text file containing \xHH sequences."""
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        text    = raw.decode("utf-8", errors="ignore")
        matches = re.findall(r"\\x([0-9a-fA-F]{2})", text)
        if len(matches) < 8:
            return None
        extracted = bytes(int(b, 16) for b in matches)
        return extracted if len(extracted) >= 16 else None
    except Exception:
        return None


def is_executable_file(file_path: str) -> bool:
    """Check if file is a PE, ELF, or Mach-O executable."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"\x4D\x5A":
            return True
        if magic == b"\x7F\x45\x4C\x46":
            return True
        if magic in (b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF",
                     b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"):
            return True
        return False
    except Exception:
        return False


# Similarity check (unchanged from original)

def _run_similarity_check(
    disassembly_data: dict,
    full_report: dict,
    results_dir: Path,
    min_overlap: int = 1,
    shared_functions_report_dir: Path | None = None,
):
    try:
        from static_analysis.function_simularity import compare_single_report
    except ImportError:
        print("[!] function_simularity.py not found — skipping function similarity check.")
        compare_single_report = None

    if not results_dir.is_dir():
        print(f"[*] Results directory does not exist yet ({results_dir}), "
              f"skipping similarity checks.")
        return

    if shared_functions_report_dir is None:
        shared_functions_report_dir = results_dir / "shared_functions"

    function_matches = []
    if compare_single_report:
        print(f"[+] Running FUNCTION similarity check against: {results_dir}")
        function_matches = compare_single_report(
            full_report,
            results_dir,
            min_overlap=min_overlap,
            shared_functions_report_dir=shared_functions_report_dir,
        )

    disassembly_data["similarity"] = {
        "function_similarity": function_matches,
    }


def _enrich_functions_with_similarity(disassembly_data: dict):
    """Inject similarity references into each function entry."""
    similarity = disassembly_data.get("similarity", {})
    matches    = similarity.get("function_similarity", [])
    if not matches:
        return

    func_hash_map: dict[str, list] = {}
    for m in matches:
        for sf in m.get("shared_functions", []):
            func_hash = sf.get("func_hash")
            if not func_hash:
                continue
            func_hash_map.setdefault(func_hash, []).append({
                "binary_id":              m.get("binary_id"),
                "sha256":                 m.get("sha256"),
                "report_path":            m.get("report_path"),
                "matched_function_name":  sf.get("name") or sf.get("function_name"),
                "matched_offset":         sf.get("offset"),
                "matched_strings":        sf.get("strings_referenced", []),
                "matched_techniques":     sf.get("techniques", []),
            })

    for f in disassembly_data.get("functions", []):
        h = f.get("func_hash")
        f["similar_occurrences"] = func_hash_map.get(h, [])


# Public entry point

def process_disassembly(
    binary_path: str,
    results_dir: str = "results",
    full_report: dict = None,
    min_overlap: int = 1,
    skip_similarity: bool = False,
):
    """
    Extract disassembly data from a binary and optionally compare it against
    existing reports in results_dir.

    Args:
        binary_path:     Path to the binary file.
        results_dir:     Directory containing existing report JSONs.
        full_report:     Complete report dict being built for this binary.
                         Must include ingest_analysis for the similarity check.
        min_overlap:     Minimum shared function count to flag a match.
        skip_similarity: Set True to skip the similarity check entirely.

    Returns:
        Dictionary with disassembly data, or None on failure.
    """
    binary_path = Path(binary_path)
    results_dir = Path(results_dir)

    if not binary_path.exists():
        print(f"[-] Binary not found: {binary_path}")
        return None

    fallback_source = None
    temp_path       = None

    if not is_executable_file(str(binary_path)):
        extracted = extract_shellcode_from_text(str(binary_path))
        if extracted:
            print(f"[+] Detected embedded shellcode in script/text file: {binary_path}")
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
            temp_file.write(extracted)
            temp_file.close()
            temp_path       = temp_file.name
            fallback_source = temp_path
            print(f"[+] Written extracted shellcode to: {temp_path}")
        else:
            print(f"[*] File is not an executable — skipping disassembly: {binary_path}")
            return None

    env_type = detect_environment()
    print(f"[+] Detected environment: {env_type}")

    if not check_radare2_available(env_type):
        print(f"[-] radare2 is not available")
        if env_type in ["Linux", "WSL"]:
            print(f"    sudo apt update && sudo apt install radare2 -y")
        elif env_type == "Windows":
            print(f"    wsl sudo apt update && sudo apt install radare2 -y")
        return None

    print(f"[+] Extracting disassembly data...")
    target_path      = fallback_source if fallback_source else str(binary_path)
    disassembly_data = extract_function_hashes(target_path, env_type)

    if temp_path and os.path.exists(temp_path):
        try:
            os.remove(temp_path)
            print(f"[+] Temporary shellcode binary removed: {temp_path}")
        except Exception:
            pass

    if disassembly_data is None:
        print(f"[-] Failed to extract disassembly data")
        return None

    print(f"[+] Disassembly extraction complete: "
          f"{disassembly_data['function_count']} functions "
          f"(format: {disassembly_data.get('binary_format', 'UNKNOWN')})")

    if not skip_similarity and full_report is not None:
        full_report["disassembly"] = disassembly_data
        _run_similarity_check(disassembly_data, full_report, results_dir, min_overlap)
        _enrich_functions_with_similarity(disassembly_data)
    elif not skip_similarity and full_report is None:
        print(f"[*] No full_report provided — skipping similarity check.")

    return disassembly_data


# CLI entry point

if __name__ == "__main__":
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        results_dir = sys.argv[2] if len(sys.argv) > 2 else "results"
    else:
        print("Usage: python disassembly.py <binary_path> [results_dir]")
        sys.exit(1)

    print("=" * 60)
    print("Binary Disassembly Analysis")
    print("=" * 60)

    minimal_report = {
        "ingest_analysis": {
            "filename": Path(binary_path).name,
            "sha256":   None,
        }
    }

    result = process_disassembly(
        binary_path,
        results_dir,
        full_report=minimal_report,
    )

    if result:
        print("\n" + "=" * 60)
        print("Processing Complete!")
        print("=" * 60)
        print(f"Format                : {result.get('binary_format', 'UNKNOWN')}")
        print(f"Functions extracted   : {result['function_count']}")
        print(f"Strings with VA       : {len(result.get('strings_with_va', []))}")
        print(f"Similar binaries found: {len(result.get('similar_binaries', []))}")
        print(f"\nSample disassembly data:")
        print(json.dumps(result, indent=2)[:500] + "...")
    else:
        print("[-] Failed to process disassembly")
