# Category	    What You Get	            Malware Use
# PE headers    Machine, timestamps, flags	Packing, spoofing
# Sections	    Entropy, sizes, names	    Packing, shellcode
# Imports	    APIs called	                Capability mapping
# Exports	    DLL exports	                Malware DLL behavior
# TLS callbacks	Pre-entry execution	        Malware tricks
# Resources	    Icons, embedded files	    Droppers, configs
# Certificates	Signature info	            Signed malware
# Overlay	    Extra appended data	        Hidden payloads
# Load config	Security features	        Missing mitigations

import pefile
import os
import json
import hashlib
import struct
import dnfile 
import re
from datetime import datetime
from pathlib import Path

BITMAPFILEHEADER_SIZE = 14   # 'BM' + file_size(4) + reserved(4) + offset(4)
BITMAPINFOHEADER_SIZE = 40   # standard DIB header size


def _detect_resource_extension(data: bytes) -> str:
    """Detect common file types based on magic bytes."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if data.startswith(b"<?xml"):
        return "xml"
    if data.startswith(b"{") or data.startswith(b"["):
        return "json"
    
    # Detect raw DIB (RT_BITMAP resource — no file header)
    if len(data) >= 40:
        hdr_size = struct.unpack_from("<I", data, 0)[0]
        if hdr_size in (40, 52, 56, 108, 124, 12):
            width  = abs(struct.unpack_from("<i", data, 4)[0])
            height = abs(struct.unpack_from("<i", data, 8)[0])
            if 1 <= width <= 65535 and 1 <= height <= 65535:
                return "dib"
            
    if len(data) > 40:
        header_size = int.from_bytes(data[0:4], "little")
        if header_size in (40, 108, 124):  # BITMAPINFOHEADER, V4, V5
            return "dib"

    return "bin"


class SimpleCarver:
    """
    Safe, defensive carver: only carves common formats with clear signatures.
    No XOR brute forcing, no recursive unpacking.
    """

    def __init__(self, max_size=50_000_000):
        self.max_size = max_size

    def carve_all(self, data: bytes, out_dir: str, prefix="carved"):
        os.makedirs(out_dir, exist_ok=True)
        results = []
        results += self._carve_png(data, out_dir, prefix)
        results += self._carve_jpeg(data, out_dir, prefix)
        results += self._carve_gif(data, out_dir, prefix)
        results += self._carve_pdf(data, out_dir, prefix)
        results += self._carve_zip(data, out_dir, prefix)
        return list(set(results))

    def _carve_png(self, data, out_dir, prefix):
        sig = b"\x89PNG\r\n\x1a\n"
        results = []
        pos = 0

        while True:
            start = data.find(sig, pos)
            if start == -1:
                break

            end = self._parse_png_end(data, start)
            if end:
                blob = data[start:end]
                out_path = os.path.join(out_dir, f"{prefix}_png_{start}.png")
                with open(out_path, "wb") as f:
                    f.write(blob)
                results.append(out_path)

            pos = start + 8

        return results

    def _parse_png_end(self, data, start):
        pos = start + 8
        while pos + 12 <= len(data):
            if pos - start > self.max_size:
                return None

            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]

            pos += 8
            pos += length
            pos += 4

            if chunk_type == b"IEND":
                return pos
        return None

    def _carve_jpeg(self, data, out_dir, prefix):
        sig = b"\xff\xd8\xff"
        results = []
        pos = 0

        while True:
            start = data.find(sig, pos)
            if start == -1:
                break

            end = data.find(b"\xff\xd9", start + 2)
            if end != -1 and (end + 2 - start) <= self.max_size:
                blob = data[start:end+2]
                out_path = os.path.join(out_dir, f"{prefix}_jpg_{start}.jpg")
                with open(out_path, "wb") as f:
                    f.write(blob)
                results.append(out_path)

            pos = start + 3

        return results

    def _carve_gif(self, data, out_dir, prefix):
        results = []
        pos = 0

        while True:
            s1 = data.find(b"GIF89a", pos)
            s2 = data.find(b"GIF87a", pos)

            candidates = [x for x in [s1, s2] if x != -1]
            if not candidates:
                break

            start = min(candidates)
            trailer = data.find(b"\x3B", start + 6)

            if trailer != -1 and (trailer + 1 - start) <= self.max_size:
                blob = data[start:trailer+1]
                out_path = os.path.join(out_dir, f"{prefix}_gif_{start}.gif")
                with open(out_path, "wb") as f:
                    f.write(blob)
                results.append(out_path)

            pos = start + 6

        return results

    def _carve_pdf(self, data, out_dir, prefix):
        sig = b"%PDF"
        results = []
        pos = 0

        while True:
            start = data.find(sig, pos)
            if start == -1:
                break

            end = data.find(b"%%EOF", start)
            if end != -1:
                end += len(b"%%EOF")
                if (end - start) <= self.max_size:
                    blob = data[start:end]
                    out_path = os.path.join(out_dir, f"{prefix}_pdf_{start}.pdf")
                    with open(out_path, "wb") as f:
                        f.write(blob)
                    results.append(out_path)

            pos = start + 4

        return results

    def _carve_zip(self, data, out_dir, prefix):
        sig = b"PK\x03\x04"
        results = []
        pos = 0

        while True:
            start = data.find(sig, pos)
            if start == -1:
                break

            eocd = data.find(b"PK\x05\x06", start)
            if eocd != -1:
                end = eocd + 22
                if (end - start) <= self.max_size:
                    blob = data[start:end]
                    out_path = os.path.join(out_dir, f"{prefix}_zip_{start}.zip")
                    with open(out_path, "wb") as f:
                        f.write(blob)
                    results.append(out_path)

            pos = start + 4

        return results


class PEStaticAnalyzer:
    """
    Comprehensive PE file static analyzer for malware analysis.
    Extracts maximum possible information from PE files.
    """

    def __init__(self, pe_file_path, output_dir="extracted_resources"):
        """
        Initialize the analyzer with a PE file path.

        Args:
            pe_file_path (str): Path to the PE file to analyze
            output_dir (str): Directory where extracted resources will be written
        """
        self.pe_file_path = pe_file_path
        self.pe = None
        self.analysis_data = {}
        self.output_dir = Path(output_dir)

    def load_pe(self):
        """Load the PE file using pefile library."""
        try:
            self.pe = pefile.PE(self.pe_file_path, fast_load=False)
            self.pe.parse_data_directories()
            return True
        except Exception as e:
            print(f"Error loading PE file: {e}")
            return False

    def get_file_hashes(self):
        """Calculate various hashes of the file."""
        hashes = {}
        try:
            with open(self.pe_file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()

                # Calculate imphash (import hash) - useful for malware family identification
                try:
                    hashes['imphash'] = self.pe.get_imphash()
                except:
                    hashes['imphash'] = None
        except Exception as e:
            print(f"Error calculating hashes: {e}")
        return hashes

    def get_basic_info(self):
        """Extract basic PE file information."""
        info = {
            'filename': os.path.basename(self.pe_file_path),
            'file_size': os.path.getsize(self.pe_file_path),
            'is_exe': self.pe.is_exe(),
            'is_dll': self.pe.is_dll(),
            'is_driver': self.pe.is_driver(),
        }
        return info

    def get_dos_header(self):
        """Extract DOS header information."""
        dos_header = {}
        try:
            dos_header['e_magic'] = hex(self.pe.DOS_HEADER.e_magic)
            dos_header['e_cblp'] = self.pe.DOS_HEADER.e_cblp
            dos_header['e_cp'] = self.pe.DOS_HEADER.e_cp
            dos_header['e_crlc'] = self.pe.DOS_HEADER.e_crlc
            dos_header['e_cparhdr'] = self.pe.DOS_HEADER.e_cparhdr
            dos_header['e_minalloc'] = self.pe.DOS_HEADER.e_minalloc
            dos_header['e_maxalloc'] = self.pe.DOS_HEADER.e_maxalloc
            dos_header['e_ss'] = hex(self.pe.DOS_HEADER.e_ss)
            dos_header['e_sp'] = hex(self.pe.DOS_HEADER.e_sp)
            dos_header['e_csum'] = hex(self.pe.DOS_HEADER.e_csum)
            dos_header['e_ip'] = hex(self.pe.DOS_HEADER.e_ip)
            dos_header['e_cs'] = hex(self.pe.DOS_HEADER.e_cs)
            dos_header['e_lfarlc'] = hex(self.pe.DOS_HEADER.e_lfarlc)
            dos_header['e_ovno'] = self.pe.DOS_HEADER.e_ovno
            dos_header['e_lfanew'] = hex(self.pe.DOS_HEADER.e_lfanew)
        except Exception as e:
            print(f"Error extracting DOS header: {e}")
        return dos_header

    def get_rich_header(self):
        """Extract Rich header (compiler/linker information)."""
        rich_header = {}
        try:
            if hasattr(self.pe, 'RICH_HEADER'):
                rich_header['checksum'] = hex(self.pe.RICH_HEADER.checksum) if self.pe.RICH_HEADER else None
                rich_header['values'] = []
                if self.pe.RICH_HEADER:
                    for entry in self.pe.RICH_HEADER.values:
                        rich_header['values'].append({
                            'product_id': entry >> 16,
                            'build_number': entry & 0xFFFF,
                            'count': self.pe.RICH_HEADER.values[entry]
                        })
                # Calculate Rich header hash
                rich_header['hash'] = hashlib.md5(
                    str(self.pe.RICH_HEADER.values).encode()).hexdigest() if self.pe.RICH_HEADER else None
        except Exception as e:
            print(f"Error extracting Rich header: {e}")
        return rich_header

    def get_file_header(self):
        """Extract FILE header information."""
        file_header = {}
        try:
            fh = self.pe.FILE_HEADER
            file_header['Machine'] = {
                'value': hex(fh.Machine),
                'decoded': pefile.MACHINE_TYPE.get(fh.Machine, 'Unknown')
            }
            file_header['NumberOfSections'] = fh.NumberOfSections
            file_header['TimeDateStamp'] = {
                'value': fh.TimeDateStamp,
                'readable': datetime.fromtimestamp(fh.TimeDateStamp).strftime(
                    '%Y-%m-%d %H:%M:%S') if fh.TimeDateStamp > 0 else 'Invalid'
            }
            file_header['PointerToSymbolTable'] = hex(fh.PointerToSymbolTable)
            file_header['NumberOfSymbols'] = fh.NumberOfSymbols
            file_header['SizeOfOptionalHeader'] = fh.SizeOfOptionalHeader
            file_header['Characteristics'] = {
                'value': hex(fh.Characteristics),
                'flags': self._decode_characteristics(fh.Characteristics)
            }
        except Exception as e:
            print(f"Error extracting FILE header: {e}")
        return file_header

    def _decode_characteristics(self, chars):
        """Decode FILE_HEADER characteristics flags."""
        flags = []
        characteristics_map = {
            0x0001: 'RELOCS_STRIPPED',
            0x0002: 'EXECUTABLE_IMAGE',
            0x0004: 'LINE_NUMS_STRIPPED',
            0x0008: 'LOCAL_SYMS_STRIPPED',
            0x0010: 'AGGRESSIVE_WS_TRIM',
            0x0020: 'LARGE_ADDRESS_AWARE',
            0x0080: 'BYTES_REVERSED_LO',
            0x0100: '32BIT_MACHINE',
            0x0200: 'DEBUG_STRIPPED',
            0x0400: 'REMOVABLE_RUN_FROM_SWAP',
            0x0800: 'NET_RUN_FROM_SWAP',
            0x1000: 'SYSTEM',
            0x2000: 'DLL',
            0x4000: 'UP_SYSTEM_ONLY',
            0x8000: 'BYTES_REVERSED_HI'
        }
        for flag, name in characteristics_map.items():
            if chars & flag:
                flags.append(name)
        return flags

    def get_optional_header(self):
        """Extract OPTIONAL header information."""
        opt_header = {}
        try:
            oh = self.pe.OPTIONAL_HEADER
            opt_header['Magic'] = {
                'value': hex(oh.Magic),
                'decoded': 'PE32' if oh.Magic == 0x10b else 'PE32+' if oh.Magic == 0x20b else 'Unknown'
            }
            opt_header['MajorLinkerVersion'] = oh.MajorLinkerVersion
            opt_header['MinorLinkerVersion'] = oh.MinorLinkerVersion
            opt_header['SizeOfCode'] = oh.SizeOfCode
            opt_header['SizeOfInitializedData'] = oh.SizeOfInitializedData
            opt_header['SizeOfUninitializedData'] = oh.SizeOfUninitializedData
            opt_header['AddressOfEntryPoint'] = hex(oh.AddressOfEntryPoint)
            opt_header['BaseOfCode'] = hex(oh.BaseOfCode)
            if hasattr(oh, 'BaseOfData'):
                opt_header['BaseOfData'] = hex(oh.BaseOfData)
            opt_header['ImageBase'] = hex(oh.ImageBase)
            opt_header['SectionAlignment'] = hex(oh.SectionAlignment)
            opt_header['FileAlignment'] = hex(oh.FileAlignment)
            opt_header['MajorOperatingSystemVersion'] = oh.MajorOperatingSystemVersion
            opt_header['MinorOperatingSystemVersion'] = oh.MinorOperatingSystemVersion
            opt_header['MajorImageVersion'] = oh.MajorImageVersion
            opt_header['MinorImageVersion'] = oh.MinorImageVersion
            opt_header['MajorSubsystemVersion'] = oh.MajorSubsystemVersion
            opt_header['MinorSubsystemVersion'] = oh.MinorSubsystemVersion
            opt_header['SizeOfImage'] = oh.SizeOfImage
            opt_header['SizeOfHeaders'] = oh.SizeOfHeaders
            opt_header['CheckSum'] = hex(oh.CheckSum)
            opt_header['Subsystem'] = {
                'value': oh.Subsystem,
                'decoded': pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, 'Unknown')
            }
            opt_header['DllCharacteristics'] = {
                'value': hex(oh.DllCharacteristics),
                'flags': self._decode_dll_characteristics(oh.DllCharacteristics)
            }
            opt_header['SizeOfStackReserve'] = hex(oh.SizeOfStackReserve)
            opt_header['SizeOfStackCommit'] = hex(oh.SizeOfStackCommit)
            opt_header['SizeOfHeapReserve'] = hex(oh.SizeOfHeapReserve)
            opt_header['SizeOfHeapCommit'] = hex(oh.SizeOfHeapCommit)
            opt_header['LoaderFlags'] = hex(oh.LoaderFlags)
            opt_header['NumberOfRvaAndSizes'] = oh.NumberOfRvaAndSizes
        except Exception as e:
            print(f"Error extracting OPTIONAL header: {e}")
        return opt_header

    def _decode_dll_characteristics(self, chars):
        """Decode DLL characteristics flags (security features)."""
        flags = []
        dll_characteristics_map = {
            0x0020: 'HIGH_ENTROPY_VA',
            0x0040: 'DYNAMIC_BASE',  # ASLR
            0x0080: 'FORCE_INTEGRITY',
            0x0100: 'NX_COMPAT',  # DEP
            0x0200: 'NO_ISOLATION',
            0x0400: 'NO_SEH',
            0x0800: 'NO_BIND',
            0x1000: 'APPCONTAINER',
            0x2000: 'WDM_DRIVER',
            0x4000: 'GUARD_CF',  # Control Flow Guard
            0x8000: 'TERMINAL_SERVER_AWARE'
        }
        for flag, name in dll_characteristics_map.items():
            if chars & flag:
                flags.append(name)
        return flags

    def get_data_directories(self):
        """Extract data directory information."""
        directories = []
        try:
            directory_names = [
                'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY',
                'BASERELOC', 'DEBUG', 'COPYRIGHT', 'GLOBALPTR', 'TLS',
                'LOAD_CONFIG', 'BOUND_IMPORT', 'IAT', 'DELAY_IMPORT',
                'COM_DESCRIPTOR', 'RESERVED'
            ]

            for idx, entry in enumerate(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                if entry.VirtualAddress != 0:
                    directories.append({
                        'name': directory_names[idx] if idx < len(directory_names) else f'DIRECTORY_{idx}',
                        'VirtualAddress': hex(entry.VirtualAddress),
                        'Size': entry.Size
                    })
        except Exception as e:
            print(f"Error extracting data directories: {e}")
        return directories

    def get_sections(self):
        """Extract detailed information about all sections."""
        sections = []
        try:
            for section in self.pe.sections:
                sec_data = {
                    'Name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'VirtualAddress': hex(section.VirtualAddress),
                    'VirtualSize': hex(section.Misc_VirtualSize),
                    'RawSize': section.SizeOfRawData,
                    'RawDataPointer': hex(section.PointerToRawData),
                    'Entropy': round(section.get_entropy(), 4),
                    'Characteristics': {
                        'value': hex(section.Characteristics),
                        'flags': self._decode_section_characteristics(section.Characteristics)
                    },
                    'MD5': section.get_hash_md5(),
                    'SHA1': section.get_hash_sha1(),
                    'SHA256': section.get_hash_sha256()
                }
                sections.append(sec_data)
        except Exception as e:
            print(f"Error extracting sections: {e}")
        return sections

    def _decode_section_characteristics(self, chars):
        """Decode section characteristics flags."""
        flags = []
        section_characteristics_map = {
            0x00000020: 'CNT_CODE',
            0x00000040: 'CNT_INITIALIZED_DATA',
            0x00000080: 'CNT_UNINITIALIZED_DATA',
            0x02000000: 'MEM_DISCARDABLE',
            0x04000000: 'MEM_NOT_CACHED',
            0x08000000: 'MEM_NOT_PAGED',
            0x10000000: 'MEM_SHARED',
            0x20000000: 'MEM_EXECUTE',
            0x40000000: 'MEM_READ',
            0x80000000: 'MEM_WRITE'
        }
        for flag, name in section_characteristics_map.items():
            if chars & flag:
                flags.append(name)
        return flags

    def get_imports(self):
        """Extract imported DLLs and functions with detailed information."""
        imports = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_imports = {
                        'dll': entry.dll.decode('utf-8', errors='ignore'),
                        'functions': []
                    }
                    for imp in entry.imports:
                        func_data = {
                            'address': hex(imp.address) if imp.address else None,
                            'name': imp.name.decode('utf-8', errors='ignore') if imp.name else None,
                            'ordinal': imp.ordinal,
                            'hint': imp.hint if hasattr(imp, 'hint') else None
                        }
                        dll_imports['functions'].append(func_data)
                    imports.append(dll_imports)
        except Exception as e:
            print(f"Error extracting imports: {e}")
        return imports

    def get_exports(self):
        """Extract exported functions with detailed information."""
        exports = {
            'dll_name': None,
            'functions': []
        }
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                exports['dll_name'] = self.pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8',
                                                                                 errors='ignore') if self.pe.DIRECTORY_ENTRY_EXPORT.name else None
                exports['characteristics'] = self.pe.DIRECTORY_ENTRY_EXPORT.struct.Characteristics
                exports['timestamp'] = datetime.fromtimestamp(
                    self.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp).strftime(
                    '%Y-%m-%d %H:%M:%S') if self.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp > 0 else 'Invalid'
                exports['base'] = self.pe.DIRECTORY_ENTRY_EXPORT.struct.Base

                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_data = {
                        'name': exp.name.decode('utf-8', errors='ignore') if exp.name else None,
                        'ordinal': exp.ordinal,
                        'address': hex(exp.address),
                        'forwarder': exp.forwarder.decode('utf-8', errors='ignore') if exp.forwarder else None
                    }
                    exports['functions'].append(export_data)
        except Exception as e:
            print(f"Error extracting exports: {e}")
        return exports
    

    def rebuild_bmp(self, dib_data: bytes) -> bytes:
        """
        Prepend a BITMAPFILEHEADER to raw DIB data to produce a valid .bmp file.

        RT_BITMAP resources are stored as DIBs (no file header).
        Most image tools (including PIL/Pillow) require the full BMP file format.
        """
        total_size = BITMAPFILEHEADER_SIZE + len(dib_data)

        # Calculate pixel data offset:
        # file_header(14) + info_header(variable) + color_table
        info_header_size = struct.unpack_from("<I", dib_data, 0)[0]

        # Colour table: only present for ≤8bpp images
        bpp = struct.unpack_from("<H", dib_data, 14)[0] if len(dib_data) >= 16 else 0
        num_colors = 0
        if bpp <= 8:
            # ClrUsed field at offset 32 in BITMAPINFOHEADER
            if len(dib_data) >= 36:
                num_colors = struct.unpack_from("<I", dib_data, 32)[0]
            if num_colors == 0 and bpp > 0:
                num_colors = 1 << bpp
        color_table_size = num_colors * 4

        pixel_data_offset = BITMAPFILEHEADER_SIZE + info_header_size + color_table_size

        file_header = struct.pack(
            "<2sIHHI",
            b"BM",
            total_size,
            0,   # reserved1
            0,   # reserved2
            pixel_data_offset,
        )
        return file_header + dib_data
    

    def extract_and_rebuild_icons(self, output_dir="extracted_resources"):
        """
        Drop-in function:
        - Extracts RT_ICON + RT_GROUP_ICON resources
        - Rebuilds proper .ico files
        - Saves them to output_dir/icons/
        - Returns list of saved .ico paths
        """
        import os
        import struct

        RT_ICON = 3
        RT_GROUP_ICON = 14

        icons_out = os.path.join(output_dir, "icons")
        os.makedirs(icons_out, exist_ok=True)

        # --- Step 1: Collect all RT_ICON blobs by ID ---
        icon_blobs = {}

        if not hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            return []

        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if not hasattr(resource_type, "directory"):
                continue

            if resource_type.id != RT_ICON:
                continue

            for resource_id in resource_type.directory.entries:
                if not hasattr(resource_id, "directory"):
                    continue

                icon_id = resource_id.id

                for resource_lang in resource_id.directory.entries:
                    offset = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size

                    blob = self.pe.get_data(offset, size)
                    icon_blobs[icon_id] = blob

        if not icon_blobs:
            return []

        # --- Step 2: Parse RT_GROUP_ICON and rebuild ICO files ---
        saved_icons = []

        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if not hasattr(resource_type, "directory"):
                continue

            if resource_type.id != RT_GROUP_ICON:
                continue

            for resource_id in resource_type.directory.entries:
                if not hasattr(resource_id, "directory"):
                    continue

                group_id = resource_id.id

                for resource_lang in resource_id.directory.entries:
                    offset = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size

                    group_data = self.pe.get_data(offset, size)

                    if len(group_data) < 6:
                        continue

                    # ICONDIR header: reserved(2), type(2), count(2)
                    reserved, icon_type, count = struct.unpack("<HHH", group_data[:6])
                    if icon_type != 1 or count <= 0:
                        continue

                    entries = []
                    pos = 6

                    # GROUP_ICON entries are 14 bytes each
                    for _ in range(count):
                        if pos + 14 > len(group_data):
                            break

                        (
                            width,
                            height,
                            color_count,
                            reserved2,
                            planes,
                            bit_count,
                            bytes_in_res,
                            icon_id
                        ) = struct.unpack("<BBBBHHIH", group_data[pos:pos+14])

                        entries.append({
                            "width": width,
                            "height": height,
                            "color_count": color_count,
                            "planes": planes,
                            "bit_count": bit_count,
                            "bytes_in_res": bytes_in_res,
                            "icon_id": icon_id
                        })

                        pos += 14

                    # Build ICO file
                    ico_header = struct.pack("<HHH", 0, 1, len(entries))
                    ico_dir_entries = b""
                    ico_images = b""

                    image_offset = 6 + (16 * len(entries))

                    for entry in entries:
                        icon_id = entry["icon_id"]

                        if icon_id not in icon_blobs:
                            continue

                        img_data = icon_blobs[icon_id]

                        w = entry["width"] if entry["width"] <= 255 else 0
                        h = entry["height"] if entry["height"] <= 255 else 0

                        # ICO dir entry is 16 bytes
                        ico_dir_entries += struct.pack(
                            "<BBBBHHII",
                            w,
                            h,
                            entry["color_count"],
                            0,
                            entry["planes"],
                            entry["bit_count"],
                            len(img_data),
                            image_offset
                        )

                        ico_images += img_data
                        image_offset += len(img_data)

                    if not ico_images:
                        continue

                    ico_data = ico_header + ico_dir_entries + ico_images

                    out_path = os.path.join(icons_out, f"groupicon_{group_id}_lang{resource_lang.id}.ico")
                    with open(out_path, "wb") as f:
                        f.write(ico_data)

                    saved_icons.append(out_path)

        return saved_icons
    

    def extract_dotnet_bitmaps(self, output_dir="extracted_resources"):
        """
        Extract managed .NET manifest resources (.resources blobs),
        then carve likely embedded image formats from them.

        Works across dnfile versions where dn.net.resources may be:
        - a list
        - an object containing .manifest_resources
        """
        results = []

        try:
            import dnfile
        except ImportError:
            print("[!] dnfile not installed. Run: pip install dnfile")
            return results

        try:
            dn = dnfile.dnPE(self.pe_file_path)
        except Exception as e:
            print(f"[!] dnfile failed to parse .NET PE: {e}")
            return results

        if not dn.net:
            return results

        # --- Normalize resource list across dnfile versions ---
        resources = None

        if hasattr(dn.net, "resources"):
            if isinstance(dn.net.resources, list):
                resources = dn.net.resources
            elif hasattr(dn.net.resources, "manifest_resources"):
                resources = dn.net.resources.manifest_resources

        if not resources:
            return results

        managed_dir = os.path.join(output_dir, "dotnet_managed")
        blob_dir = os.path.join(managed_dir, "managed_resource_blobs")
        carve_dir = os.path.join(managed_dir, "managed_resource_carved")

        os.makedirs(blob_dir, exist_ok=True)
        os.makedirs(carve_dir, exist_ok=True)

        carver = SimpleCarver(max_size=100_000_000)

        for res in resources:
            try:
                name = getattr(res, "Name", "unknown")
                offset = getattr(res, "Offset", None)
                size = getattr(res, "Size", None)

                if offset is None or size is None:
                    continue

                blob = dn.get_data(offset, size)
                if not blob:
                    continue

                safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)

                out_path = os.path.join(blob_dir, f"{safe_name}.resources")
                with open(out_path, "wb") as f:
                    f.write(blob)

                carved_files = carver.carve_all(blob, carve_dir, prefix=f"managed_{safe_name}")

                results.append({
                    "name": name,
                    "size": len(blob),
                    "saved_to": out_path,
                    "carved_files": carved_files
                })

            except Exception as e:
                results.append({
                    "name": getattr(res, "Name", "unknown"),
                    "error": str(e)
                })

        return results
    

    def extract_dotnet_managed_resources(self, output_dir="extracted_resources"):
        """
        Safe .NET managed resource extractor:
        - Dumps manifest embedded .resources blobs
        - Carves images/files from them (PNG/JPG/GIF/PDF/ZIP)
        """
        results = []

        try:
            dn = dnfile.dnPE(self.pe_file_path)
            if not dn.net or not dn.net.resources or not dn.net.resources.manifest_resources:
                return results

            managed_dir = os.path.join(output_dir, "dotnet_managed")
            blob_dir = os.path.join(managed_dir, "managed_resource_blobs")
            carve_dir = os.path.join(managed_dir, "managed_resource_carved")

            os.makedirs(blob_dir, exist_ok=True)
            os.makedirs(carve_dir, exist_ok=True)

            carver = SimpleCarver()

            for res in dn.net.resources.manifest_resources:
                try:
                    name = res.Name or "unknown"
                    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)

                    if res.Offset is None or res.Size is None:
                        continue

                    blob = dn.get_data(res.Offset, res.Size)
                    if not blob:
                        continue

                    out_path = os.path.join(blob_dir, f"{safe_name}.resources")
                    with open(out_path, "wb") as f:
                        f.write(blob)

                    carved_files = carver.carve_all(blob, carve_dir, prefix=f"managed_{safe_name}")

                    results.append({
                        "name": name,
                        "size": len(blob),
                        "saved_to": out_path,
                        "carved_files": carved_files
                    })

                except Exception as e:
                    results.append({
                        "name": getattr(res, "Name", "unknown"),
                        "error": str(e)
                    })

        except Exception:
            return results

        return results
    

    def carve_overlay(self, output_dir="extracted_resources"):
        """
        Carve files from PE overlay data (appended payload region).
        """
        try:
            overlay_offset = self.pe.get_overlay_data_start_offset()
            if overlay_offset is None:
                return []

            with open(self.pe_file_path, "rb") as f:
                f.seek(overlay_offset)
                overlay_data = f.read()

            carve_dir = os.path.join(output_dir, "carved_from_overlay")
            os.makedirs(carve_dir, exist_ok=True)

            carver = SimpleCarver()
            return carver.carve_all(overlay_data, carve_dir, prefix="overlay")

        except Exception:
            return []
        

    def extract_rt_bitmap_resources(self, output_dir="extracted_resources", enable_carving=True):
        """
        Drop-in function to extract RT_BITMAP (DIB) resources from a PE file.

        - Saves raw DIB as .dib
        - Rebuilds into valid .bmp (adds BITMAPFILEHEADER)
        - Optionally carves embedded payloads from the rebuilt BMP
        - Returns list of extracted bitmap info dicts
        """

        import os
        import struct
        import hashlib

        RT_BITMAP = 2
        results = []

        dib_dir = os.path.join(output_dir, "rt_bitmaps")
        os.makedirs(dib_dir, exist_ok=True)

        carve_dir = os.path.join(dib_dir, "carved_from_bitmaps")
        if enable_carving:
            os.makedirs(carve_dir, exist_ok=True)

        carver = SimpleCarver(max_size=100_000_000)

        if not hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            return results

        def rebuild_dib_to_bmp(dib_data: bytes) -> bytes:
            """
            Convert DIB (BITMAPINFOHEADER + pixel data) into BMP file bytes.
            """
            if len(dib_data) < 40:
                raise ValueError("DIB too small to contain BITMAPINFOHEADER")

            # DIB header size is first DWORD
            header_size = struct.unpack("<I", dib_data[0:4])[0]
            if header_size not in (40, 108, 124):
                raise ValueError(f"Unexpected DIB header size: {header_size}")

            # Extract important fields from BITMAPINFOHEADER
            width = struct.unpack("<I", dib_data[4:8])[0]
            height = struct.unpack("<I", dib_data[8:12])[0]
            planes = struct.unpack("<H", dib_data[12:14])[0]
            bpp = struct.unpack("<H", dib_data[14:16])[0]
            compression = struct.unpack("<I", dib_data[16:20])[0]

            # Determine where pixel data begins
            # For many DIBs, pixel data begins right after header + palette (if any).
            # If bpp <= 8, there is a palette of 4*(2^bpp) bytes.
            palette_size = 0
            if bpp in (1, 4, 8):
                palette_size = (2 ** bpp) * 4

            pixel_offset = 14 + header_size + palette_size
            file_size = 14 + len(dib_data)

            # BMP FILE HEADER (14 bytes)
            bmp_file_header = struct.pack(
                "<2sIHHI",
                b"BM",
                file_size,
                0,
                0,
                pixel_offset
            )

            return bmp_file_header + dib_data

        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if not hasattr(resource_type, "directory"):
                continue

            if resource_type.id != RT_BITMAP:
                continue

            for resource_id in resource_type.directory.entries:
                if not hasattr(resource_id, "directory"):
                    continue

                bmp_id = resource_id.id

                for resource_lang in resource_id.directory.entries:
                    try:
                        offset = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        dib_data = self.pe.get_data(offset, size)

                        if len(dib_data) < 40:
                            continue

                        # Save raw DIB
                        dib_path = os.path.join(dib_dir, f"RT_BITMAP_id{bmp_id}_lang{resource_lang.id}_{offset}.dib")
                        with open(dib_path, "wb") as f:
                            f.write(dib_data)

                        # Rebuild BMP
                        bmp_bytes = rebuild_dib_to_bmp(dib_data)

                        bmp_path = os.path.join(dib_dir, f"RT_BITMAP_id{bmp_id}_lang{resource_lang.id}_{offset}.bmp")
                        with open(bmp_path, "wb") as f:
                            f.write(bmp_bytes)

                        # Carve inside BMP
                        carved_files = []
                        if enable_carving:
                            carved_files = carver.carve_all(
                                bmp_bytes,
                                carve_dir,
                                prefix=f"rtbitmap_id{bmp_id}_lang{resource_lang.id}"
                            )

                        results.append({
                            "type": "RT_BITMAP",
                            "id": bmp_id,
                            "lang": resource_lang.id,
                            "size": size,
                            "offset": hex(offset),
                            "md5": hashlib.md5(dib_data).hexdigest(),
                            "entropy": self._calculate_entropy(dib_data),
                            "dib_saved_to": dib_path,
                            "bmp_saved_to": bmp_path,
                            "carved_files": carved_files
                        })

                    except Exception as e:
                        results.append({
                            "type": "RT_BITMAP",
                            "id": bmp_id,
                            "lang": getattr(resource_lang, "id", None),
                            "error": str(e)
                        })

        return results

    
    def carve_files_from_sections(self, output_dir="extracted_resources"):
        """
        Carve embedded PNG/BMP/ICO files directly from PE sections (like DIE does).
        This detects magic headers inside raw section data and extracts them.
        """

        import os
        import hashlib
        import struct

        # out_dir = os.path.join(output_dir, "carved_from_sections")
        # os.makedirs(out_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        with open(self.pe_file_path, "rb") as f:
            full_data = f.read()

        results = []

        def carve_png(start):
            # parse PNG chunks until IEND
            pos = start + 8
            while pos + 12 < len(full_data):
                length = struct.unpack(">I", full_data[pos:pos+4])[0]
                ctype = full_data[pos+4:pos+8]
                pos += 8 + length + 4
                if ctype == b"IEND":
                    return pos
            return None

        def carve_bmp(start):
            if start + 6 > len(full_data):
                return None
            size = struct.unpack("<I", full_data[start+2:start+6])[0]
            end = start + size
            if end > len(full_data):
                return None
            return end

        def carve_ico(start):
            # ICO doesn't store full size in a simple place reliably
            # We'll parse directory entries
            if start + 6 > len(full_data):
                return None

            reserved, ico_type, count = struct.unpack("<HHH", full_data[start:start+6])
            if reserved != 0 or ico_type != 1 or count <= 0:
                return None

            dir_end = start + 6 + (count * 16)
            if dir_end > len(full_data):
                return None

            max_end = dir_end
            pos = start + 6

            for _ in range(count):
                entry = full_data[pos:pos+16]
                bytes_in_res = struct.unpack("<I", entry[8:12])[0]
                img_offset = struct.unpack("<I", entry[12:16])[0]
                img_end = start + img_offset + bytes_in_res
                if img_end > max_end:
                    max_end = img_end
                pos += 16

            if max_end > len(full_data):
                return None

            return max_end

        signatures = [
            (b"\x89PNG\r\n\x1a\n", "png", carve_png),
            (b"BM", "bmp", carve_bmp),
            (b"\x00\x00\x01\x00", "ico", carve_ico),
        ]

        for section in self.pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            start = section.PointerToRawData
            end = start + section.SizeOfRawData

            if end > len(full_data):
                continue

            sec_bytes = full_data[start:end]

            for sig, ext, parser in signatures:
                pos = 0
                while True:
                    idx = sec_bytes.find(sig, pos)
                    if idx == -1:
                        break

                    abs_offset = start + idx
                    file_end = parser(abs_offset)

                    if file_end and file_end > abs_offset:
                        carved = full_data[abs_offset:file_end]

                        md5 = hashlib.md5(carved).hexdigest()
                        # out_path = os.path.join(out_dir, f"{sec_name}_{abs_offset:08x}_{md5}.{ext}")
                        out_path = os.path.join(output_dir, f"{sec_name}_{abs_offset:08x}_{md5}.{ext}")

                        with open(out_path, "wb") as f:
                            f.write(carved)

                        results.append({
                            "section": sec_name,
                            "offset": hex(abs_offset),
                            "size": len(carved),
                            "type": ext,
                            "md5": md5,
                            "saved_to": out_path
                        })

                    pos = idx + len(sig)

        return results


    def get_resources(self, output_dir="extracted_resources", enable_carving=True):
        """
        Extract detailed PE resource information, dump blobs to disk,
        rebuild RT_BITMAP DIB resources into valid BMPs,
        and carve embedded payloads (PE/ELF/ZIP/etc).
        """

        resources = []
        carver = SimpleCarver()

        try:
            os.makedirs(output_dir, exist_ok=True)

            carve_dir = os.path.join(output_dir, "carved_from_resources")
            if enable_carving:
                os.makedirs(carve_dir, exist_ok=True)

            if not hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
                return resources

            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:

                if not hasattr(resource_type, "directory"):
                    continue

                for resource_id in resource_type.directory.entries:

                    if not hasattr(resource_id, "directory"):
                        continue

                    for resource_lang in resource_id.directory.entries:

                        offset = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        data = self.pe.get_data(offset, size)

                        res_type = pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id))

                        ext = _detect_resource_extension(data)

                        saved_paths = []

                        # --- Handle RT_BITMAP / DIB conversion ---
                        if res_type == "RT_BITMAP" or ext == "dib":
                            try:
                                rebuilt_bmp = self.rebuild_bmp(data)
                                bmp_filename = f"{res_type}_id{resource_id.id}_lang{resource_lang.id}_{offset}.bmp"
                                bmp_path = os.path.join(output_dir, bmp_filename)

                                with open(bmp_path, "wb") as f:
                                    f.write(rebuilt_bmp)

                                saved_paths.append(bmp_path)

                                # Carve inside the rebuilt bitmap
                                carved_files = []
                                if enable_carving:
                                    carved_files = carver.carve_all(
                                        rebuilt_bmp,
                                        carve_dir,
                                        prefix=f"{res_type}_id{resource_id.id}_lang{resource_lang.id}"
                                    )

                                res_data = {
                                    "type": res_type,
                                    "id": resource_id.id,
                                    "lang": resource_lang.id,
                                    "sublang": resource_lang.id & 0x3F,
                                    "size": size,
                                    "offset": hex(offset),
                                    "md5": hashlib.md5(data).hexdigest(),
                                    "entropy": self._calculate_entropy(data),
                                    "saved_to": bmp_path,
                                    "rebuilt_from": "DIB",
                                    "carved_files": carved_files
                                }

                                resources.append(res_data)
                                continue

                            except Exception as e:
                                print(f"[!] Failed to rebuild DIB bitmap resource: {e}")

                        # --- Normal saving for all other resources ---
                        filename = f"{res_type}_id{resource_id.id}_lang{resource_lang.id}_{offset}.{ext}"
                        out_path = os.path.join(output_dir, filename)

                        with open(out_path, "wb") as f:
                            f.write(data)

                        saved_paths.append(out_path)

                        carved_files = []
                        if enable_carving:
                            carved_files = carver.carve_all(
                                data,
                                carve_dir,
                                prefix=f"{res_type}_id{resource_id.id}_lang{resource_lang.id}"
                            )

                        res_data = {
                            "type": res_type,
                            "id": resource_id.id,
                            "lang": resource_lang.id,
                            "sublang": resource_lang.id & 0x3F,
                            "size": size,
                            "offset": hex(offset),
                            "md5": hashlib.md5(data).hexdigest(),
                            "entropy": self._calculate_entropy(data),
                            "saved_to": out_path,
                            "carved_files": carved_files
                        }

                        resources.append(res_data)

        except Exception as e:
            print(f"Error extracting resources: {e}")

        return resources

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data. Returns a value in [0.0, 8.0]."""
        if not data:
            return 0.0
        import math
        from collections import Counter
        counts = Counter(data)
        total = len(data)
        return round(
            -sum((c / total) * math.log2(c / total) for c in counts.values()),
            4,
        )

    @staticmethod
    def _entropy_label(value: float) -> str:
        """Human-readable tier for an entropy value."""
        if value < 1.0:   return "near-zero"
        if value < 3.5:   return "low"
        if value < 6.0:   return "medium"
        if value < 7.0:   return "elevated"
        if value < 7.5:   return "high"
        return "very-high"

    def get_entropy_summary(self) -> dict:
        """
        Build a consolidated entropy picture across the whole file and its
        sections. Called after get_sections() so section entropy is already
        computed by pefile.

        Returns a dict with:
          file_entropy, file_entropy_label,
          section_entropies (sorted high->low),
          highest_entropy_section,
          suspicious_sections (entropy >= 7.0),
          mean_section_entropy,
          packed_indicator (bool)
        """
        import math
        from collections import Counter

        try:
            with open(self.pe_file_path, "rb") as f:
                file_data = f.read()
            file_entropy = self._calculate_entropy(file_data)
        except Exception:
            file_entropy = 0.0

        section_entropies = []
        for section in self.pe.sections:
            name    = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            entropy = round(section.get_entropy(), 6)
            size    = section.SizeOfRawData
            section_entropies.append({
                "name":          name,
                "entropy":       entropy,
                "entropy_label": self._entropy_label(entropy),
                "size":          size,
            })

        section_entropies.sort(key=lambda x: x["entropy"], reverse=True)
        suspicious = [s for s in section_entropies if s["entropy"] >= 7.0]
        mean_entropy = (
            round(sum(s["entropy"] for s in section_entropies) / len(section_entropies), 6)
            if section_entropies else 0.0
        )

        return {
            "file_entropy":            file_entropy,
            "file_entropy_label":      self._entropy_label(file_entropy),
            "section_entropies":       section_entropies,
            "highest_entropy_section": section_entropies[0] if section_entropies else None,
            "suspicious_sections":     suspicious,
            "mean_section_entropy":    mean_entropy,
            "packed_indicator":        len(suspicious) > 0,
        }

    def get_tls_callbacks(self):
        """Extract TLS callback information (anti-debugging technique)."""
        tls_data = {}
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
                tls = self.pe.DIRECTORY_ENTRY_TLS.struct
                tls_data = {
                    'StartAddressOfRawData': hex(tls.StartAddressOfRawData),
                    'EndAddressOfRawData': hex(tls.EndAddressOfRawData),
                    'AddressOfIndex': hex(tls.AddressOfIndex),
                    'AddressOfCallBacks': hex(tls.AddressOfCallBacks),
                    'SizeOfZeroFill': tls.SizeOfZeroFill,
                    'Characteristics': hex(tls.Characteristics),
                    'callbacks': []
                }

                # Extract callback addresses
                if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS') and hasattr(self.pe.DIRECTORY_ENTRY_TLS, 'callbacks'):
                    for callback in self.pe.DIRECTORY_ENTRY_TLS.callbacks:
                        tls_data['callbacks'].append(hex(callback))
        except Exception as e:
            print(f"Error extracting TLS callbacks: {e}")
        return tls_data

    def get_load_config(self):
        """Extract load configuration (security features like SafeSEH, CFG)."""
        load_config = {}
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                lc = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                load_config = {
                    'Size': lc.Size,
                    'TimeDateStamp': datetime.fromtimestamp(lc.TimeDateStamp).strftime(
                        '%Y-%m-%d %H:%M:%S') if lc.TimeDateStamp > 0 else 'Invalid',
                    'MajorVersion': lc.MajorVersion,
                    'MinorVersion': lc.MinorVersion,
                    'GlobalFlagsClear': hex(lc.GlobalFlagsClear),
                    'GlobalFlagsSet': hex(lc.GlobalFlagsSet),
                    'CriticalSectionDefaultTimeout': lc.CriticalSectionDefaultTimeout,
                    'DeCommitFreeBlockThreshold': hex(lc.DeCommitFreeBlockThreshold),
                    'DeCommitTotalFreeThreshold': hex(lc.DeCommitTotalFreeThreshold),
                    'SecurityCookie': hex(lc.SecurityCookie) if hasattr(lc, 'SecurityCookie') else None,
                    'SEHandlerTable': hex(lc.SEHandlerTable) if hasattr(lc, 'SEHandlerTable') else None,
                    'SEHandlerCount': lc.SEHandlerCount if hasattr(lc, 'SEHandlerCount') else None,
                    'GuardCFCheckFunctionPointer': hex(lc.GuardCFCheckFunctionPointer) if hasattr(lc,
                                                                                                  'GuardCFCheckFunctionPointer') else None,
                    'GuardCFDispatchFunctionPointer': hex(lc.GuardCFDispatchFunctionPointer) if hasattr(lc,
                                                                                                        'GuardCFDispatchFunctionPointer') else None,
                    'GuardCFFunctionTable': hex(lc.GuardCFFunctionTable) if hasattr(lc,
                                                                                    'GuardCFFunctionTable') else None,
                    'GuardCFFunctionCount': lc.GuardCFFunctionCount if hasattr(lc, 'GuardCFFunctionCount') else None,
                    'GuardFlags': hex(lc.GuardFlags) if hasattr(lc, 'GuardFlags') else None
                }
        except Exception as e:
            print(f"Error extracting load config: {e}")
        return load_config

    def get_debug_info(self):
        """Extract debug information (PDB path, GUID, etc.)."""
        debug_info = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
                for entry in self.pe.DIRECTORY_ENTRY_DEBUG:
                    debug_data = {
                        'Type': entry.struct.Type,
                        'SizeOfData': entry.struct.SizeOfData,
                        'AddressOfRawData': hex(entry.struct.AddressOfRawData),
                        'PointerToRawData': hex(entry.struct.PointerToRawData),
                        'TimeDateStamp': datetime.fromtimestamp(entry.struct.TimeDateStamp).strftime(
                            '%Y-%m-%d %H:%M:%S') if entry.struct.TimeDateStamp > 0 else 'Invalid'
                    }

                    # Extract PDB information if available
                    if entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                        try:
                            debug_data['PdbFileName'] = entry.entry.PdbFileName.decode('utf-8',
                                                                                       errors='ignore') if hasattr(
                                entry.entry, 'PdbFileName') else None
                            if hasattr(entry.entry, 'Signature_String'):
                                debug_data['GUID'] = entry.entry.Signature_String
                            if hasattr(entry.entry, 'Age'):
                                debug_data['Age'] = entry.entry.Age
                        except:
                            pass

                    debug_info.append(debug_data)
        except Exception as e:
            print(f"Error extracting debug info: {e}")
        return debug_info

    def get_relocations(self):
        """Extract base relocation information."""
        relocations = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                    reloc_data = {
                        'VirtualAddress': hex(base_reloc.struct.VirtualAddress),
                        'SizeOfBlock': base_reloc.struct.SizeOfBlock,
                        'entries_count': len(base_reloc.entries)
                    }
                    relocations.append(reloc_data)
        except Exception as e:
            print(f"Error extracting relocations: {e}")
        return relocations

    def get_bound_imports(self):
        """Extract bound import information."""
        bound_imports = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                for bound_import in self.pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                    bound_data = {
                        'name': bound_import.name.decode('utf-8', errors='ignore'),
                        'TimeDateStamp': datetime.fromtimestamp(bound_import.struct.TimeDateStamp).strftime(
                            '%Y-%m-%d %H:%M:%S') if bound_import.struct.TimeDateStamp > 0 else 'Invalid'
                    }
                    bound_imports.append(bound_data)
        except Exception as e:
            print(f"Error extracting bound imports: {e}")
        return bound_imports

    def get_delay_imports(self):
        """Extract delay-loaded imports."""
        delay_imports = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    delay_data = {
                        'dll': entry.dll.decode('utf-8', errors='ignore'),
                        'functions': []
                    }
                    for imp in entry.imports:
                        func_data = {
                            'name': imp.name.decode('utf-8', errors='ignore') if imp.name else None,
                            'ordinal': imp.ordinal,
                            'address': hex(imp.address) if hasattr(imp, 'address') else None
                        }
                        delay_data['functions'].append(func_data)
                    delay_imports.append(delay_data)
        except Exception as e:
            print(f"Error extracting delay imports: {e}")
        return delay_imports

    def get_overlay_data(self):
        """Extract overlay data (data appended after PE structure)."""
        overlay_info = {}
        try:
            overlay_offset = self.pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                with open(self.pe_file_path, 'rb') as f:
                    f.seek(overlay_offset)
                    overlay_data = f.read()
                    overlay_info = {
                        'offset': hex(overlay_offset),
                        'size': len(overlay_data),
                        'md5': hashlib.md5(overlay_data).hexdigest(),
                        'sha256': hashlib.sha256(overlay_data).hexdigest(),
                        'entropy': self._calculate_entropy(overlay_data)
                    }
        except Exception as e:
            print(f"Error extracting overlay: {e}")
        return overlay_info

    def get_version_info(self):
        """Extract version information if available."""
        version_info = {}
        try:
            if hasattr(self.pe, 'VS_VERSIONINFO'):
                if hasattr(self.pe, 'FileInfo'):
                    for entry in self.pe.FileInfo:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    version_info[key.decode('utf-8', errors='ignore')] = value.decode('utf-8',
                                                                                                      errors='ignore')
                        if hasattr(entry, 'Var'):
                            for var in entry.Var:
                                version_info['Translation'] = hex(var.entry.get('Translation', 0))
        except Exception as e:
            print(f"Error extracting version info: {e}")
        return version_info

    def get_digital_signature(self):
        """Extract digital signature information."""
        signature_info = {}
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                sig = self.pe.DIRECTORY_ENTRY_SECURITY
                signature_info = {
                    'VirtualAddress': hex(sig.VirtualAddress),
                    'Size': sig.Size,
                    'present': True
                }
                # Note: Full certificate parsing would require additional libraries like cryptography
        except Exception as e:
            signature_info['present'] = False
            print(f"Error extracting signature: {e}")
        return signature_info

    def get_pe_warnings(self):
        """Get warnings from pefile about anomalies."""
        warnings = []
        try:
            if hasattr(self.pe, 'get_warnings'):
                warnings = self.pe.get_warnings()
        except Exception as e:
            print(f"Error getting PE warnings: {e}")
        return warnings

    def detect_anomalies(self):
        """Detect suspicious characteristics and anomalies."""
        anomalies = []

        try:
            # Check for suspicious section names
            suspicious_section_names = ['.packed', 'UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', '.petite', '.ndata']
            for section in self.pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if any(sus in sec_name for sus in suspicious_section_names):
                    anomalies.append(f"Suspicious section name: {sec_name}")

            # Check for high entropy sections (possible packing/encryption)
            for section in self.pe.sections:
                entropy = section.get_entropy()
                if entropy > 7.0:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    anomalies.append(f"High entropy section ({entropy:.2f}): {sec_name}")

            # Check for unusual entry point
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in self.pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if '.text' not in sec_name and 'CODE' not in sec_name:
                        anomalies.append(f"Entry point in non-code section: {sec_name}")
                    break

            # Check for executable and writable sections (W^X violation)
            for section in self.pe.sections:
                chars = section.Characteristics
                if (chars & 0x20000000) and (chars & 0x80000000):  # Execute and Write
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    anomalies.append(f"Section is both writable and executable: {sec_name}")

            # Check for zero-size sections
            for section in self.pe.sections:
                if section.SizeOfRawData == 0:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    anomalies.append(f"Zero-size section: {sec_name}")

            # Check timestamp validity
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            if timestamp == 0:
                anomalies.append("Zero timestamp (possible tampering)")
            elif timestamp > datetime.now().timestamp():
                anomalies.append("Future timestamp (possible tampering)")

            # Check for suspicious imports
            suspicious_imports = [
                'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
                'NtSetContextThread', 'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
                'RtlCreateUserThread', 'QueueUserAPC', 'CryptEncrypt', 'InternetOpen'
            ]

            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                found_suspicious = []
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode('utf-8', errors='ignore')
                            if imp_name in suspicious_imports:
                                found_suspicious.append(imp_name)

                if found_suspicious:
                    anomalies.append(f"Suspicious imports detected: {', '.join(set(found_suspicious))}")

            # Check for no imports (possibly packed)
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') or len(self.pe.DIRECTORY_ENTRY_IMPORT) == 0:
                anomalies.append("No imports found (possibly packed or unusual)")

            # Check for resource anomalies
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    if resource_lang.data.struct.Size > 10 * 1024 * 1024:  # > 10MB
                                        anomalies.append(
                                            f"Large resource detected: {resource_lang.data.struct.Size} bytes")

        except Exception as e:
            print(f"Error detecting anomalies: {e}")

        return anomalies

    def extract_strings(self, min_length=4, max_strings=5000):
        """
        Extract ASCII and Unicode strings from the PE file.

        Args:
            min_length (int): Minimum string length to extract
            max_strings (int): Maximum number of strings per type
        """
        strings = {'ascii': [], 'unicode': []}
        try:
            with open(self.pe_file_path, 'rb') as f:
                data = f.read()

                # ASCII strings
                ascii_pattern = b'[\x20-\x7E]{' + str(min_length).encode() + b',}'
                ascii_strings = re.findall(ascii_pattern, data)
                strings['ascii'] = [s.decode('ascii', errors='ignore') for s in ascii_strings[:max_strings]]

                # Unicode strings (UTF-16 LE)
                unicode_pattern = b'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + b',}'
                unicode_strings = re.findall(unicode_pattern, data)
                strings['unicode'] = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings[:max_strings]]

                # Extract interesting strings (URLs, IPs, emails, registry keys, file paths)
                strings['interesting'] = self._extract_interesting_strings(strings['ascii'] + strings['unicode'])

        except Exception as e:
            print(f"Error extracting strings: {e}")
        return strings

    def _extract_interesting_strings(self, all_strings):
        """Extract potentially interesting strings using pattern matching."""
        interesting = {
            'urls': [],
            'ips': [],
            'emails': [],
            'registry_keys': [],
            'file_paths': [],
            'crypto_indicators': [],
            'versions': []
        }

        # Patterns
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        registry_pattern = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s]+', re.IGNORECASE)
        path_pattern = re.compile(r'[A-Za-z]:\\(?:[^\\\s:*?"<>|]+\\)*[^\\\s:*?"<>|]*', re.IGNORECASE)
        crypto_keywords = ['AES', 'DES', 'RSA', 'MD5', 'SHA', 'base64', 'encrypt', 'decrypt', 'cipher']

        for s in all_strings:
            # URLs
            urls = url_pattern.findall(s)
            interesting['urls'].extend(urls)

            # IPs (validate to exclude version numbers)
            ips = ip_pattern.findall(s)
            valid_ips = [ip for ip in ips if self._is_valid_ip(ip)]
            interesting['ips'].extend(valid_ips)

            # Emails
            emails = email_pattern.findall(s)
            interesting['emails'].extend(emails)

            # Registry keys
            reg_keys = registry_pattern.findall(s)
            interesting['registry_keys'].extend(reg_keys)

            # File paths
            paths = path_pattern.findall(s)
            interesting['file_paths'].extend(paths)

            # Crypto indicators
            for keyword in crypto_keywords:
                if keyword.lower() in s.lower():
                    interesting['crypto_indicators'].append(s)
                    break

            # Versions
            version_matches = re.findall(r'\b\d+(?:\.\d+)+\b', s)
            interesting['versions'].extend(version_matches)

        # Deduplicate and limit
        for key in interesting:
            interesting[key] = list(set(interesting[key]))[:100]  # Limit to 100 per category

        return interesting

    @staticmethod
    def _is_valid_ip(ip_str):
        """Check if a string is a valid IPv4 address (each octet 0-255)."""
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True

    def get_packer_signatures(self):
        """Attempt to detect common packers/protectors."""
        packers = []

        try:
            # Check section names for common packer signatures
            packer_signatures = {
                'UPX': ['UPX0', 'UPX1', 'UPX2', '.upx'],
                'ASPack': ['.aspack', '.adata'],
                'PECompact': ['.pec1', '.pec2', 'PEC2'],
                'Petite': ['.petite'],
                'WinUpack': ['.winup'],
                'FSG': ['.fsgs'],
                'MPRESS': ['.MPRESS1', '.MPRESS2'],
                'Themida': ['.themida', '.thmida'],
                'VMProtect': ['.vmp0', '.vmp1', '.vmp2'],
                'Armadillo': ['.arma'],
                'Obsidium': ['.obsidum'],
                'Enigma': ['.enigma1', '.enigma2']
            }

            section_names = [section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                             for section in self.pe.sections]

            for packer, signatures in packer_signatures.items():
                for sig in signatures:
                    if any(sig.lower() in name for name in section_names):
                        if packer not in packers:
                            packers.append(packer)

            # Check entry point section
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in self.pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if sec_name not in ['.text', 'CODE', '.code']:
                        packers.append(f"Possible packer (EP in {sec_name})")
                    break

        except Exception as e:
            print(f"Error detecting packers: {e}")

        return packers

    def get_security_features(self):
        """Summarize security features enabled in the binary."""
        features = {
            'ASLR': False,
            'DEP': False,
            'SEH': False,
            'CFG': False,
            'SafeSEH': False,
            'HighEntropyVA': False,
            'ForceIntegrity': False,
            'Signed': False
        }

        try:
            dll_chars = self.pe.OPTIONAL_HEADER.DllCharacteristics

            features['ASLR'] = bool(dll_chars & 0x0040)
            features['DEP'] = bool(dll_chars & 0x0100)
            features['CFG'] = bool(dll_chars & 0x4000)
            features['HighEntropyVA'] = bool(dll_chars & 0x0020)
            features['ForceIntegrity'] = bool(dll_chars & 0x0080)
            features['SEH'] = not bool(dll_chars & 0x0400)  # NO_SEH flag

            # Check for SafeSEH
            if hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                if hasattr(self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'SEHandlerTable'):
                    features['SafeSEH'] = True

            # Check for digital signature
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                features['Signed'] = True

        except Exception as e:
            print(f"Error checking security features: {e}")

        return features

    def analyze(self):
        """Perform complete comprehensive static analysis."""
        if not self.load_pe():
            return None

        print(f"[*] Analyzing: {self.pe_file_path}")
        print("[*] Extracting PE structure information...")

        output_dir = str(self.output_dir)
        self.analysis_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'analyzer_version': '2.0',
                'file_path': self.pe_file_path
            },
            'hashes': self.get_file_hashes(),
            'basic_info': self.get_basic_info(),
            'security_features': self.get_security_features(),
            'dos_header': self.get_dos_header(),
            'rich_header': self.get_rich_header(),
            'file_header': self.get_file_header(),
            'optional_header': self.get_optional_header(),
            'data_directories': self.get_data_directories(),
            'sections': self.get_sections(),
            'imports': self.get_imports(),
            'exports': self.get_exports(),
            'resources': self.get_resources(output_dir=output_dir, enable_carving=True),
            'dotnet_managed_resources': self.extract_dotnet_managed_resources(output_dir=output_dir),
            'overlay_carved_files': self.carve_overlay(output_dir=output_dir),
            'carved_section_files': self.carve_files_from_sections(output_dir=output_dir),
            'tls_callbacks': self.get_tls_callbacks(),
            'load_config': self.get_load_config(),
            'debug_info': self.get_debug_info(),
            'relocations': self.get_relocations(),
            'bound_imports': self.get_bound_imports(),
            'delay_imports': self.get_delay_imports(),
            'overlay': self.get_overlay_data(),
            'version_info': self.get_version_info(),
            'digital_signature': self.get_digital_signature(),
            'pe_warnings': self.get_pe_warnings(),
            'anomalies': self.detect_anomalies(),
            'packer_signatures': self.get_packer_signatures(),
            'strings': self.extract_strings(),
            'entropy': self.get_entropy_summary(),
        }

        # Filter out version numbers from IPs based on version_info
        version_info = self.analysis_data['version_info']
        version_strings = set()
        for key, value in version_info.items():
            if isinstance(value, str) and re.match(r'\b\d+(?:\.\d+)+\b', value):
                version_strings.add(value)
        self.analysis_data['strings']['interesting']['ips'] = [
            ip for ip in self.analysis_data['strings']['interesting']['ips'] 
            if ip not in version_strings
        ]

        self.extract_and_rebuild_icons(output_dir=output_dir)
        self.analysis_data["dotnet_managed_resources"] = self.extract_dotnet_bitmaps(output_dir=output_dir)
        self.analysis_data["rt_bitmaps"] = self.extract_rt_bitmap_resources(
            output_dir=output_dir,
            enable_carving=True
        )


        # Packing assessment — runs after all other fields are populated
        # so it can draw on sections, imports, overlay, security_features, etc.
        try:
            from static_analysis.packing_detection import assess_packing_pe
            self.analysis_data['packing'] = assess_packing_pe(self)
            verdict = self.analysis_data['packing']['verdict']
            confidence = self.analysis_data['packing']['confidence']
            packers = self.analysis_data['packing']['packer_names']
            print(f"[+] Packing assessment: {verdict} (confidence {confidence:.0%})"
                  + (f" — {', '.join(packers)}" if packers else ""))
        except ImportError:
            print("[!] packing_detector.py not found — skipping packing assessment")

        print("[+] Analysis complete!")
        return self.analysis_data

    def get_report(self):
        """
        Return the analysis data dictionary.
        Used in multiprocessing context to pass data between functions.
        """
        return self.analysis_data

    def save_report(self, output_dir=None):
        """
        Save analysis report to JSON file, appending to existing data.
        Uses SHA256 hash as filename and merges with existing JSON if present.

        Args:
            output_dir (str): Optional custom output directory (default: ../reports/)
        """
        if not self.analysis_data:
            print("[-] No analysis data to save. Run analyze() first.")
            return None

        # Determine output directory
        if output_dir is None:
            # Get the directory one level up from this script
            script_dir = Path(__file__).parent
            reports_dir = script_dir.parent / 'results'
        else:
            reports_dir = Path(output_dir)

        # Create reports directory if it doesn't exist
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Use SHA256 as filename
        sha256_hash = self.analysis_data['hashes']['sha256']
        filename = f"{sha256_hash}.json"
        report_path = reports_dir / filename

        # Load existing data if file exists
        existing_data = {}
        if report_path.exists():
            try:
                with open(report_path, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                print(f"[*] Found existing report, merging data...")
            except Exception as e:
                print(f"[!] Warning: Could not read existing file: {e}")
                print(f"[*] Will create new file instead")

        # Merge the data - add PE analysis under 'static_analysis' key
        if existing_data:
            # Preserve existing data and add our analysis
            existing_data['static_analysis'] = self.analysis_data
            # Update timestamp to show when analysis was added
            if 'analysis_timestamps' not in existing_data:
                existing_data['analysis_timestamps'] = {}
            existing_data['analysis_timestamps']['static_analysis'] = datetime.now().isoformat()
            merged_data = existing_data
        else:
            # No existing data, create new structure
            merged_data = {
                'static_analysis': self.analysis_data,
                'analysis_timestamps': {
                    'static_analysis': datetime.now().isoformat()
                }
            }

        # Save merged data to JSON
        try:
            # with open(report_path, 'w', encoding='utf-8') as f:
            #     json.dump(merged_data, f, indent=2, ensure_ascii=False)
            # print(f"[+] Report saved to: {report_path}")
            return str(report_path)
        except Exception as e:
            print(f"[-] Error saving report: {e}")
            return None

    def print_summary(self):
        """Print a brief summary of the analysis."""
        if not self.analysis_data:
            print("[-] No analysis data available.")
            return

        print("\n" + "=" * 70)
        print("MALWARE ANALYSIS SUMMARY")
        print("=" * 70)

        print(f"\n[FILE INFORMATION]")
        print(f"  Filename: {self.analysis_data['basic_info']['filename']}")
        print(f"  Size: {self.analysis_data['basic_info']['file_size']:,} bytes")
        print(
            f"  Type: {'EXE' if self.analysis_data['basic_info']['is_exe'] else 'DLL' if self.analysis_data['basic_info']['is_dll'] else 'Driver' if self.analysis_data['basic_info']['is_driver'] else 'Unknown'}")

        print(f"\n[HASHES]")
        print(f"  MD5:     {self.analysis_data['hashes']['md5']}")
        print(f"  SHA1:    {self.analysis_data['hashes']['sha1']}")
        print(f"  SHA256:  {self.analysis_data['hashes']['sha256']}")
        if self.analysis_data['hashes']['imphash']:
            print(f"  ImpHash: {self.analysis_data['hashes']['imphash']}")

        print(f"\n[SECURITY FEATURES]")
        sec = self.analysis_data['security_features']
        print(
            f"  ASLR: {'✓' if sec['ASLR'] else '✗'} | DEP: {'✓' if sec['DEP'] else '✗'} | CFG: {'✓' if sec['CFG'] else '✗'} | Signed: {'✓' if sec['Signed'] else '✗'}")

        if self.analysis_data['packer_signatures']:
            print(f"\n[PACKER DETECTION]")
            for packer in self.analysis_data['packer_signatures']:
                print(f"  ⚠ {packer}")

        if self.analysis_data['anomalies']:
            print(f"\n[ANOMALIES DETECTED] ({len(self.analysis_data['anomalies'])})")
            for anomaly in self.analysis_data['anomalies'][:5]:
                print(f"  ⚠ {anomaly}")
            if len(self.analysis_data['anomalies']) > 5:
                print(f"  ... and {len(self.analysis_data['anomalies']) - 5} more")

        print(f"\n[SECTIONS] ({len(self.analysis_data['sections'])})")
        for section in self.analysis_data['sections']:
            perms = ''.join([
                'R' if 'MEM_READ' in section['Characteristics']['flags'] else '-',
                'W' if 'MEM_WRITE' in section['Characteristics']['flags'] else '-',
                'X' if 'MEM_EXECUTE' in section['Characteristics']['flags'] else '-'
            ])
            print(f"  {section['Name']:10} | Entropy: {section['Entropy']:.2f} | Perms: {perms}")

        if self.analysis_data['imports']:
            print(f"\n[IMPORTS] ({len(self.analysis_data['imports'])} DLLs)")
            for dll in self.analysis_data['imports'][:5]:
                print(f"  {dll['dll']} ({len(dll['functions'])} functions)")
            if len(self.analysis_data['imports']) > 5:
                print(f"  ... and {len(self.analysis_data['imports']) - 5} more DLLs")

        if self.analysis_data['strings']['interesting']['urls']:
            print(f"\n[INTERESTING STRINGS - URLs]")
            for url in self.analysis_data['strings']['interesting']['urls'][:3]:
                print(f"  • {url}")

        if self.analysis_data['strings']['interesting']['ips']:
            print(f"\n[INTERESTING STRINGS - IPs]")
            for ip in self.analysis_data['strings']['interesting']['ips'][:3]:
                print(f"  • {ip}")

        print("\n" + "=" * 70 + "\n")


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python pe_analyzer.py <path_to_pe_file>")
        print("\nComprehensive PE Static Analyzer for Malware Analysis")
        print("Extracts maximum information from PE files including:")
        print("  - File hashes (MD5, SHA1, SHA256, ImpHash)")
        print("  - All PE headers and structures")
        print("  - Security features (ASLR, DEP, CFG, etc.)")
        print("  - Imports, Exports, Resources")
        print("  - TLS callbacks, Debug info, Relocations")
        print("  - Anomaly detection and packer signatures")
        print("  - String extraction with pattern matching")
        sys.exit(1)

    pe_path = sys.argv[1]

    if not os.path.exists(pe_path):
        print(f"[-] File not found: {pe_path}")
        sys.exit(1)

    # Create analyzer instance
    analyzer = PEStaticAnalyzer(pe_path)

    # Perform analysis
    results = analyzer.analyze()

    if results:
        # Print summary
        analyzer.print_summary()

        # Save detailed report
        report_path = analyzer.save_report()
    else:
        print("[-] Analysis failed!")
        sys.exit(1)