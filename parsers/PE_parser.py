# TODO: Look at Subparse (https://github.com/jstrosch/subparse/blob/main/parser/src/parsers/PEParser.py) for a starting
#       point in building out this parser to get everything we need for the static analysis and create an output JSON
#       with that information

import pefile
import os
import json
import hashlib
import re
from datetime import datetime
from pathlib import Path


class PEStaticAnalyzer:
    """
    Comprehensive PE file static analyzer for malware analysis.
    Extracts maximum possible information from PE files.
    """

    def __init__(self, pe_file_path):
        """
        Initialize the analyzer with a PE file path.

        Args:
            pe_file_path (str): Path to the PE file to analyze
        """
        self.pe_file_path = pe_file_path
        self.pe = None
        self.analysis_data = {}

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

    def get_resources(self):
        """Extract detailed resource information."""
        resources = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData,
                                                            resource_lang.data.struct.Size)
                                    res_data = {
                                        'type': pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id)),
                                        'id': resource_id.id,
                                        'lang': resource_lang.id,
                                        'sublang': resource_lang.id & 0x3F,
                                        'size': resource_lang.data.struct.Size,
                                        'offset': hex(resource_lang.data.struct.OffsetToData),
                                        'md5': hashlib.md5(data).hexdigest(),
                                        'entropy': self._calculate_entropy(data)
                                    }
                                    resources.append(res_data)
        except Exception as e:
            print(f"Error extracting resources: {e}")
        return resources

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x).bit_length()
        return round(entropy, 4)

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
            'crypto_indicators': []
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

            # IPs
            ips = ip_pattern.findall(s)
            interesting['ips'].extend(ips)

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

        # Deduplicate and limit
        for key in interesting:
            interesting[key] = list(set(interesting[key]))[:100]  # Limit to 100 per category

        return interesting

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
            'resources': self.get_resources(),
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
            'strings': self.extract_strings()
        }

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
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(merged_data, f, indent=2, ensure_ascii=False)
            print(f"[+] Report saved to: {report_path}")
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
