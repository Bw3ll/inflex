# TODO: This will take all of the results and run all of the final steps for the enrichment before passing the data to
#       the correlation sections. It will also need to clean up any redundant fields!?

# import lief
# from hashlib import md5

# def get_elf_imphash(file_path):
#     try:
#         # Parse the ELF file
#         elf_file = lief.parse(file_path)
        
#         # Extract and sort imported functions and libraries for a consistent hash
#         # The specific normalization might vary, a simple approach is:
#         imports_list = sorted([f"{lib.name}:{func.name}" for lib in elf_file.libraries for func in lib.functions])
        
#         # Join with commas and MD5 hash (similar to PE imphash convention)
#         imphash_string = ",".join(imports_list).encode()
#         imphash = md5(imphash_string).hexdigest()
#         return imphash
#     except lief.lief.exception.bad_format:
#         return "Not a valid ELF file or error parsing"

# # Example: Get imphash for an ELF file
# file_path_elf = "/bin/ls" # Replace with your ELF file path (e.g., a Linux binary)
# imphash_value_elf = get_elf_imphash(file_path_elf)
# print(f"The imphash for the ELF file is: {imphash_value_elf}")


"""
Static Analysis Pipeline Normalizer

This script normalizes static analysis results from different file formats
(PE, ELF, OLE, shellcode) into a unified format while preserving format-specific
details and maintaining the top-level structure (ingest_analysis, static_analysis, etc.)

Usage:
    python normalize_analysis.py input.json output.json
"""

import json
import re
import sys
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path


class AnalysisNormalizer:
    """Normalizes static analysis results across different file formats."""
    
    def __init__(self):
        self.format_type = None
    
    def detect_format(self, data: Dict[str, Any]) -> str:
        """Detect the file format from the analysis data."""
        ingest = data.get('ingest_analysis', {})
        static = data.get('static_analysis', {})

        detected_type = ingest.get('detected_type', '').lower()
        claimed_type = ingest.get('claimed_type', '').lower()
        basic_file_type = static.get('basic_info', {}).get('file_type', '') or ''

        # Check explicit shellcode markers first
        if 'shellcode' in detected_type or 'shellcode' in claimed_type or 'shellcode' in basic_file_type:
            return 'SHELLCODE'
        if static.get('shellcode'):
            return 'SHELLCODE'

        # Shellcode from SHAREM pipeline: file_type is 'rawHex'/'raw'/'bin' and inner normalized block present
        if basic_file_type.lower() in ('rawhex', 'raw', 'bin') and static.get('normalized'):
            return 'SHELLCODE'

        # Shellcode indicated by analysis_metadata classification string
        analysis_meta = static.get('analysis_metadata', {})
        if 'shellcode' in analysis_meta.get('shellcode_type', '').lower():
            return 'SHELLCODE'

        # Shellcode indicated by SHAREM emulation outputs (apis_called + emulation_summary)
        if static.get('apis_called') is not None and static.get('emulation_summary'):
            return 'SHELLCODE'

        # Shellcode indicated by disassembly annotation in static_analysis.disassembly list
        if isinstance(static.get('disassembly'), list):
            for ins in static['disassembly']:
                if isinstance(ins, dict) and 'shellcode entry point' in str(ins.get('annotation', '')).lower():
                    return 'SHELLCODE'

        if 'pe' in detected_type or 'portable executable' in detected_type:
            return 'PE'
        elif 'elf' in detected_type:
            return 'ELF'
        elif static.get('file_header') or static.get('dos_header'):
            return 'PE'
        elif static.get('elf_header'):
            return 'ELF'
        elif 'ole' in detected_type or 'office' in detected_type:
            return 'OLE'

        if isinstance(data.get('disassembly'), list):
            annotations = [str(ins.get('annotation', '')).lower() for ins in data.get('disassembly') if isinstance(ins, dict)]
            if any('shellcode' in a for a in annotations):
                return 'SHELLCODE'

        return 'UNKNOWN'
    
    def normalize_sections(self, sections: List[Dict], format_type: str) -> List[Dict]:
        """Normalize section data across formats."""
        normalized = []
        
        for section in sections:
            if format_type == 'PE':
                norm_section = {
                    'name': section.get('Name', ''),
                    'virtual_address': section.get('VirtualAddress'),
                    'virtual_size': section.get('VirtualSize'),
                    'raw_size': section.get('RawSize'),
                    'raw_offset': section.get('RawDataPointer'),
                    'entropy': section.get('Entropy'),
                    'permissions': section.get('Characteristics', {}).get('flags', []),
                    'hashes': {
                        'md5': section.get('MD5'),
                        'sha1': section.get('SHA1'),
                        'sha256': section.get('SHA256')
                    }
                }
            elif format_type == 'ELF':
                header = section.get('header', {})
                norm_section = {
                    'name': section.get('name', ''),
                    'virtual_address': header.get('sh_addr'),
                    'virtual_size': header.get('sh_size'),
                    'raw_size': header.get('sh_size'),
                    'raw_offset': header.get('sh_offset'),
                    'entropy': section.get('entropy'),  # May not be present
                    'permissions': self._elf_flags_to_permissions(header.get('sh_flags', 0)),
                    'type': header.get('sh_type'),
                    'hashes': section.get('hashes', {})
                }
            else:
                norm_section = section
            
            normalized.append(norm_section)
        
        return normalized
    
    def _elf_flags_to_permissions(self, flags: int) -> List[str]:
        """Convert ELF section flags to permission strings."""
        perms = []
        if flags & 0x1:  # SHF_WRITE
            perms.append('WRITE')
        if flags & 0x2:  # SHF_ALLOC
            perms.append('ALLOC')
        if flags & 0x4:  # SHF_EXECINSTR
            perms.append('EXECUTE')
        return perms
    
    def normalize_imports(self, imports: List[Dict], format_type: str) -> List[Dict]:
        """Normalize import data across formats."""
        normalized = []
        
        if format_type == 'PE':
            for dll in imports:
                norm_dll = {
                    'library': dll.get('dll', ''),
                    'functions': []
                }
                
                for func in dll.get('functions', []):
                    norm_func = {
                        'name': func.get('name'),
                        'address': func.get('address'),
                        'ordinal': func.get('ordinal'),
                        'hint': func.get('hint')
                    }
                    norm_dll['functions'].append(norm_func)
                
                normalized.append(norm_dll)
        
        elif format_type == 'ELF':
            # ELF imports are typically in dynamic symbols
            # This would need to be adapted based on your ELF analyzer output
            normalized = imports
        
        return normalized
    
    def normalize_symbols(self, static_data: Dict, format_type: str) -> List[Dict]:
        """Extract and normalize symbol information."""
        symbols = []
        
        if format_type == 'ELF':
            symbol_tables = static_data.get('symbol_tables', [])
            for table in symbol_tables:
                for symbol in table.get('symbols', []):
                    symbols.append({
                        'name': symbol.get('name'),
                        'value': symbol.get('value'),
                        'size': symbol.get('size'),
                        'type': symbol.get('type'),
                        'binding': symbol.get('bind'),
                        'visibility': symbol.get('visibility')
                    })
        
        return symbols
    
    def normalize_security_features(self, static_data: Dict, format_type: str) -> Dict[str, Any]:
        """Normalize security features across formats."""
        if format_type == 'PE':
            return static_data.get('security_features', {})
        elif format_type == 'ELF':
            security = static_data.get('security', {})
            # Map ELF security features to more generic names
            return {
                'NX': security.get('nx', False),
                'PIE': security.get('pie', False),
                'RELRO': security.get('relro', 'none'),
                'StackCanary': security.get('stack_canary', False)
            }
        return {}
    
    def extract_format_specific_pe(self, static_data: Dict) -> Dict[str, Any]:
        """Extract PE-specific fields that don't map to common structure."""
        return {
            'dos_header': static_data.get('dos_header'),
            'rich_header': static_data.get('rich_header'),
            'file_header': static_data.get('file_header'),
            'optional_header': static_data.get('optional_header'),
            'data_directories': static_data.get('data_directories'),
            'exports': static_data.get('exports'),
            'resources': static_data.get('resources'),
            'version_info': static_data.get('version_info'),
            'digital_signature': static_data.get('digital_signature'),
            'tls': static_data.get('tls'),
            'debug': static_data.get('debug'),
            'delay_imports': static_data.get('delay_imports')
        }
    
    def extract_format_specific_elf(self, static_data: Dict) -> Dict[str, Any]:
        """Extract ELF-specific fields that don't map to common structure."""
        return {
            'elf_header': static_data.get('elf_header'),
            'program_headers': static_data.get('program_headers'),
            'section_headers': static_data.get('section_headers'),
            'relocations': static_data.get('relocations'),
            'dynamic': static_data.get('dynamic'),
            'interpreter': static_data.get('interpreter'),
            'notes': static_data.get('notes'),
            'dwarf': static_data.get('dwarf'),
            'symbol_tables': static_data.get('symbol_tables')
        }
    

    def _get_shellcode_source(self, static_data: Dict) -> Dict[str, Any]:
        """
        SHAREM produces a rich inner 'normalized' block inside static_analysis.
        Prefer that when available; fall back to the flat static_analysis fields.
        """
        inner = static_data.get('normalized', {})
        if inner:
            return inner.get('static_analysis', {})
        return {}

    def normalize_shellcode_hashes(self, static_data: Dict) -> Dict[str, Any]:
        """Build unified hashes block for shellcode samples."""
        inner = self._get_shellcode_source(static_data)
        # Prefer inner normalized hashes, fall back to basic_info hashes
        hashes = inner.get('hashes') or {}
        bi = static_data.get('basic_info', {})
        return {
            'md5':    hashes.get('md5')    or bi.get('md5'),
            'sha1':   hashes.get('sha1'),
            'sha256': hashes.get('sha256') or bi.get('sha256'),
            'ssdeep': hashes.get('ssdeep') or bi.get('ssdeep'),
        }

    def normalize_shellcode_basic_info(self, static_data: Dict) -> Dict[str, Any]:
        """Build unified basic_info block for shellcode samples."""
        inner = self._get_shellcode_source(static_data)
        inner_bi = inner.get('basic_info', {})
        bi = static_data.get('basic_info', {})
        analysis_meta = static_data.get('analysis_metadata', {})
        return {
            'filename':    inner_bi.get('filename')    or bi.get('filename'),
            'file_size':   inner_bi.get('file_size')   or bi.get('file_size'),
            'file_type':   'SHELLCODE',
            'bits':        inner_bi.get('bits')        or bi.get('bits'),
            'arch':        inner_bi.get('arch')        or analysis_meta.get('architecture'),
            'entry_point': inner_bi.get('entry_point') or bi.get('entry_point'),
            'entropy':     inner_bi.get('entropy')     or bi.get('entropy'),
        }

    def normalize_shellcode_strings(self, static_data: Dict) -> Dict[str, Any]:
        """Build unified strings block from SHAREM shellcode output."""
        inner = self._get_shellcode_source(static_data)
        sc_block = inner.get('shellcode', {})
        strings_detailed = sc_block.get('strings_detailed', {})

        # Also collect from flat strings_found list
        flat_strings = static_data.get('strings_found', [])
        flat_ascii = [s for s in flat_strings if s.get('type') in ('ascii',)]
        flat_push  = [s for s in flat_strings if s.get('type') == 'pushString']

        ascii_list = strings_detailed.get('ascii') or flat_ascii
        unicode_list = strings_detailed.get('unicode', [])
        push_list  = strings_detailed.get('push_stack') or flat_push

        return {
            'ascii':      ascii_list,
            'unicode':    unicode_list,
            'push_stack': push_list,
        }

    def normalize_shellcode_apis(self, static_data: Dict) -> List[Dict]:
        """
        Normalise the apis_called list (flat SHAREM format) into a
        library-grouped structure consistent with PE imports, plus
        preserves full argument detail.
        """
        apis = static_data.get('apis_called', [])
        if not apis:
            # Fall back to sharem_emulation block inside threat_intelligence
            return []
        by_dll: Dict[str, Dict] = {}
        for api in apis:
            dll = api.get('dll', 'unknown')
            if dll not in by_dll:
                by_dll[dll] = {'library': dll, 'functions': []}
            by_dll[dll]['functions'].append({
                'name':         api.get('name'),
                'address':      api.get('address'),
                'signature':    api.get('signature'),
                'return_value': api.get('return_value'),
                'arguments':    api.get('arguments', []),
            })
        return list(by_dll.values())

    def _normalize_shellcode_instruction(self, instruction: str) -> str:
        if not instruction:
            return ""
        normalized = re.sub(r'0x[0-9a-fA-F]+|\b\d+\b', 'CONST', instruction)
        normalized = normalized.replace(',', ' ').strip().lower()
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized

    def _get_shellcode_disassembly_instructions(self, static_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        inner = self._get_shellcode_source(static_data)
        inner_disasm = inner.get('disassembly', {})
        if isinstance(inner_disasm, dict):
            instructions = inner_disasm.get('instructions')
            if isinstance(instructions, list):
                return instructions
        flat_disasm = static_data.get('disassembly', [])
        if isinstance(flat_disasm, dict):
            return flat_disasm.get('instructions', []) or []
        if isinstance(flat_disasm, list):
            return flat_disasm
        return []

    def normalize_shellcode_functions(self, static_data: Dict[str, Any]) -> Dict[str, Any]:
        instructions = self._get_shellcode_disassembly_instructions(static_data)
        if not instructions:
            return {
                'functions': [],
                'function_count': 0,
                'similar_binaries': [],
            }

        normalized_ops = [
            self._normalize_shellcode_instruction(
                ins.get('instruction') or ins.get('disasm') or ''
            )
            for ins in instructions
        ]
        func_hash = hashlib.sha256(
            '\n'.join(normalized_ops).encode('utf-8', errors='replace')
        ).hexdigest()

        mnemonics = [ins.get('instruction') or ins.get('disasm') or '' for ins in instructions]
        total_size = 0
        for ins in instructions:
            size_val = ins.get('size') or ins.get('length') or 0
            try:
                total_size += int(size_val)
            except Exception:
                pass

        shellcode_function = {
            'name': 'shellcode_entry',
            'offset': instructions[0].get('offset') if instructions else '0x0',
            'size': total_size or len(instructions),
            'func_hash': func_hash,
            'mnemonics': mnemonics,
            'instructions': instructions,
        }

        return {
            'functions': [shellcode_function],
            'function_count': 1,
            'similar_binaries': [],
        }

    def extract_format_specific_shellcode(self, static_data: Dict) -> Dict[str, Any]:
        """
        Extract all shellcode-specific fields that do not map to the common
        normalised structure and place them in format_specific so that the
        analysis UI can render them without touching PE/ELF paths.
        """
        inner = self._get_shellcode_source(static_data)
        sc_block = inner.get('shellcode', {})
        analysis_meta = static_data.get('analysis_metadata', {})
        emulation_summary = static_data.get('emulation_summary', {})

        # Disassembly: prefer the richer inner version (has data_type / data_accessed)
        inner_disasm = inner.get('disassembly', {})
        flat_disasm  = static_data.get('disassembly', [])

        # Registry, network, file, syscall artefacts
        registry   = static_data.get('registry_operations', {})
        network    = static_data.get('network_indicators', [])
        file_ops   = static_data.get('file_operations', [])
        syscalls   = static_data.get('syscalls', [])
        artifacts  = static_data.get('artifacts', {})
        dlls_loaded = static_data.get('dlls_loaded', [])

        return {
            # Classification
            'classification':        sc_block.get('classification')        or analysis_meta.get('shellcode_type'),
            'classification_reason': sc_block.get('classification_reason') or analysis_meta.get('classification_reason'),
            'features_detected':     sc_block.get('features_detected')     or analysis_meta.get('features_detected', []),
            # Raw bytes
            'shellcode_hex': sc_block.get('shellcode_hex') or {
                'rawhex': static_data.get('basic_info', {}).get('shellcode_hex'),
                'strlit': static_data.get('basic_info', {}).get('shellcode_strlit'),
            },
            # Deobfuscation
            'deobfuscation': sc_block.get('deobfuscation', static_data.get('deobfuscation', {})),
            # Shellcode-specific indicators (push/ret, call/pop, PEB walk, etc.)
            'indicators': sc_block.get('indicators', {}),
            # Disassembly with full per-instruction metadata
            'disassembly': inner_disasm if inner_disasm else {'instructions': flat_disasm},
            # Dynamic / emulation artefacts
            'emulation_summary': emulation_summary or inner.get('emulation_summary', {}),
            'dlls_loaded':       dlls_loaded,
            'artifacts':         artifacts,
            'syscalls':          syscalls,
            'network_indicators': network,
            'file_operations':   file_ops,
            'registry':          registry,
            # Annotations list (offset → description)
            'disassembly_annotations': static_data.get('disassembly_annotations', []),
        }

    def normalize_shellcode_threat_intelligence(self, data: Dict) -> Dict[str, Any]:
        """
        Merge the top-level threat_intelligence with the richer sharem_emulation
        block that lives inside static_analysis.normalized.threat_intelligence.
        """
        top_ti = data.get('threat_intelligence', {})
        inner  = data.get('static_analysis', {}).get('normalized', {}).get('threat_intelligence', {})

        merged = dict(top_ti)
        # Bring sharem_emulation up from inner if not already at top level
        if 'sharem_emulation' not in merged and inner.get('sharem_emulation'):
            merged['sharem_emulation'] = inner['sharem_emulation']
        return merged

    def normalize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize the entire analysis result.
        
        Maintains top-level structure (ingest_analysis, static_analysis, etc.)
        while standardizing common fields and preserving format-specific data.
        """
        self.format_type = self.detect_format(data)
        
        # Preserve top-level structure
        normalized = {
            'format_type': self.format_type,
            'ingest_analysis': data.get('ingest_analysis', {}),
            'analysis_timestamps': data.get('analysis_timestamps', {}),
        }
        
        # Normalize static_analysis section
        static_data = data.get('static_analysis', {})
        
        # Get imports before normalization
        raw_imports = static_data.get('imports', [])
        
        if self.format_type == 'SHELLCODE':
            #  SHELLCODE path: pull from SHAREM's inner normalized block 
            inner_sa = self._get_shellcode_source(static_data)
            shellcode_disasm = self.normalize_shellcode_functions(static_data)
            normalized_static = {
                'metadata': inner_sa.get('metadata', static_data.get('metadata', {})),
                'hashes':   self.normalize_shellcode_hashes(static_data),
                'basic_info': self.normalize_shellcode_basic_info(static_data),
                # Shellcode has no PE/ELF sections; keep empty list for schema compat
                'sections': [],
                # APIs called grouped by DLL (mirrors PE imports structure)
                'imports':  self.normalize_shellcode_apis(static_data),
                'symbols':  [],
                # Shellcode has no traditional security mitigations
                'security_features': inner_sa.get('security_features', {}),
                'strings':      self.normalize_shellcode_strings(static_data),
                'yara_matches': static_data.get('yara_matches'),
                'mitre_mapping': static_data.get('mitre_mapping'),
                'virustotal': static_data.get('virustotal'),
                'packing':    None,
                'functions': shellcode_disasm['functions'],
                'function_count': shellcode_disasm['function_count'],
                'similar_binaries': shellcode_disasm['similar_binaries'],
                # All shellcode-specific rich data lives here
                'format_specific': self.extract_format_specific_shellcode(static_data),
            }
        else:
            #  PE / ELF / UNKNOWN path (original logic, untouched) 
            normalized_static = {
                'metadata': static_data.get('metadata', {}),

                # Common fields across all formats
                'hashes': static_data.get('hashes', {}),

                'basic_info': {
                    'filename': static_data.get('basic_info', {}).get('filename'),
                    'file_size': static_data.get('basic_info', {}).get('file_size'),
                    'file_type': self.format_type
                },

                # Normalized structures
                'sections': self.normalize_sections(
                    static_data.get('sections', []) or static_data.get('section_headers', []),
                    self.format_type
                ),

                'imports': self.normalize_imports(raw_imports, self.format_type),

                'symbols': self.normalize_symbols(static_data, self.format_type),

                'security_features': self.normalize_security_features(static_data, self.format_type),

                # Optional common fields
                'strings': static_data.get('strings'),
                'yara_matches': static_data.get('yara_matches'),
                'mitre_mapping': static_data.get('mitre_mapping'),
                'virustotal': static_data.get('virustotal'),
                'packing': static_data.get('packing'),
            }

            # Add format-specific data in a separate section
            if self.format_type == 'PE':
                normalized_static['format_specific'] = self.extract_format_specific_pe(static_data)
            elif self.format_type == 'ELF':
                normalized_static['format_specific'] = self.extract_format_specific_elf(static_data)
        
        # Include disassembly data (common across formats)
        if 'disassembly' in static_data:
            normalized_static['disassembly'] = static_data['disassembly']
        
        # Include function analysis if present
        if 'functions' in static_data:
            normalized_static['functions'] = static_data['functions']
        if 'function_count' in static_data:
            normalized_static['function_count'] = static_data['function_count']
        if 'similar_binaries' in static_data:
            normalized_static['similar_binaries'] = static_data['similar_binaries']
        
        normalized['static_analysis'] = normalized_static
        
        # Preserve other top-level sections
        if 'disassembly' in data:
            normalized['disassembly'] = data['disassembly']

        if 'threat_intelligence' in data:
            if self.format_type == 'SHELLCODE':
                normalized['threat_intelligence'] = self.normalize_shellcode_threat_intelligence(data)
            else:
                normalized['threat_intelligence'] = data['threat_intelligence']
        
        if 'description' in data:
            normalized['description'] = data['description']
        
        if 'mitre' in data:
            normalized['mitre'] = data['mitre']
        
        if 'extracted' in data:
            normalized['extracted'] = data['extracted']
        
        # Preserve stegoscan results
        if 'stegoscan' in data:
            normalized['stegoscan'] = data['stegoscan']
        
        return normalized
    

def normalize(input_path: Path, output_path: Path):
    """Normalize the analysis results from input_path and save to output_path."""
    # Load input data
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Normalize
    normalizer = AnalysisNormalizer()
    normalized_data = normalizer.normalize(data)
    
    # Save output
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(normalized_data, f, indent=2)
    
    print(f"Successfully normalized {input_path} -> {output_path}")
    print(f"Detected format: {normalized_data['format_type']}")


def main():
    """Main entry point for the normalization script."""
    if len(sys.argv) != 3:
        print("Usage: python normalize_analysis.py <input.json> <output.json>")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' not found")
        sys.exit(1)
    
    try:
        # Load input data
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Normalize
        normalizer = AnalysisNormalizer()
        normalized_data = normalizer.normalize(data)
        
        # Save output
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(normalized_data, f, indent=2)
        
        print(f"Successfully normalized {input_path} -> {output_path}")
        print(f"Detected format: {normalized_data['format_type']}")
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
