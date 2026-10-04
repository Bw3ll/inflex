"""
OLE Static Analysis Module - Professional Grade
Enhanced with deobfuscation, MITRE mapping, complexity analysis, and more
Cross-platform compatible: Linux (testing) and Windows (production)
"""

import io
import os
import sys
import json
import hashlib
import subprocess
import re
import base64
import contextlib
import importlib
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

# Detect platform
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

def get_system_python_executable() -> str:
    """
    Get the system Python executable, preferring system Python over venv.
    This is useful for running tools like oledump.py that may have dependency issues in venvs.
    """
    import shutil
    
    # If we're in a venv, try to find the system Python
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        # We're in a venv, try to find system python
        
        # On Windows, try common locations
        if IS_WINDOWS:
            candidates = [
                r'C:\Python314\python.exe',
                r'C:\Python313\python.exe',
                r'C:\Python312\python.exe',
                r'C:\Python311\python.exe',
                shutil.which('python'),  # System python in PATH
                shutil.which('python3'),  # Fallback to python3
            ]
            for candidate in candidates:
                if candidate and os.path.exists(candidate):
                    return candidate
        
        # On Linux, use system python
        system_python = shutil.which('python3') or shutil.which('python')
        if system_python:
            return system_python
    
    # Not in a venv or couldn't find system python, use current executable
    return sys.executable

# Platform-specific imports
PYWIN32_AVAILABLE = False
if IS_WINDOWS:
    try:
        import win32com.client
        import pythoncom
        PYWIN32_AVAILABLE = True
    except ImportError:
        print("Warning: pywin32 not available on Windows. Some features disabled.")
        PYWIN32_AVAILABLE = False

# Import oletools components
# try:
#     from oletools import olevba
#     from oletools.oleid import OleID
#     from oletools.olemeta import OleMetaFile  
#     from oletools.oleobj import find_ole_objects
#     from oletools.rtfobj import RtfObjParser
#     from oletools.common.io_encoding import ensure_stdout_handles_unicode
# except ImportError:
#     print("Error: oletools not installed. Run: pip install oletools")
#     sys.exit(1)
from oletools import olevba
from oletools.oleid import OleID
# from oletools.olemeta import OleMetaFile
# from oletools.oleobj import find_ole_objects
from oletools.rtfobj import RtfObjParser
from oletools.common.io_encoding import ensure_stdout_handles_unicode
# from oletools import olemeta
import olefile
from oletools.oleobj import find_ole, OleNativeStream



def _safe_import_module(module_name: str):
    """Import a module while suppressing native stderr output from failed imports."""
    try:
        result = subprocess.run(
            [sys.executable, '-c', f'import {module_name}'],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        return importlib.import_module(module_name)
    except Exception:
        return None

# Import for YARA scanning via standalone scanner module
YaraPEScanner = None

yara = _safe_import_module('yara')
if yara is None:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from static_analysis.YARA import YaraPEScanner
    except Exception:
        YaraPEScanner = None
else:
    try:
        from static_analysis.YARA import YaraPEScanner
    except Exception:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from static_analysis.YARA import YaraPEScanner
        except Exception:
            YaraPEScanner = None

if yara is None and YaraPEScanner is None:
    print("Warning: yara-python not installed or failed to load. YARA scanning will be disabled.")


def _b(v):
    """
    Coerce a value that oletools/olefile may return as bytes into a str.
    All other types are returned unchanged.
    """
    if isinstance(v, (bytes, bytearray)):
        return v.decode('utf-8', errors='replace')
    return v


def _sanitize(obj):
    """
    Recursively make an object JSON-serializable.
    Converts bytes -> str, type objects -> str, leaves everything else alone.
    """
    if isinstance(obj, dict):
        return {str(k): _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize(i) for i in obj]
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, type):
        return obj.__name__
    # datetime, int, float, bool, str, None all pass through unchanged
    return obj


class OLEStaticAnalyzer:
    """Comprehensive static analysis for OLE files"""
    
    # Non-obfuscatable VBA keywords
    VBA_KEYWORDS = {
        'sub', 'function', 'end', 'exit',
        'if', 'then', 'else', 'elseif', 'endif',
        'for', 'to', 'step', 'next',
        'while', 'wend', 'do', 'loop', 'until',
        'select', 'case',
        'dim', 'redim', 'const', 'static', 'private', 'public',
        'as', 'integer', 'string', 'long', 'double', 'boolean', 'variant', 'object',
        'set', 'new', 'nothing', 'createobject', 'getobject',
        'call', 'shell', 'run', 'exec',
        'on', 'error', 'resume', 'goto',
        'and', 'or', 'not', 'xor', 'mod', 'is',
        'environ', 'chr', 'strreverse', 'replace', 'mid', 'left', 'right',
        'open', 'close', 'write', 'print', 'get', 'put',
    }
    
    # Auto-execute methods
    AUTO_EXEC_METHODS = {
        # Word
        'autoexec', 'autoopen', 'auto_open', 'autoclose', 'auto_close',
        'document_open', 'document_close', 'document_beforeclose',
        'documentchange', 'autonew', 'auto_new', 'newdocument',
        
        # Excel  
        'workbook_open', 'workbook_activate', 'workbook_beforeclose', 
        'workbook_deactivate',
        
        # PowerPoint
        'presentation_open', 'slideshowbegin',
    }
    
    # MITRE ATT&CK patterns
    MITRE_PATTERNS = {
        'T1566.001': {
            'name': 'Phishing: Spearphishing Attachment',
            'indicators': ['autoopen', 'document_open', 'workbook_open'],
            'severity': 'high'
        },
        'T1059.005': {
            'name': 'Command and Scripting Interpreter: Visual Basic',
            'indicators': ['shell', 'wscript.shell', 'shell.application', 'createobject'],
            'severity': 'high'
        },
        'T1140': {
            'name': 'Deobfuscate/Decode Files or Information',
            'indicators': ['chr(', 'strreverse', 'base64', 'xor'],
            'severity': 'medium'
        },
        'T1105': {
            'name': 'Ingress Tool Transfer',
            'indicators': ['xmlhttp', 'urldownloadtofile', 'msxml2', 'serverxmlhttp'],
            'severity': 'high'
        },
        'T1204.002': {
            'name': 'User Execution: Malicious File',
            'indicators': ['autoopen', 'auto_open'],
            'severity': 'high'
        },
        'T1027': {
            'name': 'Obfuscated Files or Information',
            'indicators': ['chr(', '&', 'strreverse', 'replace('],
            'severity': 'medium'
        },
        'T1071.001': {
            'name': 'Application Layer Protocol: Web Protocols',
            'indicators': ['http', 'https', 'xmlhttp', 'get', 'post'],
            'severity': 'medium'
        },
        'T1059.003': {
            'name': 'Command and Scripting Interpreter: Windows Command Shell',
            'indicators': ['cmd', 'powershell', 'wscript', 'cscript'],
            'severity': 'high'
        }
    }
    
    # Risk scores for oletools oleid
    RISK_HIGH = 3
    RISK_MEDIUM = 2
    RISK_LOW = 1

    def __init__(self, file_path: str, oledump_path: str = None, yara_rules_path: str = None):
        self.file_path = file_path
        self.oledump_path = oledump_path or "oledump.py"
        self.yara_rules_path = yara_rules_path
        self.yara_rules = None
        self.yara_scanner = None
        
        # Platform information
        self.platform = platform.system()
        self.is_windows = IS_WINDOWS
        self.is_linux = IS_LINUX
        self.pywin32_available = PYWIN32_AVAILABLE

        # Load YARA rules via standalone scanner if available
        if yara_rules_path and os.path.exists(yara_rules_path):
            if YaraPEScanner:
                try:
                    self.yara_scanner = YaraPEScanner(rules_dir=yara_rules_path)
                    self.yara_scanner.initialize(skip_clone=True, update=False, verbose=False)
                    if not getattr(self.yara_scanner, '_initialized', False):
                        self.yara_scanner = None
                except Exception as e:
                    print(f"Warning: Failed to initialize YARA scanner: {e}")
                    self.yara_scanner = None

            # Fallback to direct yara-python loading if the scanner is unavailable
            if self.yara_scanner is None and yara:
                try:
                    if os.path.isfile(yara_rules_path):
                        self.yara_rules = yara.compile(filepath=yara_rules_path)
                    elif os.path.isdir(yara_rules_path):
                        rule_files = {}
                        for ext in ['*.yar', '*.yara']:
                            for rule_file in Path(yara_rules_path).glob(ext):
                                rule_files[rule_file.stem] = str(rule_file)
                        if rule_files:
                            self.yara_rules = yara.compile(filepaths=rule_files)
                except Exception as e:
                    print(f"Warning: Failed to load YARA rules directly: {e}")

    def calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
        
        with open(self.file_path, 'rb') as f:
            while chunk := f.read(8192):
                for h in hashes.values():
                    h.update(chunk)
        
        return {name: h.hexdigest() for name, h in hashes.items()}

    def get_file_info(self) -> Dict[str, Any]:
        """Get basic file information"""
        stat = os.stat(self.file_path)
        
        return {
            'filename': os.path.basename(self.file_path),
            'file_size': stat.st_size,
            'file_path': os.path.abspath(self.file_path),
            'modification_time': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            'creation_time': datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
        }

    def run_oleid(self) -> Dict[str, Any]:
        """Run oleid for file identification - FIXED API"""
        try:
            oid = OleID(self.file_path)
            indicators = oid.check()

            results = {
                'indicators': [],
                'risk_score': 0,
                'file_type': None
            }

            for indicator in indicators:
                # Get risk value properly
                risk_val = indicator.value if hasattr(indicator, 'value') else None
                
                ind_dict = {
                    'id': indicator.id,
                    'name': indicator.name,
                    'value': str(risk_val),
                    'type': indicator.type if hasattr(indicator, 'type') else 'unknown',
                    'risk': str(indicator.risk) if hasattr(indicator, 'risk') else 'unknown',
                    'description': indicator.description if hasattr(indicator, 'description') else ''
                }
                results['indicators'].append(ind_dict)

                # Calculate risk score using string comparison (API changed)
                if hasattr(indicator, 'risk'):
                    risk_str = str(indicator.risk).lower()
                    if 'high' in risk_str:
                        results['risk_score'] += self.RISK_HIGH
                    elif 'medium' in risk_str:
                        results['risk_score'] += self.RISK_MEDIUM
                    elif 'low' in risk_str:
                        results['risk_score'] += self.RISK_LOW

                # Extract file type
                if indicator.id == 'ole_format':
                    results['file_type'] = str(risk_val)

            return _sanitize(results)
        except Exception as e:
            return {'error': str(e)}

    def run_olemeta(self) -> Dict[str, Any]:
        """Extract OLE metadata - FIXED API"""
        try:
            # meta = OleMetaFile(self.file_path)
            # meta.parse_properties()

            ole = olefile.OleFileIO(self.file_path)
            meta = ole.get_metadata()

            metadata = {}

            for prop in meta.SUMMARY_ATTRIBS:
                value = getattr(meta, prop)
                if value is not None:
                    metadata[prop] = value

            for prop in meta.DOCSUM_ATTRIBS:
                value = getattr(meta, prop)
                if value is not None:
                    metadata[prop] = value

            ole.close()

            
            result = {}
            
            # Extract summary information
            if hasattr(meta, 'author'):
                result['author'] = meta.author
            if hasattr(meta, 'title'):
                result['title'] = meta.title
            if hasattr(meta, 'subject'):
                result['subject'] = meta.subject
            if hasattr(meta, 'create_time'):
                result['create_time'] = str(meta.create_time)
            if hasattr(meta, 'modify_time'):
                result['modify_time'] = str(meta.modify_time)
                
            return _sanitize(result)
        except Exception as e:
            return {'error': str(e)}

    def run_oleobj(self) -> dict:
        try:
            results = {
                "objects": [],
                "total_objects": 0
            }

            # find_ole yields OleFileIO objects
            for ole in find_ole(self.file_path, data=None):
                if ole is None:
                    continue

                for path_parts in ole.listdir():
                    # Ole10Native is case-insensitive
                    if path_parts[-1].lower() == "\x01ole10native":
                        stream = ole.openstream(path_parts)

                        try:
                            native = OleNativeStream(stream)

                            if native.is_link:
                                continue  # linked, not embedded

                            obj_info = {
                                "filename": native.filename,
                                "source_path": native.src_path,
                                "temp_path": native.temp_path,
                                "size": native.actual_size,
                                "is_link": native.is_link,
                            }

                            results["objects"].append(obj_info)
                            results["total_objects"] += 1

                        finally:
                            stream.close()

                ole.close()

            return _sanitize(results)

        except Exception as e:
            return {"error": str(e)}

    def run_olevba(self) -> Dict[str, Any]:
        """Extract and analyze VBA macros"""
        try:
            vba_parser = olevba.VBA_Parser(self.file_path)

            results = {
                'has_macros': False,
                'macros': [],
                'suspicious_keywords': [],
                'iocs': {
                    'urls': [],
                    'ips': [],
                    'emails': [],
                    'executables': [],
                    'suspicious_strings': []
                },
                'auto_exec': [],
                'analysis_summary': {}
            }

            if not vba_parser.detect_vba_macros():
                return results

            results['has_macros'] = True

            # Extract macros
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                macro_info = {
                    'filename': filename,
                    'stream_path': stream_path,
                    'vba_filename': vba_filename,
                    'code_length': len(vba_code),
                    'code_hash': hashlib.sha256(vba_code.encode()).hexdigest()
                }
                results['macros'].append(macro_info)

            # Analyze macros
            analysis_results = vba_parser.analyze_macros()
            if analysis_results:
                for kw_type, keyword, description in analysis_results:
                    keyword_info = {
                        'type': kw_type,
                        'keyword': keyword,
                        'description': description
                    }
                    results['suspicious_keywords'].append(keyword_info)

                    if kw_type == 'AutoExec':
                        results['auto_exec'].append(keyword)

            # Extract IOCs
            try:
                for indicator_type, value in vba_parser.find_iocs():
                    if indicator_type == 'URL':
                        results['iocs']['urls'].append(value)
                    elif indicator_type == 'IP':
                        results['iocs']['ips'].append(value)
                    elif indicator_type == 'Email':
                        results['iocs']['emails'].append(value)
                    elif indicator_type == 'Executable':
                        results['iocs']['executables'].append(value)
                    else:
                        results['iocs']['suspicious_strings'].append(value)
            except:
                pass

            # Summary
            results['analysis_summary'] = {
                'total_macros': len(results['macros']),
                'suspicious_keywords_count': len(results['suspicious_keywords']),
                'auto_exec_count': len(results['auto_exec']),
                'ioc_count': sum(len(v) for v in results['iocs'].values())
            }

            vba_parser.close()
            return results

        except Exception as e:
            return {'error': str(e), 'has_macros': False}

    def run_rtfobj(self) -> Dict[str, Any]:
        """Extract objects from RTF files"""
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(5)
                if header != b'{\\rtf':
                    return {'is_rtf': False}

            results = {
                'is_rtf': True,
                'objects': []
            }

            rtfobj_parser = RtfObjParser(self.file_path)
            rtfobj_parser.parse()

            for obj in rtfobj_parser.objects:
                obj_info = {
                    'index': obj.index,
                    'class_name': obj.class_name,
                    'size': obj.rawdata_size if hasattr(obj, 'rawdata_size') else None,
                    'format': obj.format_type if hasattr(obj, 'format_type') else None,
                    'is_ole': obj.is_ole if hasattr(obj, 'is_ole') else False,
                    'is_package': obj.is_package if hasattr(obj, 'is_package') else False
                }
                results['objects'].append(obj_info)

            return _sanitize(results)

        except Exception as e:
            return {'error': str(e), 'is_rtf': False}
    
    def deobfuscate_vba(self, code: str) -> Tuple[str, List[str]]:
        """
        Apply common VBA deobfuscation techniques
        Returns: (deobfuscated_code, list of techniques used)
        """
        techniques_used = []
        original_code = code
        
        # 1. Resolve Chr() calls
        chr_pattern = r'Chr\((\d+)\)'
        chr_matches = re.findall(chr_pattern, code, re.IGNORECASE)
        if chr_matches:
            for match in chr_matches:
                try:
                    char_code = int(match)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        code = re.sub(
                            rf'Chr\({match}\)',
                            f'"{chr(char_code)}"',
                            code,
                            flags=re.IGNORECASE
                        )
                except:
                    pass
            if chr_matches:
                techniques_used.append('chr_decoding')
        
        # 2. Resolve string concatenation (simple cases)
        concat_pattern = r'"([^"]+)"\s*&\s*"([^"]+)"'
        if re.search(concat_pattern, code):
            code = re.sub(concat_pattern, r'"\1\2"', code)
            techniques_used.append('string_concatenation')
        
        # 3. Decode base64 strings (if found)
        base64_pattern = r'"([A-Za-z0-9+/]{20,}={0,2})"'
        base64_matches = re.findall(base64_pattern, code)
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match).decode('ascii', errors='ignore')
                if decoded.isprintable() and len(decoded) > 3:
                    code = code.replace(f'"{match}"', f'"{decoded}"')
                    if 'base64_decoding' not in techniques_used:
                        techniques_used.append('base64_decoding')
            except:
                pass
        
        # 4. Resolve simple StrReverse
        reverse_pattern = r'StrReverse\("([^"]+)"\)'
        reverse_matches = re.findall(reverse_pattern, code, re.IGNORECASE)
        for match in reverse_matches:
            reversed_str = match[::-1]
            code = re.sub(
                rf'StrReverse\("{re.escape(match)}"\)',
                f'"{reversed_str}"',
                code,
                flags=re.IGNORECASE
            )
        if reverse_matches:
            techniques_used.append('string_reverse')
        
        return code, techniques_used

    def detect_auto_exec_comprehensive(self, functions: List[Dict]) -> List[Dict]:
        """Detect ALL auto-execution entry points"""
        auto_exec = []
        
        for func in functions:
            func_name_lower = func['name'].lower()
            
            for method in self.AUTO_EXEC_METHODS:
                if method in func_name_lower:
                    auto_exec.append({
                        'function': func['name'],
                        'type': func['type'],
                        'method': method,
                        'stream': func['stream'],
                        'line': func['start_line'],
                        'risk': 'HIGH' if 'open' in method else 'MEDIUM'
                    })
                    break
        
        return auto_exec

    def map_to_mitre(self, functions: List[Dict], code_samples: Dict[str, str]) -> List[Dict]:
        """Map observed behaviors to MITRE ATT&CK techniques"""
        techniques = []
        
        for technique_id, pattern in self.MITRE_PATTERNS.items():
            matches = []
            confidence_score = 0
            
            # Check function names
            for func in functions:
                func_name_lower = func['name'].lower()
                for indicator in pattern['indicators']:
                    if indicator in func_name_lower:
                        matches.append(f"Function name: {func['name']}")
                        confidence_score += 2
            
            # Check keywords in functions
            for func in functions:
                keywords_str = ' '.join(func.get('keywords', [])).lower()
                for indicator in pattern['indicators']:
                    if indicator in keywords_str:
                        matches.append(f"Keyword '{indicator}' in {func['name']}")
                        confidence_score += 1
            
            # Check actual code
            for stream_name, code in code_samples.items():
                code_lower = code.lower()
                for indicator in pattern['indicators']:
                    if indicator in code_lower:
                        matches.append(f"Pattern '{indicator}' in {stream_name}")
                        confidence_score += 1
            
            if matches:
                # Remove duplicates
                matches = list(set(matches))[:5]
                
                # Determine confidence
                if confidence_score >= 5:
                    confidence = 'high'
                elif confidence_score >= 3:
                    confidence = 'medium'
                else:
                    confidence = 'low'
                
                techniques.append({
                    'technique_id': technique_id,
                    'name': pattern['name'],
                    'severity': pattern['severity'],
                    'confidence': confidence,
                    'evidence_count': len(matches),
                    'evidence': matches
                })
        
        return techniques

    def calculate_complexity(self, func: Dict) -> Dict[str, Any]:
        """Calculate code complexity metrics"""
        
        # Cyclomatic complexity (approximation based on control flow keywords)
        control_keywords = ['if', 'elseif', 'for', 'while', 'do', 'case', 'and', 'or']
        cyclomatic = 1  # Base complexity
        
        for keyword in func.get('keywords', []):
            if keyword in control_keywords:
                cyclomatic += 1
        
        # Cognitive complexity (nesting + conditions)
        code_lines = func.get('raw_code', '').lower().split('\n') if 'raw_code' in func else []
        nesting_depth = 0
        max_nesting = 0
        
        for line in code_lines:
            line = line.strip()
            if any(kw in line for kw in ['if ', 'for ', 'while ', 'do ', 'select ']):
                nesting_depth += 1
                max_nesting = max(max_nesting, nesting_depth)
            elif any(kw in line for kw in ['end if', 'next', 'wend', 'loop', 'end select']):
                nesting_depth = max(0, nesting_depth - 1)
        
        # Sophistication categorization
        obfuscation_keywords = ['chr', 'strreverse', 'replace', 'xor']
        has_obfuscation = any(kw in func.get('keywords', []) for kw in obfuscation_keywords)
        
        if cyclomatic > 15 and has_obfuscation:
            sophistication = 'ADVANCED'
        elif cyclomatic > 10 or has_obfuscation:
            sophistication = 'INTERMEDIATE'
        else:
            sophistication = 'BASIC'
        
        return {
            'cyclomatic_complexity': cyclomatic,
            'max_nesting_depth': max_nesting,
            'loc': func.get('size', 0),
            'unique_keywords': len(set(func.get('keywords', []))),
            'has_obfuscation': has_obfuscation,
            'sophistication': sophistication
        }

    def run_oledump(self) -> Dict[str, Any]:
        """Run oledump.py for stream analysis"""
        try:
            if not os.path.exists(self.oledump_path):
                return {
                    'error': 'oledump.py not found',
                    'path_checked': self.oledump_path,
                    'streams': [],
                    'macro_streams': [],
                    'macro_code': {},
                    'functions': [],
                    'warnings': ['oledump.py not available']
                }

            results = {
                'streams': [],
                'macro_streams': [],
                'macro_code': {},
                'functions': [],
                'deobfuscation': {},
                'auto_exec_analysis': [],
                'complexity_analysis': {},
                'warnings': []
            }

            print(f"  > Using oledump at: {self.oledump_path}")

            # Use system Python if in venv (to avoid yara-python issues)
            python_exe = get_system_python_executable()
            
            # List streams
            cmd = [python_exe, self.oledump_path, self.file_path]
            print(f"  > Running: {' '.join(cmd)}")
            
            process = subprocess.run(cmd, capture_output=True, timeout=30)

            if process.returncode != 0:
                results['warnings'].append(f"oledump returned non-zero: {process.returncode}")
            
            # Decode with error handling
            try:
                stdout = process.stdout.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    stdout = process.stdout.decode('latin-1')
                except:
                    stdout = process.stdout.decode('utf-8', errors='ignore')
            
            # Debug output
            if stdout:
                print(f"  > oledump output: {len(stdout)} bytes, {len(stdout.splitlines())} lines")
            else:
                print(f"  > oledump output: EMPTY")
                results['warnings'].append("oledump produced no output")

            # Parse streams
            macro_stream_indices = []
            parse_failures = 0
            for line in stdout.splitlines():
                if line.strip():
                    stream_info = self._parse_oledump_line(line)
                    if stream_info:
                        results['streams'].append(stream_info)
                        if stream_info.get('has_macro'):
                            results['macro_streams'].append(stream_info)
                            macro_stream_indices.append(stream_info['index'])
                    else:
                        parse_failures += 1

            print(f"  > Found {len(results['streams'])} streams, {len(macro_stream_indices)} with macros")
            if parse_failures > 0:
                print(f"  > Warning: Failed to parse {parse_failures} lines from oledump output")

            # Extract and process each macro stream
            all_functions = []
            code_samples = {}
            
            for stream_idx in macro_stream_indices:
                try:
                    print(f"  > Extracting stream {stream_idx}...")
                    
                    cmd = [python_exe, self.oledump_path, '-s', str(stream_idx), '-v', self.file_path]
                    process = subprocess.run(cmd, capture_output=True, timeout=30)

                    if process.returncode != 0:
                        results['warnings'].append(f"Stream {stream_idx} returned code {process.returncode}")
                    
                    if not process.stdout or len(process.stdout) == 0:
                        print(f"    ✗ Stream {stream_idx} produced no output")
                        continue

                    # Decode
                    vba_code = None
                    encoding_used = None
                    
                    try:
                        vba_code = process.stdout.decode('utf-8')
                        encoding_used = 'utf-8'
                    except UnicodeDecodeError:
                        try:
                            vba_code = process.stdout.decode('latin-1')
                            encoding_used = 'latin-1'
                        except Exception:
                            vba_code = process.stdout.decode('utf-8', errors='ignore')
                            encoding_used = 'utf-8-ignore'
                    
                    if not vba_code or len(vba_code.strip()) == 0:
                        print(f"    ✗ Stream {stream_idx} is empty after decoding")
                        continue

                    stream_key = f"stream_{stream_idx}"
                    code_hash = hashlib.sha256(vba_code.encode('utf-8', errors='ignore')).hexdigest()
                    
                    # Deobfuscate
                    try:
                        deobfuscated_code, techniques = self.deobfuscate_vba(vba_code)
                    except Exception as deobfusc_err:
                        # If deobfuscation fails, just use original code
                        deobfuscated_code = vba_code
                        techniques = []
                        results['warnings'].append(f"Stream {stream_idx} deobfuscation error: {str(deobfusc_err)}")
                    
                    results['macro_code'][stream_key] = {
                        'stream_index': stream_idx,
                        'code': vba_code,
                        'code_length': len(vba_code),
                        'code_hash': code_hash,
                        'lines': len(vba_code.splitlines())
                    }
                    
                    if techniques:
                        results['deobfuscation'][stream_key] = {
                            'techniques_applied': techniques,
                            'deobfuscated_code': deobfuscated_code,
                            'deobfuscation_successful': len(deobfuscated_code) != len(vba_code)
                        }
                    
                    code_samples[stream_key] = vba_code
                    
                    print(f"    [OK] Extracted {len(vba_code.splitlines())} lines ({len(vba_code)} bytes) using {encoding_used}")
                    if techniques:
                        print(f"    [OK] Deobfuscated using: {', '.join(techniques)}")
                    
                    # Parse functions
                    try:
                        functions = self._extract_functions_from_vba(vba_code, stream_key)
                        all_functions.extend(functions)
                        if functions:
                            print(f"    [OK] Found {len(functions)} functions")
                    except Exception as func_err:
                        functions = []
                        results['warnings'].append(f"Stream {stream_idx} function extraction error: {str(func_err)}")

                except subprocess.TimeoutExpired:
                    results['warnings'].append(f"Timeout extracting stream {stream_idx}")
                except Exception as e:
                    results['warnings'].append(f"Error extracting stream {stream_idx}: {str(e)}")

            # Calculate complexity for all functions
            for func in all_functions:
                complexity = self.calculate_complexity(func)
                func['complexity'] = complexity
                results['complexity_analysis'][func['name']] = complexity

            # Detect auto-exec methods
            results['auto_exec_analysis'] = self.detect_auto_exec_comprehensive(all_functions)
            
            results['functions'] = all_functions

            # Summary
            results['summary'] = {
                'total_streams': len(results['streams']),
                'macro_streams': len(results['macro_streams']),
                'extracted_streams': len(results['macro_code']),
                'total_functions': len(all_functions),
                'unique_function_hashes': len(set(f['func_hash'] for f in all_functions)) if all_functions else 0,
                'auto_exec_count': len(results['auto_exec_analysis']),
                'deobfuscation_applied': len(results['deobfuscation']),
                'avg_complexity': sum(f['complexity']['cyclomatic_complexity'] for f in all_functions) / len(all_functions) if all_functions else 0
            }

            print(f"  > Summary: {results['summary']['total_functions']} functions, {results['summary']['unique_function_hashes']} unique hashes")

            # YARA
            if self.yara_rules_path and os.path.exists(self.yara_rules_path):
                yara_results = self._run_oledump_yara()
                results['yara_matches'] = yara_results

            return results

        except subprocess.TimeoutExpired:
            return {
                'error': 'oledump timed out',
                'streams': [],
                'functions': [],
                'warnings': ['Timeout during oledump execution']
            }
        except Exception as e:
            return {
                'error': str(e),
                'streams': [],
                'functions': [],
                'warnings': [f'Exception during oledump: {str(e)}']
            }

    def _parse_oledump_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single line from oledump output
        
        Expected format (with leading spaces):
          1:       114 'stream_name'          (no macro)
         12: M    6655 'Macros/VBA/Form'     (with macro indicator 'M')
        """
        try:
            line = line.strip()
            if not line:
                return None
            
            # Use regex to parse the line robustly
            # Format: INDEX [MACRO_INDICATOR] SIZE 'NAME'
            import re
            
            # Match: optional spaces, index+colon, optional macro indicator, size, quoted name
            match = re.match(
                r'^(\d+):\s*([MmEe])?\s+(\d+)\s+(.+)$',
                line
            )
            
            if not match:
                return None
            
            index_str, macro_indicator, size_str, name_with_quotes = match.groups()
            
            stream_info = {
                'index': int(index_str),
                'size': int(size_str),
                'name': name_with_quotes.strip("'\""),  # Remove quotes
                'has_macro': macro_indicator is not None,
                'macro_indicator': macro_indicator.upper() if macro_indicator else None
            }
            
            return stream_info

        except Exception as e:
            return None

    def _extract_functions_from_vba(self, vba_code: str, stream_name: str) -> List[Dict[str, Any]]:
        """Extract functions from VBA code"""
        functions = []
        
        if not vba_code or not vba_code.strip():
            return functions

        lines = vba_code.splitlines()
        
        normalized_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.lower().startswith('attribute vb_'):
                continue
            normalized_lines.append(line)

        current_function = None
        current_lines = []
        
        func_pattern = re.compile(
            r'^\s*(public|private|friend|static)?\s*(sub|function)\s+(\w+)',
            re.IGNORECASE
        )
        
        end_pattern = re.compile(
            r'^\s*end\s+(sub|function)',
            re.IGNORECASE
        )

        for line_num, line in enumerate(normalized_lines, 1):
            stripped_line = line.strip()
            
            if not stripped_line:
                if current_function is not None:
                    current_lines.append(line)
                continue
            
            match = func_pattern.match(stripped_line)
            if match:
                if current_function is not None:
                    self._save_vba_function(
                        functions,
                        current_function,
                        current_lines,
                        stream_name
                    )
                
                visibility = match.group(1) or 'public'
                func_type = match.group(2).lower()
                func_name = match.group(3)
                
                params = '()'
                if '(' in stripped_line:
                    paren_start = stripped_line.find('(')
                    paren_end = stripped_line.find(')')
                    if paren_end > paren_start:
                        params = stripped_line[paren_start:paren_end+1]
                
                current_function = {
                    'name': func_name,
                    'type': func_type,
                    'visibility': visibility.lower(),
                    'params': params,
                    'start_line': line_num
                }
                current_lines = [line]
                continue
            
            if current_function is not None and end_pattern.match(stripped_line):
                current_lines.append(line)
                current_function['end_line'] = line_num
                
                self._save_vba_function(
                    functions,
                    current_function,
                    current_lines,
                    stream_name
                )
                
                current_function = None
                current_lines = []
                continue
            
            if current_function is not None:
                current_lines.append(line)
        
        if current_function is not None:
            current_function['end_line'] = len(normalized_lines)
            self._save_vba_function(
                functions,
                current_function,
                current_lines,
                stream_name
            )

        return functions

    def _save_vba_function(self, functions: List, func_meta: Dict, func_lines: List[str], stream_name: str):
        """Save a VBA function with hash and metadata"""
        if not func_lines:
            return

        keywords = self._extract_keywords(func_lines)
        
        keyword_string = '|'.join(sorted(keywords))
        func_hash = hashlib.sha256(keyword_string.encode()).hexdigest()
        
        fuzzy_keywords = [k for k in keywords if k in self.VBA_KEYWORDS]
        fuzzy_string = '|'.join(sorted(fuzzy_keywords))
        fuzzy_hash = hashlib.sha256(fuzzy_string.encode()).hexdigest()
        
        signature = f"{func_meta.get('visibility', 'public')} {func_meta['type']} {func_meta['name']}{func_meta.get('params', '()')}"
        
        full_code = '\n'.join(func_lines)
        
        function_data = {
            'name': func_meta['name'],
            'type': func_meta['type'],
            'visibility': func_meta.get('visibility', 'public'),
            'signature': signature,
            'offset': f"{stream_name}:line_{func_meta['start_line']}",
            'start_line': func_meta['start_line'],
            'end_line': func_meta['end_line'],
            'size': func_meta['end_line'] - func_meta['start_line'] + 1,
            'func_hash': func_hash,
            'fuzzy_hash': fuzzy_hash,
            'keywords': sorted(list(keywords)),
            'keyword_count': len(keywords),
            'stream': stream_name,
            'code_length': len(full_code),
            'raw_code': full_code  # Store for complexity analysis
        }
        
        functions.append(function_data)

    def _extract_keywords(self, lines: List[str]) -> set:
        """Extract non-obfuscatable VBA keywords from code"""
        keywords = set()
        
        for line in lines:
            comment_pos = line.find("'")
            if comment_pos >= 0:
                line = line[:comment_pos]
            
            line_lower = line.lower().strip()
            
            if not line_lower:
                continue
            
            words = re.findall(r'\b\w+\b', line_lower)
            
            for word in words:
                if word in self.VBA_KEYWORDS:
                    keywords.add(word)
        
        return keywords

    def _run_oledump_yara(self) -> List[Dict[str, Any]]:
        """Run oledump with YARA rules"""
        try:
            yara_path = self.yara_rules_path
            if os.path.isdir(yara_path):
                yar_files = list(Path(yara_path).glob('*.yar'))
                if yar_files:
                    yara_path = str(yar_files[0])
                else:
                    return []

            cmd = [sys.executable, self.oledump_path, '-y', yara_path, self.file_path]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            matches = []
            for line in process.stdout.splitlines():
                if 'YARA rule' in line or line.strip().startswith('Rule:'):
                    matches.append({'match': line.strip()})

            return matches

        except Exception as e:
            return [{'error': str(e)}]

    def run_yara_scan(self) -> Dict[str, Any]:
        """Run YARA scan on the file"""
        if self.yara_scanner:
            try:
                matches = self.yara_scanner.scan(self.file_path, verbose=False)
                results = {
                    'total_matches': len(matches),
                    'matches': []
                }

                for match in matches:
                    match_info = {
                        'rule': match.get('rule_name'),
                        'namespace': None,
                        'tags': match.get('tags', []),
                        'meta': match.get('meta', {}),
                        'strings': []
                    }

                    for name, offset, data in match.get('strings', []):
                        if isinstance(data, (bytes, bytearray)):
                            data_value = data[:100].hex()
                        else:
                            data_value = str(data)

                        match_info['strings'].append({
                            'offset': offset,
                            'identifier': name,
                            'data': data_value
                        })

                    results['matches'].append(match_info)

                return results
            except Exception as e:
                return {'error': str(e)}

        if not self.yara_rules:
            return {'error': 'No YARA rules loaded'}

        try:
            matches = self.yara_rules.match(self.file_path)

            results = {
                'total_matches': len(matches),
                'matches': []
            }

            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags),
                    'meta': dict(match.meta),
                    'strings': []
                }

                for string_match in match.strings:
                    match_info['strings'].append({
                        'offset': string_match[0],
                        'identifier': string_match[1],
                        'data': string_match[2][:100].hex()
                    })

                results['matches'].append(match_info)

            return results

        except Exception as e:
            return {'error': str(e)}

    def analyze_vba_project_windows(self) -> Dict[str, Any]:
        """
        Windows-only: Deep VBA project analysis using COM
        Requires: pywin32 (pip install pywin32)
        """
        if not self.is_windows or not PYWIN32_AVAILABLE:
            return {
                'available': False,
                'reason': 'Windows with pywin32 required',
                'platform': self.platform
            }
        
        try:
            results = {
                'available': True,
                'vba_project': {
                    'is_locked': False,
                    'has_password': False,
                    'modules': [],
                    'references': [],
                    'code_modules': []
                }
            }
            
            # Determine file type
            file_ext = os.path.splitext(self.file_path)[1].lower()
            
            # Create appropriate COM object
            if file_ext in ['.doc', '.docm', '.docx']:
                app_name = 'Word.Application'
                doc_method = 'Documents'
            elif file_ext in ['.xls', '.xlsm', '.xlsx']:
                app_name = 'Excel.Application'
                doc_method = 'Workbooks'
            elif file_ext in ['.ppt', '.pptm', '.pptx']:
                app_name = 'PowerPoint.Application'
                doc_method = 'Presentations'
            else:
                return {
                    'available': False,
                    'reason': f'Unsupported file type: {file_ext}'
                }
            
            # Initialize COM
            pythoncom.CoInitialize()
            
            try:
                app = win32com.client.Dispatch(app_name)
                app.Visible = False
                app.DisplayAlerts = False
                
                # Open document
                if app_name == 'Word.Application':
                    doc = app.Documents.Open(os.path.abspath(self.file_path), ReadOnly=True)
                elif app_name == 'Excel.Application':
                    doc = app.Workbooks.Open(os.path.abspath(self.file_path), ReadOnly=True)
                else:
                    doc = app.Presentations.Open(os.path.abspath(self.file_path), ReadOnly=True)
                
                # Check if VBA project exists
                try:
                    vba_project = doc.VBProject
                    
                    # Check if locked
                    try:
                        vba_project.VBComponents.Count
                    except:
                        results['vba_project']['is_locked'] = True
                    
                    # Get modules
                    if not results['vba_project']['is_locked']:
                        for component in vba_project.VBComponents:
                            module_info = {
                                'name': component.Name,
                                'type': component.Type,
                                'code_lines': 0
                            }
                            
                            try:
                                code_module = component.CodeModule
                                module_info['code_lines'] = code_module.CountOfLines
                            except:
                                pass
                            
                            results['vba_project']['modules'].append(module_info)
                        
                        # Get references
                        try:
                            for ref in vba_project.References:
                                ref_info = {
                                    'name': ref.Name,
                                    'description': ref.Description,
                                    'guid': ref.Guid if hasattr(ref, 'Guid') else None
                                }
                                results['vba_project']['references'].append(ref_info)
                        except:
                            pass
                
                except Exception as e:
                    results['vba_project']['error'] = str(e)
                
                # Close document
                doc.Close(False)
                app.Quit()
                
            finally:
                pythoncom.CoUninitialize()
            
            return results
            
        except Exception as e:
            return {
                'available': True,
                'error': str(e)
            }

    def extract_activeX_controls_windows(self) -> Dict[str, Any]:
        """
        Windows-only: Extract ActiveX controls and forms
        Requires: pywin32
        """
        if not self.is_windows or not PYWIN32_AVAILABLE:
            return {
                'available': False,
                'reason': 'Windows with pywin32 required',
                'platform': self.platform
            }
        
        try:
            results = {
                'available': True,
                'controls': [],
                'forms': []
            }
            
            # This would require more complex COM interaction
            # Placeholder for now
            results['note'] = 'ActiveX extraction requires additional implementation'
            
            return results
            
        except Exception as e:
            return {
                'available': True,
                'error': str(e)
            }

    def _extract_ole_strings(self, vba_analysis: Dict[str, Any], oledump_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and categorize strings from VBA code and OLE streams,
        mirroring the PE static_analysis.strings schema:
          { ascii, unicode, interesting: { urls, ips, emails, registry_keys,
                                           file_paths, crypto_indicators,
                                           versions } }
        """
        ascii_strings: List[str] = []
        unicode_strings: List[str] = []
        urls: List[str] = []
        ips: List[str] = []
        emails: List[str] = []
        registry_keys: List[str] = []
        file_paths: List[str] = []
        crypto_indicators: List[str] = []
        versions: List[str] = []

        # --- collect raw strings from every macro stream ----------------------
        for stream_info in oledump_results.get('macro_code', {}).values():
            code = stream_info.get('code', '')
            for line in code.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    stripped.encode('ascii')
                    if len(stripped) >= 4:
                        ascii_strings.append(stripped[:512])
                except UnicodeEncodeError:
                    if len(stripped) >= 4:
                        unicode_strings.append(stripped[:512])

        # --- pull IOCs already extracted by olevba ----------------------------
        iocs = vba_analysis.get('iocs', {})
        urls        = list(set(iocs.get('urls', [])))
        ips         = list(set(iocs.get('ips', [])))
        emails      = list(set(iocs.get('emails', [])))
        executables = list(set(iocs.get('executables', [])))
        susp_strs   = list(set(iocs.get('suspicious_strings', [])))

        # --- classify suspicious strings further ------------------------------
        reg_pattern  = re.compile(r'HKEY_[A-Z_]+[\\/][^\s"\']+', re.IGNORECASE)
        path_pattern = re.compile(r'(?:[A-Z]:\\|/tmp/|/var/|/etc/)[\w\\/\-\.]+', re.IGNORECASE)
        ver_pattern  = re.compile(r'\bv?\d+\.\d+(\.\d+)?(\.\d+)?\b')
        crypto_kws   = {'base64', 'xor', 'aes', 'rc4', 'md5', 'sha', 'encrypt',
                        'decrypt', 'cipher', 'chr(', 'strreverse'}

        for s in susp_strs + ascii_strings:
            sl = s.lower()
            if reg_pattern.search(s):
                registry_keys.append(s[:256])
            if path_pattern.search(s):
                file_paths.append(s[:256])
            if ver_pattern.search(s):
                versions.append(s[:64])
            if any(kw in sl for kw in crypto_kws):
                crypto_indicators.append(s[:128])

        # --- merge executables into file_paths (same slot in PE schema) -------
        file_paths = list(set(file_paths + executables))

        # cap list sizes to match PE output conventions
        ascii_strings   = ascii_strings[:5000]
        unicode_strings = unicode_strings[:1000]

        return {
            'ascii':   ascii_strings,
            'unicode': unicode_strings,
            'interesting': {
                'urls':              urls,
                'ips':               ips,
                'emails':            emails,
                'registry_keys':     list(set(registry_keys))[:100],
                'file_paths':        list(set(file_paths))[:100],
                'crypto_indicators': list(set(crypto_indicators))[:50],
                'versions':          list(set(versions))[:20],
            }
        }

    def _build_sections_from_streams(self, oledump_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Map OLE streams to the PE sections[] schema so downstream consumers
        get a consistent list of:
          { name, virtual_address, virtual_size, raw_size, raw_offset,
            entropy, permissions, hashes }
        """
        sections = []
        for stream in oledump_results.get('streams', []):
            name = stream.get('name') or f"stream_{stream.get('index', '?')}"
            raw_size = stream.get('size') or 0

            # Calculate entropy from macro code if available
            entropy = 0.0
            stream_key = f"stream_{stream.get('index', '')}"
            code_info = oledump_results.get('macro_code', {}).get(stream_key, {})
            code_bytes = code_info.get('code', '').encode('utf-8', errors='ignore')
            if code_bytes:
                import math
                freq = {}
                for b in code_bytes:
                    freq[b] = freq.get(b, 0) + 1
                n = len(code_bytes)
                entropy = -sum((c / n) * math.log2(c / n) for c in freq.values() if c)

            # permissions derived from macro indicator
            perms = []
            if stream.get('has_macro'):
                perms.append('EXECUTABLE')
            perms.append('READABLE')

            # hashes of code content
            code_hash_val = code_info.get('code_hash', '')
            stream_hashes = {
                'md5':    hashlib.md5(code_bytes).hexdigest() if code_bytes else '',
                'sha1':   hashlib.sha1(code_bytes).hexdigest() if code_bytes else '',
                'sha256': code_hash_val or (hashlib.sha256(code_bytes).hexdigest() if code_bytes else ''),
            }

            sections.append({
                'name':            name,
                'virtual_address': '0x0',            # not applicable for OLE
                'virtual_size':    hex(raw_size),
                'raw_size':        raw_size,
                'raw_offset':      hex(stream.get('index', 0)),
                'entropy':         round(entropy, 4),
                'permissions':     perms,
                'hashes':          stream_hashes,
                # OLE-specific extras kept under a sub-key so PE consumers ignore them
                'ole_stream': {
                    'index':          stream.get('index'),
                    'has_macro':      stream.get('has_macro', False),
                    'macro_indicator': stream.get('macro_indicator'),
                    'lines':          code_info.get('lines', 0),
                },
            })
        return sections

    def analyze(self) -> Dict[str, Any]:
        """
        Run complete static analysis and return a report whose schema mirrors
        the PE normalized report:

          format_type          str
          ingest_analysis      dict   (basic file identity fields)
          static_analysis      dict   (hashes, basic_info, sections, imports,
                                       security_features, strings, yara_matches,
                                       mitre_mapping, packing, format_specific)
          disassembly          dict   (functions, function_count, …)
          behavioral_analysis  dict   (mitre_techniques, sophistication, …)
        """
        print(f"[*] Starting ENHANCED static analysis of {self.file_path}")
        print(f"[*] Platform: {self.platform} ({'Windows-specific features available' if self.is_windows and PYWIN32_AVAILABLE else 'Linux mode - some features disabled'})")

        #  Phase 1: collect raw data from all sub-analysers 
        print("[*] Running oleid...")
        oleid_results = self.run_oleid()

        print("[*] Extracting OLE metadata...")
        ole_meta = self.run_olemeta()

        print("[*] Analyzing embedded objects...")
        embedded_objs = self.run_oleobj()

        print("[*] Extracting and analyzing VBA macros...")
        vba_results = self.run_olevba()

        print("[*] Checking for RTF objects...")
        rtf_results = self.run_rtfobj()

        print("[*] Running oledump...")
        oledump_results = self.run_oledump()

        yara_results = {}
        if self.yara_scanner or self.yara_rules:
            print("[*] Running YARA scan...")
            yara_results = self.run_yara_scan()

        windows_analysis: Dict[str, Any] = {}
        if self.is_windows and PYWIN32_AVAILABLE:
            print("[*] Running Windows-specific analysis...")
            windows_analysis = {
                'vba_project_com': self.analyze_vba_project_windows(),
                'activex_controls': self.extract_activeX_controls_windows(),
            }
        else:
            windows_analysis = {
                'available': False,
                'reason': 'Not on Windows or pywin32 not available',
                'note': 'Run on Windows with pywin32 for additional features',
            }

        #  Phase 2: build disassembly (VBA functions -> PE functions schema) 
        functions = oledump_results.get('functions', [])

        disassembly: Dict[str, Any] = {}
        if functions:
            # Normalize each function to match PE disassembly.functions[] schema:
            #   { name, offset, size, func_hash, fuzzy_hash, mnemonics,
            #     strings_referenced, similar_occurrences, … }
            normalized_funcs = []
            for fn in functions:
                normalized_funcs.append({
                    'name':                fn.get('name'),
                    'offset':              fn.get('offset'),
                    'size':                fn.get('size', 0),
                    'func_hash':           fn.get('func_hash'),
                    'fuzzy_hash':          fn.get('fuzzy_hash'),
                    # 'mnemonics' in PE = instruction list; here = VBA keyword list
                    'mnemonics':           fn.get('keywords', []),
                    'strings_referenced':  [],        # populated if deobfuscation ran
                    'similar_occurrences': [],
                    # OLE-specific extras
                    'vba': {
                        'type':         fn.get('type'),
                        'visibility':   fn.get('visibility'),
                        'signature':    fn.get('signature'),
                        'stream':       fn.get('stream'),
                        'start_line':   fn.get('start_line'),
                        'end_line':     fn.get('end_line'),
                        'code_length':  fn.get('code_length', 0),
                        'keyword_count': fn.get('keyword_count', 0),
                        'complexity':   fn.get('complexity', {}),
                    },
                })

            disassembly = {
                'functions':             normalized_funcs,
                'function_count':        len(normalized_funcs),
                'unique_function_hashes': oledump_results.get('summary', {}).get('unique_function_hashes', 0),
                'binary_format':         'OLE/VBA',
                'similar_binaries':      [],  # filled by pipeline similarity pass
                'strings_with_va':       [],
                # OLE-specific stream metadata kept under its own key
                'stream_analysis': {
                    'total_streams':    oledump_results.get('summary', {}).get('total_streams', 0),
                    'macro_streams':    oledump_results.get('summary', {}).get('macro_streams', 0),
                    'total_code_bytes': sum(
                        mc.get('code_length', 0)
                        for mc in oledump_results.get('macro_code', {}).values()
                    ),
                    'avg_function_size': int(oledump_results.get('summary', {}).get('avg_complexity', 0)),
                    'deobfuscation':    oledump_results.get('deobfuscation', {}),
                },
                'auto_exec_methods': oledump_results.get('auto_exec_analysis', []),
                'complexity_analysis': oledump_results.get('complexity_analysis', {}),
                # Raw oledump macro code kept for downstream consumers
                'macro_code': oledump_results.get('macro_code', {}),
            }

        #  Phase 3: MITRE mapping -> behavioral_analysis 
        behavioral_analysis: Dict[str, Any] = {}
        if functions:
            print("[*] Mapping to MITRE ATT&CK...")
            code_samples = {
                k: v.get('code', '')
                for k, v in oledump_results.get('macro_code', {}).items()
            }
            mitre_techniques = self.map_to_mitre(functions, code_samples)

            sophistication_levels = [
                f.get('complexity', {}).get('sophistication', 'BASIC')
                for f in functions
            ]
            overall_sophistication = (
                'ADVANCED'     if 'ADVANCED'     in sophistication_levels else
                'INTERMEDIATE' if 'INTERMEDIATE' in sophistication_levels else
                'BASIC'
            )

            # Build mitre_mapping list in the same shape as PE static_analysis.mitre_mapping
            mitre_mapping = [
                {
                    'technique_id':  t.get('technique_id'),
                    'name':          t.get('name'),
                    'severity':      t.get('severity'),
                    'confidence':    t.get('confidence'),
                    'evidence_count': t.get('evidence_count', 0),
                    'evidence':      t.get('evidence', []),
                }
                for t in mitre_techniques
            ]

            behavioral_analysis = {
                'mitre_techniques':   mitre_techniques,   # full objects with evidence
                'mitre_mapping':      mitre_mapping,       # slim list (mirrors PE field name)
                'technique_count':    len(mitre_techniques),
                'sophistication':     overall_sophistication,
                'obfuscation_detected': any(
                    f.get('complexity', {}).get('has_obfuscation', False)
                    for f in functions
                ),
                'auto_exec_detected': len(oledump_results.get('auto_exec_analysis', [])) > 0,
            }

        #  Phase 4: assemble final report matching PE schema 
        file_info   = self.get_file_info()
        hashes      = self.calculate_hashes()
        strings_obj = self._extract_ole_strings(vba_results, oledump_results)
        sections    = self._build_sections_from_streams(oledump_results)

        # --- ingest_analysis mirrors ingest.py metadata block ----------------
        ingest_analysis = {
            'original_path':    file_info.get('file_path', self.file_path),
            'ingested_path':    file_info.get('file_path', self.file_path),
            'filename':         file_info.get('filename'),
            'size_bytes':       file_info.get('file_size'),
            'original_mtime':   file_info.get('modification_time'),
            'ingest_timestamp': datetime.now(timezone.utc).isoformat(),
            'extension':        os.path.splitext(file_info.get('filename', ''))[1].lstrip('.'),
            'claimed_type':     oleid_results.get('file_type') or 'OLE Compound Document',
            'detected_type':    oleid_results.get('file_type') or 'OLE Compound Document',
            'matched_signature_hex': 'D0CF11E0A1B11AE1',
            'magic_header_hex': '',
            'sha256':           hashes.get('sha256', ''),
            'mime_type_guess':  'application/msword',
            'types_match':      True,
            'can_contain_vba_macros': vba_results.get('has_macros', False),
            'extracted_resources_path': '',
        }

        # --- security_features: OLE equivalents of PE mitigations -----------
        security_features = {
            'ASLR':           False,   # N/A for OLE documents
            'DEP':            False,
            'SEH':            False,
            'CFG':            False,
            'SafeSEH':        False,
            'HighEntropyVA':  False,
            'ForceIntegrity': False,
            'Signed':         False,
            # OLE-specific features
            'HasMacros':        vba_results.get('has_macros', False),
            'HasAutoExec':      bool(vba_results.get('auto_exec')),
            'HasEmbeddedObjs':  embedded_objs.get('total_objects', 0) > 0,
            'IsRTF':            rtf_results.get('is_rtf', False),
            'OleidRiskScore':   oleid_results.get('risk_score', 0),
        }

        # --- packing: map oleid risk + obfuscation to PE packing schema ------
        has_obfuscation = behavioral_analysis.get('obfuscation_detected', False)
        packing = {
            'verdict':      'obfuscated' if has_obfuscation else 'clean',
            'confidence':   0.8 if has_obfuscation else 0.5,
            'packer_names': [],
            'signals': {
                'obfuscation':      {'detected': has_obfuscation},
                'chr_encoding':     {'detected': any(
                    'chr_decoding' in d.get('techniques_applied', [])
                    for d in oledump_results.get('deobfuscation', {}).values()
                )},
                'base64_encoding':  {'detected': any(
                    'base64_decoding' in d.get('techniques_applied', [])
                    for d in oledump_results.get('deobfuscation', {}).values()
                )},
                'string_reverse':   {'detected': any(
                    'string_reverse' in d.get('techniques_applied', [])
                    for d in oledump_results.get('deobfuscation', {}).values()
                )},
            },
            'summary': [
                t
                for d in oledump_results.get('deobfuscation', {}).values()
                for t in d.get('techniques_applied', [])
            ],
        }

        # --- format_specific: OLE equivalent of PE pe_header -----------------
        format_specific = {
            'file_format':      'OLE Compound Document',
            'ole_version':      oleid_results.get('file_type'),
            'ole_metadata': {
                'author':       ole_meta.get('author'),
                'title':        ole_meta.get('title'),
                'subject':      ole_meta.get('subject'),
                'create_time':  ole_meta.get('create_time'),
                'modify_time':  ole_meta.get('modify_time'),
            },
            'oleid_indicators': oleid_results.get('indicators', []),
            'embedded_objects': {
                'total':   embedded_objs.get('total_objects', 0),
                'objects': embedded_objs.get('objects', []),
            },
            'rtf': rtf_results,
            'vba_project': {
                'has_macros':          vba_results.get('has_macros', False),
                'macros':              vba_results.get('macros', []),
                'auto_exec':           vba_results.get('auto_exec', []),
                'suspicious_keywords': vba_results.get('suspicious_keywords', []),
                'analysis_summary':    vba_results.get('analysis_summary', {}),
            },
            'windows_analysis': windows_analysis,
            # raw oledump stream list for forensic completeness
            'streams':         oledump_results.get('streams', []),
        }

        # --- static_analysis block (mirrors PE schema exactly) ---------------
        static_analysis = {
            'metadata': {
                'timestamp':         datetime.now(timezone.utc).isoformat(),
                'analyzer_version':  '2.0-enhanced-crossplatform',
                'file_path':         self.file_path,
                'platform':          self.platform,
                'platform_capabilities': {
                    'is_windows':        self.is_windows,
                    'is_linux':          self.is_linux,
                    'pywin32_available': PYWIN32_AVAILABLE,
                },
            },
            'hashes':            hashes,
            'basic_info': {
                'filename':  file_info.get('filename'),
                'file_size': file_info.get('file_size'),
                'file_type': oleid_results.get('file_type') or 'OLE Compound Document',
            },
            # sections[] mirrors PE sections[] — one entry per OLE stream
            'sections':          sections,
            # imports[] mirrors PE imports[] — VBA external references as "imports"
            'imports':           self._build_imports_from_vba(vba_results),
            'symbols':           [],
            'security_features': security_features,
            'strings':           strings_obj,
            'yara_matches':      yara_results if yara_results else None,
            'mitre_mapping':     behavioral_analysis.get('mitre_mapping'),
            'virustotal':        None,   # filled by threat_intel pipeline
            'packing':           packing,
            'format_specific':   format_specific,
        }

        analysis = {
            'format_type':       'OLE',
            'ingest_analysis':   ingest_analysis,
            'static_analysis':   static_analysis,
            'disassembly':       disassembly,
            'behavioral_analysis': behavioral_analysis,
        }

        print("[*] Enhanced static analysis complete")
        return _sanitize(analysis)

    def _build_imports_from_vba(self, vba_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Translate VBA external calls / suspicious keywords into an imports[]
        list that mirrors the PE imports[] schema:
          [ { library, functions: [ str, … ] } ]
        """
        lib_map: Dict[str, List[str]] = defaultdict(list)

        # Group suspicious keywords by category -> synthetic "library" name
        category_to_lib = {
            'AutoExec':  'VBA.AutoExec',
            'Suspicious': 'VBA.Suspicious',
            'IOC':        'VBA.IOC',
        }

        for kw_info in vba_results.get('suspicious_keywords', []):
            kw_type = kw_info.get('type', 'Suspicious')
            lib_name = category_to_lib.get(kw_type, f'VBA.{kw_type}')
            func_name = kw_info.get('keyword', '')
            if func_name and func_name not in lib_map[lib_name]:
                lib_map[lib_name].append(func_name)

        return [
            {'library': lib, 'functions': funcs}
            for lib, funcs in sorted(lib_map.items())
        ]


def main():
    """Main function for standalone execution"""
    if len(sys.argv) < 2:
        print("Usage: python OLE_parser_enhanced.py <ole_file> [oledump_path] [yara_rules_path]")
        sys.exit(1)

    file_path = sys.argv[1]
    oledump_path = sys.argv[2] if len(sys.argv) > 2 else None
    yara_rules_path = sys.argv[3] if len(sys.argv) > 3 else None

    analyzer = OLEStaticAnalyzer(file_path, oledump_path, yara_rules_path)
    results = analyzer.analyze()

    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
