# TODO: Also need to run the fix line endings script to ensure that it runs correctly

"""
OLE Analysis Pipeline Driver with Docker-based ViperMonkey
Orchestrates static analysis and emulation, produces comprehensive JSON output
Automatically downloads and configures required tools on first run
Uses Docker for ViperMonkey emulation
"""

import io
import os
import sys
import json
import argparse
import subprocess
import shutil
import urllib.request
import contextlib
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Union, List


class DependencyManager:
    """Manages automatic download and setup of required tools"""
    
    def __init__(self, tools_dir: str = None, verbose: bool = True):
        """
        Initialize dependency manager
        
        Args:
            tools_dir: Directory to store downloaded tools (default: ~/.ole_analysis_tools)
            verbose: Print status messages
        """
        if tools_dir:
            self.tools_dir = Path(tools_dir)
        else:
            self.tools_dir = Path.home() / '.ole_analysis_tools'
        
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        
        self.oledump_path = None
        self.yara_rules_path = None
        self.dockermonkey_path = None
    
    def _print(self, message: str):
        """Print message if verbose is enabled"""
        if not self.verbose:
            return

        try:
            print(message)
        except UnicodeEncodeError:
            enc = sys.stdout.encoding or 'utf-8'
            safe_message = message.encode(enc, errors='replace').decode(enc, errors='replace')
            print(safe_message)
    
    def check_python_dependencies(self) -> bool:
        """Check and install Python dependencies"""
        self._print("[*] Checking Python dependencies...")
        
        # Core required packages
        required_packages = {
            'oletools': 'oletools',
            'yara': 'yara-python'
        }
        
        missing = []
        
        # Check required packages
        for import_name, package_name in required_packages.items():
            if import_name == 'yara':
                result = subprocess.run(
                    [sys.executable, '-c', 'import yara'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self._print(f"  OK {package_name} installed")
                else:
                    stderr = result.stderr.strip() or result.stdout.strip()
                    if 'No module named yara' in stderr:
                        missing.append(package_name)
                        self._print(f"  ERROR {package_name} not found")
                    else:
                        error_line = stderr.splitlines()[-1] if stderr else 'native import failure'
                        self._print(f"  WARNING: {package_name} import failed: {error_line}")
                        self._print("    YARA scanning will be disabled for this run")
            else:
                try:
                    with contextlib.redirect_stderr(io.StringIO()):
                        __import__(import_name)
                    self._print(f"  OK {package_name} installed")
                except Exception:
                    missing.append(package_name)
                    self._print(f"  ERROR {package_name} not found")
        
        # Install missing required packages
        if missing:
            self._print(f"\n[*] Installing missing required packages: {', '.join(missing)}")
            try:
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', '--upgrade'
                ] + missing, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._print("   Required dependencies installed successfully")
            except subprocess.CalledProcessError as e:
                self._print(f"   Failed to install required dependencies: {e}")
                self._print(f"  ! Please run manually: pip install {' '.join(missing)}")
                return False
        
        return True
    
    def check_docker_available(self) -> bool:
        """Check if Docker is installed and running"""
        self._print("[*] Checking Docker availability...")
        
        try:
            result = subprocess.run(
                ['docker', 'info'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self._print("   Docker is installed and running")
                return True
            else:
                self._print("   Docker daemon is not running")
                self._print("    Please start Docker")
                return False
                
        except FileNotFoundError:
            self._print("   Docker is not installed")
            self._print("    Install Docker: https://docs.docker.com/get-docker/")
            return False
        except subprocess.TimeoutExpired:
            self._print("   Docker check timed out")
            return False
    
    def setup_dockermonkey(self) -> Optional[str]:
        """Clone ViperMonkey repository to get dockermonkey.sh"""
        self._print("[*] Setting up dockermonkey.sh...")
        
        vipermonkey_dir = self.tools_dir / 'ViperMonkey'
        dockermonkey_path = vipermonkey_dir / 'docker' / 'dockermonkey.sh'
        
        # Check if already exists
        if dockermonkey_path.exists():
            self._print(f"   dockermonkey.sh already exists at {dockermonkey_path}")
            os.chmod(dockermonkey_path, 0o755)
            self.dockermonkey_path = str(dockermonkey_path)
            return str(dockermonkey_path)
        
        self._print("  -> Cloning ViperMonkey repository...")
        
        try:
            # Check if git is available
            try:
                git_check = subprocess.run(['git', '--version'], capture_output=True, timeout=5)
                if git_check.returncode != 0:
                    self._print("   Git is not installed or not working properly.")
                    self._print("    Install git: https://git-scm.com/download/win")
                    return None
                else:
                    git_version = git_check.stdout.decode('utf-8', errors='ignore').strip()
                    self._print(f"    Git found: {git_version}")
            except FileNotFoundError:
                self._print("   Git is not installed.")
                self._print("    Install git: https://git-scm.com/download/win")
                self._print("    After installing git, restart your terminal/IDE")
                return None
            except subprocess.TimeoutExpired:
                self._print("   Git check timed out")
                return None
            
            # Remove old directory if exists
            if vipermonkey_dir.exists():
                self._print("  -> Removing old ViperMonkey directory...")
                shutil.rmtree(vipermonkey_dir)
            
            # Clone repository
            self._print("    Cloning from GitHub...")
            clone_result = subprocess.run(
                ['git', 'clone', 'https://github.com/decalage2/ViperMonkey.git', str(vipermonkey_dir)],
                capture_output=True,
                timeout=120  # 2 minute timeout for clone
            )
            
            if clone_result.returncode != 0:
                error_msg = clone_result.stderr.decode('utf-8', errors='ignore')
                self._print(f"   Git clone failed: {error_msg}")
                return None
            
            if dockermonkey_path.exists():
                os.chmod(dockermonkey_path, 0o755)
                self._print(f"   dockermonkey.sh installed at {dockermonkey_path}")
                self.dockermonkey_path = str(dockermonkey_path)
                return str(dockermonkey_path)
            else:
                self._print(f"   dockermonkey.sh not found after cloning")
                self._print(f"    Expected at: {dockermonkey_path}")
                return None
                
        except subprocess.TimeoutExpired:
            self._print(f"   Git clone timed out (network issue?)")
            return None
        except Exception as e:
            self._print(f"   Error setting up dockermonkey: {e}")
            return None
    
    def download_oledump(self) -> Optional[str]:
        """Download oledump.py from Didier Stevens Suite"""
        self._print("[*] Checking oledump.py...")
        
        oledump_dir = self.tools_dir / 'DidierStevensSuite'
        oledump_file = oledump_dir / 'oledump.py'
        
        if oledump_file.exists():
            self._print(f"   oledump.py already exists at {oledump_file}")
            self.oledump_path = str(oledump_file)
            return str(oledump_file)
        
        self._print("  -> Downloading Didier Stevens Suite...")
        
        try:
            # Download as ZIP from GitHub
            url = "https://github.com/DidierStevens/DidierStevensSuite/archive/refs/heads/master.zip"
            zip_path = self.tools_dir / 'didier_stevens.zip'
            
            self._print(f"    Downloading from {url}")
            urllib.request.urlretrieve(url, zip_path)
            
            # Extract
            self._print("    Extracting...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.tools_dir)
            
            # Rename directory
            extracted_dir = self.tools_dir / 'DidierStevensSuite-master'
            if extracted_dir.exists():
                if oledump_dir.exists():
                    shutil.rmtree(oledump_dir)
                extracted_dir.rename(oledump_dir)
            
            # Clean up
            zip_path.unlink()
            
            if oledump_file.exists():
                self._print(f"   oledump.py downloaded to {oledump_file}")
                self.oledump_path = str(oledump_file)
                return str(oledump_file)
            else:
                self._print(f"   oledump.py not found after extraction")
                return None
                
        except Exception as e:
            self._print(f"   Failed to download oledump.py: {e}")
            return None
    
    def download_yara_rules(self) -> Optional[str]:
        """Download community YARA rules"""
        self._print("[*] Checking YARA rules...")
        
        yara_dir = self.tools_dir / 'yara_rules'
        
        if yara_dir.exists() and any(yara_dir.glob('*.yar*')):
            self._print(f"   YARA rules already exist at {yara_dir}")
            self.yara_rules_path = str(yara_dir)
            return str(yara_dir)
        
        self._print("  -> Downloading community YARA rules...")
        
        try:
            # Download multiple rule sources
            rule_sources = [
                {
                    'name': 'Yara-Rules',
                    'url': 'https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip',
                    'subdir': 'rules-master'
                },
                {
                    'name': 'Neo23x0-signature-base',
                    'url': 'https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip',
                    'subdir': 'signature-base-master/yara'
                }
            ]
            
            yara_dir.mkdir(parents=True, exist_ok=True)
            
            for source in rule_sources:
                try:
                    self._print(f"    Downloading {source['name']}...")
                    zip_path = self.tools_dir / f"{source['name']}.zip"
                    
                    urllib.request.urlretrieve(source['url'], zip_path)
                    
                    # Extract
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(self.tools_dir / 'temp_yara')
                    
                    # Copy .yar and .yara files
                    source_dir = self.tools_dir / 'temp_yara' / source['subdir']
                    if source_dir.exists():
                        for rule_file in source_dir.rglob('*.yar*'):
                            if rule_file.is_file():
                                # Create subdirectory structure
                                rel_path = rule_file.relative_to(source_dir)
                                dest_file = yara_dir / source['name'] / rel_path
                                dest_file.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(rule_file, dest_file)
                    
                    # Clean up
                    zip_path.unlink()
                    
                    self._print(f"     {source['name']} downloaded")
                    
                except Exception as e:
                    self._print(f"    ! Warning: Failed to download {source['name']}: {e}")
            
            # Clean up temp directory
            temp_dir = self.tools_dir / 'temp_yara'
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            
            # Check if we got any rules
            rule_count = len(list(yara_dir.rglob('*.yar*')))
            if rule_count > 0:
                self._print(f"   Downloaded {rule_count} YARA rule files to {yara_dir}")
                self.yara_rules_path = str(yara_dir)
                return str(yara_dir)
            else:
                self._print(f"  ! Warning: No YARA rules downloaded, continuing without YARA scanning")
                return None
                
        except Exception as e:
            self._print(f"  ! Warning: Failed to download YARA rules: {e}")
            self._print("    Continuing without YARA scanning...")
            return None
    
    def setup_all(self) -> Dict[str, Optional[str]]:
        """Setup all required dependencies"""
        if self.verbose:
            print("=" * 80)
            print("AUTO-SETUP: CHECKING AND DOWNLOADING REQUIRED TOOLS")
            print("=" * 80)
            print(f"Tools directory: {self.tools_dir}\n")
        
        # Check Python dependencies
        python_deps_ok = self.check_python_dependencies()
        if self.verbose:
            print()
        
        # Check Docker
        docker_available = self.check_docker_available()
        if self.verbose:
            print()
        
        # Setup dockermonkey if Docker is available
        dockermonkey_path = None
        if docker_available:
            dockermonkey_path = self.setup_dockermonkey()
        else:
            self._print("[!] Skipping dockermonkey.sh setup (Docker not available)")
        if self.verbose:
            print()
        
        # Download oledump
        oledump_path = self.download_oledump()
        if not oledump_path:
            self._print("\n[!] Warning: oledump.py not available, some features will be limited")
        if self.verbose:
            print()
        
        # Download YARA rules
        yara_path = self.download_yara_rules()
        if not yara_path:
            self._print("\n[!] Warning: YARA rules not available, YARA scanning will be skipped")
        
        if self.verbose:
            print("\n" + "=" * 80)
            print("AUTO-SETUP COMPLETE")
            print("=" * 80 + "\n")
        
        return {
            'oledump_path': oledump_path,
            'yara_rules_path': yara_path,
            'dockermonkey_path': dockermonkey_path,
            'docker_available': docker_available
        }


# Import analysis modules
def import_analysis_modules():
    """Import analysis modules after dependencies are installed"""
    try:
        # from OLE_parser import OLEStaticAnalyzer
        # from OLE_emulator import OLEEmulator
        # return OLEStaticAnalyzer, OLEEmulator
        from parsers.OLE_analysis.OLE_parser import OLEStaticAnalyzer
        from parsers.OLE_analysis.OLE_emulator import OLEEmulator
        return OLEStaticAnalyzer, OLEEmulator
    except ImportError as e:
        raise ImportError(f"Failed to import analysis modules: {e}. "
                         "Ensure OLE_parser.py and OLE_emulator.py are in the same directory or in PYTHONPATH")


class OLEAnalysisPipeline:
    """Comprehensive OLE malware analysis pipeline with Docker-based emulation"""
    
    def __init__(
        self,
        file_path: str,
        output_dir: str = None,
        oledump_path: str = None,
        yara_rules_path: str = None,
        dockermonkey_path: str = None,
        emulation_timeout: int = 300,
        skip_emulation: bool = False,
        skip_static: bool = False,
        auto_setup: bool = True,
        tools_dir: str = None,
        verbose: bool = True
    ):
        """
        Initialize the OLE analysis pipeline
        """
        self.file_path = file_path
        self.output_dir = output_dir or os.getcwd()
        self.emulation_timeout = emulation_timeout
        self.skip_emulation = skip_emulation
        self.skip_static = skip_static
        self.verbose = verbose
        
        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Auto-setup if needed
        if auto_setup:
            dep_manager = DependencyManager(tools_dir, verbose=verbose)
            paths = dep_manager.setup_all()
            
            if oledump_path is None:
                oledump_path = paths.get('oledump_path')
            if yara_rules_path is None:
                yara_rules_path = paths.get('yara_rules_path')
            if dockermonkey_path is None:
                dockermonkey_path = paths.get('dockermonkey_path')
            
            # Auto-skip emulation if Docker/dockermonkey not available
            if not paths.get('docker_available') or not dockermonkey_path:
                if not skip_emulation:
                    if verbose:
                        print("\n[!] Auto-disabling emulation (Docker or dockermonkey.sh not available)")
                    skip_emulation = True
        
        self.oledump_path = oledump_path
        self.yara_rules_path = yara_rules_path
        self.dockermonkey_path = dockermonkey_path
        
        # Import and initialize analyzers
        OLEStaticAnalyzer, OLEEmulator = import_analysis_modules()
        
        self.static_analyzer = None
        self.emulator = None
        
        if not skip_static:
            self.static_analyzer = OLEStaticAnalyzer(
                file_path,
                oledump_path,
                yara_rules_path
            )
        
        if not skip_emulation:
            self.emulator = OLEEmulator(
                file_path,
                emulation_timeout,
                dockermonkey_path=dockermonkey_path,
                tools_dir=tools_dir,
                verbose=verbose  # Pass verbose flag
            )
            
            # Check if emulator was initialized successfully
            if not hasattr(self.emulator, 'dockermonkey_path') or not self.emulator.dockermonkey_path:
                # Always print this warning as it affects analysis results
                print("\n[!] WARNING: Skipping emulation - dockermonkey.sh not available")
                print("    Possible reasons:")
                print("    - Git not installed (needed to clone ViperMonkey repo)")
                print("    - Docker not running")
                print("    - Network issue preventing git clone")
                print("    Solution: Install git and ensure Docker is running")
                skip_emulation = True
                self.emulator = None
        
        self.skip_emulation = skip_emulation
        self.skip_static = skip_static
    
    def _print(self, message: str):
        """Print message if verbose is enabled"""
        if self.verbose:
            print(message)
    
    def run_analysis(self) -> Dict[str, Any]:
        """
        Run complete analysis pipeline
        
        Returns:
            Complete analysis results as dictionary
        """
        if self.verbose:
            print("=" * 80)
            print("OLE MALWARE ANALYSIS PIPELINE (Docker Edition)")
            print("=" * 80)
            print(f"File: {self.file_path}")
            print(f"Started: {datetime.now().isoformat()}")
            print("=" * 80)
        
        # Initialize results structure — top-level keys match PE normalized schema:
        #   format_type, ingest_analysis, analysis_timestamps,
        #   static_analysis, disassembly, dynamic_analysis,
        #   threat_intelligence, verdict, family
        # Pipeline bookkeeping goes under pipeline_metadata (OLE-specific extra).
        results = {
            'format_type': 'OLE',
            'ingest_analysis': {},          # hoisted from static_analysis output
            'analysis_timestamps': {},
            'static_analysis': {},
            'disassembly': {},              # hoisted from static_analysis output
            'dynamic_analysis': {},         # replaces emulation_analysis
            'threat_intelligence': {},      # filled by threat_intel pipeline
            'verdict': {},                  # replaces overall_assessment
            'family': {},                   # filled by family_identifier pipeline
            # OLE-specific bookkeeping (not present in PE schema but harmless)
            'pipeline_metadata': {
                'pipeline_version': '1.1-docker',
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'file_path': os.path.abspath(self.file_path),
                'file_name': os.path.basename(self.file_path),
                'phases_executed': [],
                'tools_used': {
                    'oledump': self.oledump_path is not None,
                    'yara': self.yara_rules_path is not None,
                    'vipermonkey_docker': self.dockermonkey_path is not None,
                },
            },
        }
        
        # Phase 1: Static Analysis
        if not self.skip_static:
            self._print("\n[PHASE 1] STATIC ANALYSIS")
            self._print("-" * 80)
            try:
                static_start = datetime.now(timezone.utc)
                raw_static = self.static_analyzer.analyze()
                static_end = datetime.now(timezone.utc)

                # OLE_parser.analyze() returns the full PE-mirrored report.
                # Hoist top-level fields into the pipeline results dict so the
                # output schema exactly matches the PE normalized report.
                results['ingest_analysis']     = raw_static.get('ingest_analysis', {})
                results['static_analysis']     = raw_static.get('static_analysis', {})
                results['disassembly']         = raw_static.get('disassembly', {})
                # behavioral_analysis is OLE-specific; keep at top level for
                # consumers that want it without digging into static_analysis.
                results['behavioral_analysis'] = raw_static.get('behavioral_analysis', {})

                results['analysis_timestamps']['static_analysis'] = {
                    'start': static_start.isoformat(),
                    'end': static_end.isoformat(),
                    'duration_seconds': (static_end - static_start).total_seconds(),
                }
                results['pipeline_metadata']['phases_executed'].append('static_analysis')

                self._print(f"[OK] Static analysis completed in {(static_end - static_start).total_seconds():.2f}s")

            except Exception as e:
                self._print(f"[ERROR] Static analysis failed: {str(e)}")
                results['static_analysis'] = {'error': str(e), 'status': 'failed'}
        
        # Phase 2: Dynamic Analysis — VBA emulation via Docker/ViperMonkey
        # Results stored under dynamic_analysis to match PE schema key name.
        if not self.skip_emulation and self.emulator:
            self._print("\n[PHASE 2] DYNAMIC ANALYSIS / VBA EMULATION (Docker)")
            self._print("-" * 80)
            try:
                emulation_start = datetime.now(timezone.utc)
                raw_emulation = self.emulator.emulate()
                emulation_end = datetime.now(timezone.utc)

                # Remap emulation output to dynamic_analysis schema that mirrors
                # the PE dynamic_analysis block:
                #   { sandbox, behavior, signatures, ttps, network,
                #     iocs, dropped_files, errors, warnings, summary }
                results['dynamic_analysis'] = self._map_emulation_to_dynamic(raw_emulation)

                results['analysis_timestamps']['dynamic_analysis'] = {
                    'start': emulation_start.isoformat(),
                    'end': emulation_end.isoformat(),
                    'duration_seconds': (emulation_end - emulation_start).total_seconds(),
                }
                results['pipeline_metadata']['phases_executed'].append('dynamic_analysis')

                self._print(f"[] Dynamic analysis completed in {(emulation_end - emulation_start).total_seconds():.2f}s")

            except Exception as e:
                self._print(f"[] Dynamic analysis failed: {str(e)}")
                results['dynamic_analysis'] = {'error': str(e), 'status': 'failed'}
        
        # Phase 3: Verdict — mirrors PE verdict schema
        # { verdict, confidence, override, scores, reasoning, hits }
        self._print("\n[PHASE 3] VERDICT ASSESSMENT")
        self._print("-" * 80)
        results['verdict'] = self._generate_verdict(results)
        
        # Sanitize the entire result tree before returning so that any
        # bytes objects from oletools/olefile are coerced to str and the
        # dict is safe for json.dump() without a custom encoder.
        results = self._sanitize_for_json(results)

        if self.verbose:
            print("\n" + "=" * 80)
            print("ANALYSIS COMPLETE")
            print("=" * 80)

        return results
    
    def _map_emulation_to_dynamic(self, emulation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remap OLE_emulator output to the PE dynamic_analysis schema:

          sandbox       – emulator identity / environment metadata
          behavior      – { summary, processes, anomaly, actions }
          signatures    – high-level behavioural findings (mirrors CAPE signatures[])
          ttps          – MITRE ATT&CK techniques observed at runtime
          network       – { hosts, domains, dns, http, urls, ips }
          iocs          – consolidated IOC list
          dropped_files – list of files written during execution
          errors / warnings
          summary       – counts mirror PE dynamic_analysis.summary
        """
        actions  = emulation.get('actions', {})
        iocs     = emulation.get('iocs', {})
        risk     = emulation.get('risk_assessment', {})

        #  sandbox block 
        sandbox = {
            'id':         emulation.get('metadata', {}).get('emulator', 'ViperMonkey'),
            'machine':    emulation.get('metadata', {}).get('environment', 'unknown'),
            'platform':   'Windows (emulated)',
            'duration':   None,   # ViperMonkey does not report wall-clock duration
            'malscore':   risk.get('risk_score', 0),
            'malstatus':  risk.get('risk_level', 'UNKNOWN'),
            'emulation_success': emulation.get('emulation_success', False),
            'emulator_version':  emulation.get('metadata', {}).get('emulator_version', 'unknown'),
            'timeout':           emulation.get('metadata', {}).get('timeout'),
        }

        #  behavior block 
        behavior = {
            'summary': {
                'file_operations':     len(actions.get('file_operations', [])),
                'registry_operations': len(actions.get('registry_operations', [])),
                'network_operations':  len(actions.get('network_operations', [])),
                'process_operations':  len(actions.get('process_operations', [])),
                'shell_commands':      len(actions.get('shell_commands', [])),
            },
            'processes':   emulation.get('functions_called', []),
            'anomaly':     [],
            'actions':     actions,
            'variables':   emulation.get('variables', {}),
            'external_functions': emulation.get('external_functions', []),
        }

        #  signatures[] — PE-style behavioural findings 
        signatures = []
        for factor in risk.get('risk_factors', []):
            signatures.append({
                'name':        factor,
                'severity':    risk.get('risk_level', 'UNKNOWN'),
                'description': factor,
                'data':        [],
            })
        if emulation.get('obfuscation_detected'):
            signatures.append({
                'name':        'obfuscation_detected',
                'severity':    'MEDIUM',
                'description': 'Code obfuscation techniques identified during emulation',
                'data':        [],
            })
        if emulation.get('anti_analysis_detected'):
            signatures.append({
                'name':        'anti_analysis',
                'severity':    'HIGH',
                'description': 'Anti-analysis or sandbox-evasion behaviour observed',
                'data':        [],
            })

        #  ttps[] — runtime MITRE mapping (mirrors PE ttps[]) 
        ttp_map = {
            'shell_commands':      ('T1059.005', 'Command and Scripting Interpreter: Visual Basic'),
            'network_operations':  ('T1071.001', 'Application Layer Protocol: Web Protocols'),
            'file_operations':     ('T1105',     'Ingress Tool Transfer'),
            'registry_operations': ('T1112',     'Modify Registry'),
            'process_operations':  ('T1059.003', 'Command and Scripting Interpreter: Windows Command Shell'),
        }
        ttps = []
        for action_key, (tid, tname) in ttp_map.items():
            if actions.get(action_key):
                ttps.append({
                    'technique_id':   tid,
                    'name':           tname,
                    'evidence_count': len(actions[action_key]),
                    'source':         'emulation',
                })
        if emulation.get('obfuscation_detected'):
            ttps.append({
                'technique_id': 'T1027',
                'name':         'Obfuscated Files or Information',
                'evidence_count': 1,
                'source':       'emulation',
            })

        #  network block (mirrors PE dynamic_analysis.network) 
        network = {
            'hosts':   list(set(iocs.get('ips', []) + iocs.get('domains', []))),
            'domains': iocs.get('domains', []),
            'dns':     [],
            'http':    [op.get('data', '') for op in actions.get('network_operations', [])],
            'urls':    iocs.get('urls', []),
            'ips':     iocs.get('ips', []),
            'tcp':     [],
            'udp':     [],
        }

        #  consolidated IOCs (superset of static IOCs; mirrors PE iocs) 
        consolidated_iocs = {
            'urls':          iocs.get('urls', []),
            'ips':           iocs.get('ips', []),
            'emails':        iocs.get('emails', []),
            'domains':       iocs.get('domains', []),
            'file_paths':    iocs.get('file_paths', []),
            'registry_keys': iocs.get('registry_keys', []),
            'executables':   iocs.get('executables', []),
        }

        #  summary (mirrors PE dynamic_analysis.summary) 
        summary = {
            'total_actions':          emulation.get('summary', {}).get('total_actions', 0),
            'total_iocs':             emulation.get('summary', {}).get('total_iocs', 0),
            'dropped_files_count':    emulation.get('summary', {}).get('dropped_files_count', 0),
            'variables_captured':     emulation.get('summary', {}).get('variables_captured', 0),
            'functions_called_count': emulation.get('summary', {}).get('functions_called_count', 0),
            'has_obfuscation':        emulation.get('obfuscation_detected', False),
            'has_anti_analysis':      emulation.get('anti_analysis_detected', False),
            'execution_trace_lines':  emulation.get('summary', {}).get('execution_trace_lines', 0),
            'error_count':            emulation.get('summary', {}).get('error_count', 0),
            'warning_count':          emulation.get('summary', {}).get('warning_count', 0),
            'signatures_count':       len(signatures),
            'ttps_count':             len(ttps),
        }

        return {
            'sandbox':       sandbox,
            'behavior':      behavior,
            'signatures':    signatures,
            'ttps':          ttps,
            'network':       network,
            'iocs':          consolidated_iocs,
            'dropped_files': emulation.get('dropped_files', []),
            'errors':        emulation.get('errors', []),
            'warnings':      emulation.get('warnings', []),
            'summary':       summary,
            # Keep the raw execution trace for forensic completeness
            'execution_trace': emulation.get('execution_trace', []),
        }

    def _generate_verdict(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a verdict dict that exactly mirrors the PE normalized verdict schema:
          { verdict, confidence, override, scores, reasoning, hits }

        Scoring is driven by static + dynamic signals, parallel to the PE
        verdict_scorer.py logic so downstream verdict consumers stay format-agnostic.
        """
        scores: Dict[str, float] = {
            'oleid':    0.0,
            'vba':      0.0,
            'yara':     0.0,
            'dynamic':  0.0,
            'iocs':     0.0,
            'embedded': 0.0,
            'corpus':   0.0,
        }
        reasoning: List[str] = []

        # Hits mirrors PE verdict.hits: { capa: [], yara: [] }
        # For OLE we repurpose capa -> vba_keywords, yara -> yara_matches
        hits: Dict[str, List] = {'vba_keywords': [], 'yara': []}

        try:
            static = results.get('static_analysis', {})
            dynamic = results.get('dynamic_analysis', {})

            #  static signals 
            fmt = static.get('format_specific', {})

            # oleid risk score (0-3+ -> 0.0-1.0)
            oleid_risk = fmt.get('oleid_indicators', [])
            raw_oleid = sum(
                3 if 'high' in str(i.get('risk', '')).lower() else
                2 if 'medium' in str(i.get('risk', '')).lower() else
                1 if 'low' in str(i.get('risk', '')).lower() else 0
                for i in oleid_risk
            )
            scores['oleid'] = min(raw_oleid / 10.0, 1.0)
            if scores['oleid'] > 0.5:
                reasoning.append(f"High oleid risk score: {raw_oleid} points across {len(oleid_risk)} indicators")

            # VBA macro signals
            vba_proj = fmt.get('vba_project', {})
            if vba_proj.get('has_macros'):
                scores['vba'] += 0.3
                reasoning.append("VBA macros present")
            if vba_proj.get('auto_exec'):
                scores['vba'] += 0.4
                reasoning.append(f"AutoExec macro(s) detected: {vba_proj['auto_exec']}")
            kws = vba_proj.get('suspicious_keywords', [])
            if kws:
                scores['vba'] = min(scores['vba'] + len(kws) * 0.02, 1.0)
                hits['vba_keywords'] = [k.get('keyword', '') for k in kws[:20]]
                reasoning.append(f"{len(kws)} suspicious VBA keyword(s) found")
            scores['vba'] = min(scores['vba'], 1.0)

            # IOC signals from strings.interesting
            interesting = static.get('strings', {}).get('interesting', {})
            ioc_total = sum(len(v) for v in interesting.values() if isinstance(v, list))
            if ioc_total:
                scores['iocs'] = min(ioc_total / 20.0, 1.0)
                reasoning.append(f"{ioc_total} IOCs found in static strings")

            # Embedded objects
            embed_count = fmt.get('embedded_objects', {}).get('total', 0)
            if embed_count:
                scores['embedded'] = min(embed_count * 0.2, 1.0)
                reasoning.append(f"{embed_count} embedded object(s) found")

            # YARA matches
            yara_data = static.get('yara_matches') or {}
            yara_count = yara_data.get('total_matches', 0)
            if yara_count:
                scores['yara'] = min(yara_count * 0.25, 1.0)
                hits['yara'] = [m.get('rule', '') for m in yara_data.get('matches', [])[:10]]
                reasoning.append(f"{yara_count} YARA rule(s) matched")

            #  dynamic signals 
            sandbox = dynamic.get('sandbox', {})
            if sandbox.get('emulation_success'):
                dyn_risk_score = sandbox.get('malscore', 0)
                scores['dynamic'] = min(dyn_risk_score / 20.0, 1.0)

                sigs = dynamic.get('signatures', [])
                if sigs:
                    reasoning.append(f"{len(sigs)} behavioural signature(s) triggered during emulation")

                ttps = dynamic.get('ttps', [])
                if ttps:
                    reasoning.append(f"{len(ttps)} MITRE ATT&CK technique(s) observed at runtime")

                dropped = dynamic.get('dropped_files', [])
                if dropped:
                    scores['dynamic'] = min(scores['dynamic'] + 0.3, 1.0)
                    reasoning.append(f"CRITICAL: {len(dropped)} file(s) dropped to disk during emulation")

                net = dynamic.get('network', {})
                if net.get('urls') or net.get('ips'):
                    scores['dynamic'] = min(scores['dynamic'] + 0.15, 1.0)
                    reasoning.append(f"Network IOCs: {len(net.get('urls', []))} URL(s), {len(net.get('ips', []))} IP(s)")

            #  composite score -> verdict 
            weights = {
                'oleid': 0.15, 'vba': 0.25, 'yara': 0.20,
                'dynamic': 0.25, 'iocs': 0.10, 'embedded': 0.03, 'corpus': 0.02,
            }
            composite = sum(scores[k] * weights[k] for k in weights)

            if composite >= 0.70:
                verdict_str   = 'malicious'
                confidence    = min(composite, 1.0)
                override_note = None
            elif composite >= 0.45:
                verdict_str   = 'likely_malicious'
                confidence    = composite
                override_note = None
            elif composite >= 0.25:
                verdict_str   = 'suspicious'
                confidence    = composite
                override_note = None
            elif composite >= 0.10:
                verdict_str   = 'potentially_unwanted'
                confidence    = composite
                override_note = None
            else:
                verdict_str   = 'likely_benign'
                confidence    = 1.0 - composite
                override_note = None

            # Hard overrides (mirrors PE verdict_scorer behaviour)
            if scores['yara'] >= 0.75:
                verdict_str = 'malicious'
                confidence  = max(confidence, 0.90)
                override_note = 'yara_hard_match'
                reasoning.append("Override: strong YARA match forces malicious verdict")

            if vba_proj.get('auto_exec') and scores['dynamic'] > 0.5:
                verdict_str = 'malicious'
                confidence  = max(confidence, 0.85)
                override_note = override_note or 'autoexec_with_dynamic_behaviour'
                reasoning.append("Override: AutoExec + high-risk dynamic behaviour")

        except Exception as exc:
            reasoning.append(f"Verdict scoring error: {exc}")
            verdict_str   = 'unknown'
            confidence    = 0.0
            override_note = 'scoring_error'

        return {
            'verdict':    verdict_str,
            'confidence': round(confidence, 4),
            'override':   override_note,
            'scores':     {k: round(v, 4) for k, v in scores.items()},
            'reasoning':  reasoning,
            'hits':       hits,
        }
    
    def _sanitize_for_json(self, obj):
        """
        Recursively sanitize objects for JSON serialization
        Handles type objects, bytes, and other non-serializable types
        """
        if isinstance(obj, dict):
            return {k: self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, tuple):
            return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, bytes):
            try:
                return obj.decode('utf-8', errors='replace')
            except:
                return obj.hex()
        elif isinstance(obj, type):
            # Handle type objects
            return str(obj.__name__)
        elif hasattr(obj, '__dict__'):
            # Handle custom objects
            return str(obj)
        else:
            # Fallback to string representation
            return str(obj)
    
    def save_results(self, results: Dict[str, Any], output_format: str = 'json') -> str:
        """
        Save analysis results to file
        
        Args:
            results: Analysis results dictionary
            output_format: Output format ('json' or 'text')
        
        Returns:
            Path to saved file
        """
        # Generate output filename
        # sha256 lives in ingest_analysis in the PE-mirrored schema;
        # fall back to static_analysis.hashes for older builds.
        file_hash = (
            results.get('ingest_analysis', {}).get('sha256')
            or results.get('static_analysis', {}).get('hashes', {}).get('sha256', 'unknown')
        )
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_format == 'json':
            output_file = os.path.join(
                self.output_dir,
                f"{file_hash}_{timestamp}.json"
            )
            # Sanitize results before saving
            sanitized_results = self._sanitize_for_json(results)
            with open(output_file, 'w') as f:
                json.dump(sanitized_results, f, indent=2)
        
        elif output_format == 'text':
            output_file = os.path.join(
                self.output_dir,
                f"{file_hash}_{timestamp}_report.txt"
            )
            with open(output_file, 'w') as f:
                self._write_text_report(f, results)
        
        if self.verbose:
            print(f"\n[] Results saved to: {output_file}")
        return output_file
    
    def _write_text_report(self, file, results: Dict[str, Any]):
        """Write human-readable text report"""
        file.write("=" * 80 + "\n")
        file.write("OLE MALWARE ANALYSIS REPORT\n")
        file.write("=" * 80 + "\n\n")
        
        # Metadata
        meta = results.get('pipeline_metadata', {})
        file.write(f"Analysis Date: {meta.get('analysis_timestamp', 'N/A')}\n")
        file.write(f"File: {meta.get('file_name', 'N/A')}\n")
        file.write(f"Path: {meta.get('file_path', 'N/A')}\n")
        file.write("\n")
        
        # Overall Assessment
        file.write("OVERALL ASSESSMENT\n")
        file.write("-" * 80 + "\n")
        # verdict now mirrors PE schema: { verdict, confidence, override, scores, reasoning }
        verdict = results.get('verdict', {})
        file.write(f"Verdict: {verdict.get('verdict', 'unknown').upper()}\n")
        file.write(f"Confidence: {verdict.get('confidence', 0) * 100:.1f}%\n")
        file.write(f"Override: {verdict.get('override') or 'none'}\n")
        scores = verdict.get('scores', {})
        score_str = ", ".join("{}={:.2f}".format(k, v) for k, v in scores.items())
        file.write("Scores: " + score_str + "\n")
        file.write("\n")
        
        # Key Findings
        reasoning = verdict.get('reasoning', [])
        if reasoning:
            file.write("\nReasoning:\n")
            for r in reasoning:
                file.write(f"  • {r}\n")
            file.write("\n")
        
        # Recommendations

        
        # Static Analysis Summary
        static = results.get('static_analysis', {})
        if static and 'error' not in static:
            file.write("\nSTATIC ANALYSIS SUMMARY\n")
            file.write("-" * 80 + "\n")
            
            fmt_spec = static.get('format_specific', {})
            vba_proj = fmt_spec.get('vba_project', {})
            file.write(f"VBA Macros: {'Yes' if vba_proj.get('has_macros') else 'No'}\n")
            if vba_proj.get('has_macros'):
                file.write(f"  Macros: {len(vba_proj.get('macros', []))}\n")
                file.write(f"  AutoExec: {len(vba_proj.get('auto_exec', []))}\n")
                file.write(f"  Suspicious Keywords: {len(vba_proj.get('suspicious_keywords', []))}\n")
            sec_feats = static.get('security_features', {})
            file.write(f"YARA Matches: {static.get('yara_matches', {}) and static['yara_matches'].get('total_matches', 0) or 0}\n")
            file.write(f"Oleid Risk Score: {sec_feats.get('OleidRiskScore', 0)}\n")
            file.write("\n")
        
        # Emulation Summary
        dynamic = results.get('dynamic_analysis', {})
        if dynamic and 'error' not in dynamic:
            file.write("\nDYNAMIC ANALYSIS SUMMARY (ViperMonkey / Docker)\n")
            file.write("-" * 80 + "\n")
            sandbox_info = dynamic.get('sandbox', {})
            file.write(f"Emulation: {'Success' if sandbox_info.get('emulation_success') else 'Failed/Skipped'}\n")
            dyn_sum = dynamic.get('summary', {})
            file.write(f"Actions: {dyn_sum.get('total_actions', 0)}\n")
            file.write(f"IOCs: {dyn_sum.get('total_iocs', 0)}\n")
            file.write(f"Dropped Files: {dyn_sum.get('dropped_files_count', 0)}\n")
            file.write(f"Signatures: {dyn_sum.get('signatures_count', 0)}\n")
            file.write(f"MITRE TTPs: {dyn_sum.get('ttps_count', 0)}\n")
            file.write("\n")
        
        file.write("=" * 80 + "\n")
        file.write("END OF REPORT\n")
        file.write("=" * 80 + "\n")


# Convenience function for programmatic use
def analyze_file(
    file_path: str,
    output_dir: str = None,
    save_results: bool = True,
    output_format: str = 'json',
    skip_emulation: bool = False,
    skip_static: bool = False,
    verbose: bool = False,
    **kwargs
) -> Dict[str, Any]:
    """
    Convenience function to analyze an OLE file programmatically
    """
    # Create pipeline
    pipeline = OLEAnalysisPipeline(
        file_path=file_path,
        output_dir=output_dir,
        skip_emulation=skip_emulation,
        skip_static=skip_static,
        verbose=verbose,
        **kwargs
    )
    
    # Run analysis
    results = pipeline.run_analysis()
    
    # Save if requested
    if save_results:
        if output_format == 'both':
            pipeline.save_results(results, 'json')
            pipeline.save_results(results, 'text')
        else:
            pipeline.save_results(results, output_format)
    
    return results


# Batch processing function
def analyze_batch(
    file_paths: List[str],
    output_dir: str = None,
    verbose: bool = True,
    **kwargs
) -> Dict[str, Dict[str, Any]]:
    """
    Analyze multiple OLE files in batch
    """
    results = {}
    
    for i, file_path in enumerate(file_paths, 1):
        if verbose:
            print(f"\n{'='*80}")
            print(f"Processing file {i}/{len(file_paths)}: {file_path}")
            print(f"{'='*80}")
        
        try:
            result = analyze_file(
                file_path=file_path,
                output_dir=output_dir,
                verbose=verbose,
                **kwargs
            )
            results[file_path] = result
        except Exception as e:
            if verbose:
                print(f"[!] Error analyzing {file_path}: {e}")
            results[file_path] = {
                'error': str(e),
                'status': 'failed'
            }
    
    return results


def main():
    """Main entry point for CLI"""
    parser = argparse.ArgumentParser(
        description='OLE Malware Analysis Pipeline with Docker-based ViperMonkey',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (auto-downloads tools, uses Docker for emulation)
  python %(prog)s malicious.doc
  
  # Specify output directory
  python %(prog)s malicious.doc -o ./results
  
  # Use custom tools directory
  python %(prog)s malicious.doc --tools-dir /opt/ole_tools
  
  # Skip auto-setup and use manual paths
  python %(prog)s malicious.doc --no-auto-setup -d /path/to/oledump.py
  
  # Quick scan (skip emulation)
  python %(prog)s malicious.doc --skip-emulation
  
  # Quiet mode (minimal output)
  python %(prog)s malicious.doc --quiet

Programmatic Usage:
  from OLE_driver import analyze_file, analyze_batch
  
  # Single file
  results = analyze_file('malware.doc', verbose=False)
  
  # Multiple files
  results = analyze_batch(['file1.doc', 'file2.xls'])
  
Note: This version uses Docker for ViperMonkey emulation.
No Python 2 installation required!
        """
    )
    
    parser.add_argument('file', help='OLE file to analyze')
    parser.add_argument('-o', '--output-dir', default=None,
                        help='Output directory for results')
    parser.add_argument('-d', '--oledump', default=None,
                        help='Path to oledump.py (auto-downloads if not specified)')
    parser.add_argument('-y', '--yara', default=None,
                        help='Path to YARA rules file/directory (auto-downloads if not specified)')
    parser.add_argument('--dockermonkey', default=None,
                        help='Path to dockermonkey.sh (auto-downloads if not specified)')
    parser.add_argument('-t', '--timeout', type=int, default=300,
                        help='Emulation timeout in seconds (default: 300)')
    parser.add_argument('--skip-static', action='store_true',
                        help='Skip static analysis phase')
    parser.add_argument('--skip-emulation', action='store_true',
                        help='Skip emulation phase')
    parser.add_argument('-f', '--format', choices=['json', 'text', 'both'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('--stdout', action='store_true',
                        help='Print JSON results to stdout')
    parser.add_argument('--no-auto-setup', action='store_true',
                        help='Disable automatic tool download')
    parser.add_argument('--tools-dir', default=None,
                        help='Directory for auto-downloaded tools (default: ~/.ole_analysis_tools)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    # Validate file exists
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    
    # Initialize pipeline
    pipeline = OLEAnalysisPipeline(
        file_path=args.file,
        output_dir=args.output_dir,
        oledump_path=args.oledump,
        yara_rules_path=args.yara,
        dockermonkey_path=args.dockermonkey,
        emulation_timeout=args.timeout,
        skip_emulation=args.skip_emulation,
        skip_static=args.skip_static,
        auto_setup=not args.no_auto_setup,
        tools_dir=args.tools_dir,
        verbose=not args.quiet
    )
    
    # Run analysis
    try:
        results = pipeline.run_analysis()
        
        # Save results
        if args.format in ['json', 'both']:
            pipeline.save_results(results, 'json')
        
        if args.format in ['text', 'both']:
            pipeline.save_results(results, 'text')
        
        # Print to stdout if requested
        if args.stdout:
            print("\n" + "=" * 80)
            print("JSON OUTPUT")
            print("=" * 80)
            print(json.dumps(results, indent=2))
        
        # Print summary (unless quiet mode)
        if not args.quiet:
            print("\n" + "=" * 80)
            print("ANALYSIS SUMMARY")
            print("=" * 80)
            verdict_out = results.get('verdict', {})
            print(f"Verdict: {verdict_out.get('verdict', 'unknown').upper()}")
            scores_out = verdict_out.get('scores', {})
            top_score = max(scores_out.values(), default=0.0)
            print(f"Confidence: {verdict_out.get('confidence', 0) * 100:.1f}%")
            if verdict_out.get('override'):
                print(f"Override: {verdict_out['override']}")
            print("=" * 80)
        
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
