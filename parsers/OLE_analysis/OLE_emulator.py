"""
OLE Emulation Module (Docker Version)
Performs dynamic analysis by running ViperMonkey in Docker container
Uses dockermonkey.sh from the ViperMonkey GitHub repository
Cross-platform support with WSL integration for Windows
"""

import os
import sys
import json
import hashlib
import subprocess
import traceback
import re
import shutil
import platform
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path


# WSL configuration - same as disassembly module
WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")


def detect_environment():
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
        except:
            return "Linux"
    elif system == "Windows":
        return "Windows"
    else:
        return "Other"


def to_wsl_path(win_path: str) -> str:
    """
    Convert a Windows path to a WSL path.
    Handles relative paths by resolving to absolute paths first.
    """
    try:
        p = Path(win_path).resolve()
    except Exception:
        p = Path(win_path)

    drive, tail = os.path.splitdrive(str(p))
    if not drive:
        # No drive - return posix path
        return str(p).replace('\\', '/')

    drive_letter = drive.rstrip(":").lower()
    tail_posix = tail.replace('\\', '/')
    # Ensure leading slash before tail
    if not tail_posix.startswith('/'):
        tail_posix = '/' + tail_posix
    return f"/mnt/{drive_letter}{tail_posix}"


def check_docker_available() -> bool:
    """Check if Docker is installed and running"""
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_dockermonkey_available() -> Optional[str]:
    """Check if dockermonkey.sh is available and return its path"""
    
    # Check if dockermonkey.sh exists in common locations
    common_paths = [
        './dockermonkey.sh',
        './docker/dockermonkey.sh',
        os.path.expanduser('~/.ole_analysis_tools/ViperMonkey/docker/dockermonkey.sh'),
        '/opt/ViperMonkey/docker/dockermonkey.sh',
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return os.path.abspath(path)
    
    # Check in PATH
    dockermonkey_path = shutil.which('dockermonkey.sh')
    if dockermonkey_path:
        return dockermonkey_path
    
    return None


def fix_script_line_endings(script_path: str) -> bool:
    """
    Fix Windows CRLF line endings in shell scripts
    Converts CRLF to LF (Unix format) to prevent bash syntax errors
    
    Args:
        script_path: Path to the shell script
        
    Returns:
        True if fixed or already correct, False on error
    """
    try:
        with open(script_path, 'rb') as f:
            content = f.read()
        
        # Check if file has CRLF line endings
        if b'\r\n' in content:
            crlf_count = content.count(b'\r\n')
            print(f"[*] Fixing {crlf_count} Windows line endings in {Path(script_path).name}...")
            
            # Create backup
            backup_path = Path(script_path).with_suffix('.sh.crlf_backup')
            if not backup_path.exists():  # Don't overwrite existing backups
                with open(backup_path, 'wb') as f:
                    f.write(content)
            
            # Convert CRLF to LF
            fixed_content = content.replace(b'\r\n', b'\n')
            
            with open(script_path, 'wb') as f:
                f.write(fixed_content)
            
            print(f"[✓] Fixed line endings (backup: {backup_path.name})")
        
        return True
    
    except Exception as e:
        print(f"[!] Error fixing line endings: {e}")
        return False


def check_docker_image(image_name: str = "haroldogden/vipermonkey:latest", use_wsl: bool = False) -> bool:
    """
    Check if a Docker image exists locally
    
    Args:
        image_name: Name of the Docker image to check
        use_wsl: Whether to check in WSL (for Windows systems)
        
    Returns:
        True if image exists, False otherwise
    """
    # TODO: This is the command that worked "wsl -d Ubuntu docker pull haroldogden/vipermonkey:latest"
    # For some reason when you enter it now it just hangs, need a more reliable way to check this, could be a problem with the WSL integration or Docker setup, need to investigate further
    try:
        if use_wsl:
            cmd = ['wsl', '-d', WSL_DISTRO, 'docker', 'images', '-q', image_name]
        else:
            cmd = ['docker', 'images', '-q', image_name]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # If image exists, command returns the image ID
        return result.returncode == 0 and len(result.stdout.strip()) > 0
    
    except Exception:
        return False


def pull_docker_image(image_name: str = "haroldogden/vipermonkey:latest", use_wsl: bool = False) -> bool:
    """
    Pull a Docker image
    
    Args:
        image_name: Name of the Docker image to pull
        use_wsl: Whether to use WSL (for Windows systems)
        
    Returns:
        True if successful, False otherwise
    """
    print(f"[*] Pulling Docker image: {image_name}")
    print("[*] This may take several minutes on first run...")
    
    try:
        if use_wsl:
            cmd = ['wsl', '-d', WSL_DISTRO, 'docker', 'pull', image_name]
        else:
            cmd = ['docker', 'pull', image_name]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes
        )
        
        if result.returncode == 0:
            print(f"[✓] Successfully pulled {image_name}")
            return True
        else:
            print(f"[!] Failed to pull {image_name}")
            if result.stderr:
                print(f"    Error: {result.stderr[:200]}")
            return False
    
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout pulling {image_name}")
        return False
    except Exception as e:
        print(f"[!] Error pulling image: {e}")
        return False


def setup_dockermonkey(tools_dir: str = None) -> Optional[str]:
    """
    Download and setup dockermonkey.sh from ViperMonkey GitHub
    
    Args:
        tools_dir: Directory to store the ViperMonkey repository
        
    Returns:
        Path to dockermonkey.sh if successful, None otherwise
    """
    if tools_dir:
        base_dir = Path(tools_dir)
    else:
        base_dir = Path.home() / '.ole_analysis_tools'
    
    base_dir.mkdir(parents=True, exist_ok=True)
    vipermonkey_dir = base_dir / 'ViperMonkey'
    dockermonkey_path = vipermonkey_dir / 'docker' / 'dockermonkey.sh'
    
    # Check if already exists
    if dockermonkey_path.exists():
        print(f"[*] dockermonkey.sh already exists at {dockermonkey_path}")
        # Make sure it's executable
        os.chmod(dockermonkey_path, 0o755)
        # Fix line endings if needed
        fix_script_line_endings(str(dockermonkey_path))
        return str(dockermonkey_path)
    
    print("[*] Cloning ViperMonkey repository...")
    
    try:
        # Clone the repository
        if vipermonkey_dir.exists():
            print("[*] Removing old ViperMonkey directory...")
            shutil.rmtree(vipermonkey_dir)
        
        subprocess.run(
            ['git', 'clone', 'https://github.com/decalage2/ViperMonkey.git', str(vipermonkey_dir)],
            check=True,
            capture_output=True
        )
        
        if dockermonkey_path.exists():
            # Make executable
            os.chmod(dockermonkey_path, 0o755)
            # Fix line endings (important for Windows)
            fix_script_line_endings(str(dockermonkey_path))
            print(f"[✓] dockermonkey.sh installed at {dockermonkey_path}")
            return str(dockermonkey_path)
        else:
            print(f"[!] dockermonkey.sh not found after cloning")
            return None
            
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to clone ViperMonkey repository: {e}")
        return None
    except Exception as e:
        print(f"[!] Error setting up dockermonkey: {e}")
        return None


class OLEEmulator:
    """VBA emulation and behavioral analysis using ViperMonkey in Docker"""
    
    def __init__(self, file_path: str, timeout: int = 300, dockermonkey_path: str = None, tools_dir: str = None, verbose: bool = True):
        """
        Initialize the OLE emulator
        
        Args:
            file_path: Path to the OLE file to emulate
            timeout: Maximum emulation time in seconds
            dockermonkey_path: Path to dockermonkey.sh (auto-detected if None)
            tools_dir: Directory for tools (used for auto-setup)
            verbose: Enable verbose debug output
        """
        self.file_path = os.path.abspath(file_path)
        self.timeout = timeout
        self.tools_dir = tools_dir
        self.verbose = verbose
        
        # Check Docker availability
        if not check_docker_available():
            print("[!] Docker is not available or not running")
            print("    Please install Docker: https://docs.docker.com/get-docker/")
            self.dockermonkey_path = None
            return
        
        # Find or setup dockermonkey.sh
        if dockermonkey_path:
            self.dockermonkey_path = dockermonkey_path
        else:
            self.dockermonkey_path = check_dockermonkey_available()
            
            if not self.dockermonkey_path:
                print("[*] dockermonkey.sh not found, attempting to download...")
                self.dockermonkey_path = setup_dockermonkey(tools_dir)
    
    def emulate(self) -> Dict[str, Any]:
        """
        Run ViperMonkey emulation via Docker
        
        Returns:
            Dictionary containing emulation results
        """
        print(f"[*] Starting VBA emulation of {self.file_path}")
        
        # Detect environment
        env_type = detect_environment()
        
        results = {
            'metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'emulator': 'ViperMonkey (Docker)',
                'emulator_version': self._get_vipermonkey_version(),
                'file_path': self.file_path,
                'timeout': self.timeout,
                'execution_method': 'docker',
                'environment': env_type
            },
            'emulation_success': False,
            'execution_trace': [],
            'actions': {
                'file_operations': [],
                'registry_operations': [],
                'network_operations': [],
                'process_operations': [],
                'shell_commands': []
            },
            'iocs': {
                'urls': [],
                'ips': [],
                'domains': [],
                'file_paths': [],
                'registry_keys': [],
                'executables': [],
                'emails': []
            },
            'dropped_files': [],
            'variables': {},
            'functions_called': [],
            'external_functions': [],
            'obfuscation_detected': False,
            'anti_analysis_detected': False,
            'errors': [],
            'warnings': []
        }
        
        # Check if Docker is available
        if not check_docker_available():
            results['errors'].append({
                'error': 'Docker not available',
                'type': 'DockerNotFound',
                'message': 'Docker is not installed or not running. Please install Docker and ensure the Docker daemon is running.'
            })
            results['warnings'].append('Install Docker to enable emulation: https://docs.docker.com/get-docker/')
            print("[!] Docker not available - skipping emulation")
            return results
        
        # Check if dockermonkey.sh is available
        if not self.dockermonkey_path or not os.path.exists(self.dockermonkey_path):
            results['errors'].append({
                'error': 'dockermonkey.sh not found',
                'type': 'CommandNotFound',
                'message': 'dockermonkey.sh script not available. Clone ViperMonkey repository.'
            })
            results['warnings'].append('Clone ViperMonkey repository to get dockermonkey.sh')
            print("[!] dockermonkey.sh not available - skipping emulation")
            return results
        
        try:
            # Run dockermonkey.sh as subprocess
            print(f"[*] Running dockermonkey.sh: {self.dockermonkey_path}")
            print(f"[*] Analyzing file: {self.file_path}")
            
            # Handle different environments
            if env_type == "Windows":
                # Windows - use WSL with specific distro
                print(f"[*] Using WSL distro: {WSL_DISTRO}")
                
                # Check if ViperMonkey Docker image exists, pull if missing
                if not check_docker_image("haroldogden/vipermonkey:latest", use_wsl=True):
                    print("[*] ViperMonkey Docker image not found")
                    if not pull_docker_image("haroldogden/vipermonkey:latest", use_wsl=True):
                        results['errors'].append({
                            'error': 'Failed to pull ViperMonkey Docker image',
                            'type': 'DockerImageError',
                            'message': 'Could not pull haroldogden/vipermonkey:latest'
                        })
                        print("[!] Failed to pull Docker image - skipping emulation")
                        return results
                else:
                    print("[✓] ViperMonkey Docker image available")
                
                # Check if Docker is accessible in WSL
                docker_check = subprocess.run(
                    ['wsl', '-d', WSL_DISTRO, 'docker', '--version'],
                    capture_output=True,
                    timeout=5
                )
                
                if docker_check.returncode != 0:
                    results['errors'].append({
                        'error': 'Docker not accessible from WSL',
                        'type': 'WSLDockerError',
                        'message': f'Docker not found in WSL distro: {WSL_DISTRO}'
                    })
                    print(f"[!] Docker not accessible from WSL distro: {WSL_DISTRO}")
                    print("    Solution:")
                    print("    1. Open Docker Desktop")
                    print("    2. Settings → Resources → WSL Integration")
                    print(f"    3. Enable integration with '{WSL_DISTRO}'")
                    print("    4. Apply & Restart")
                    return results
                
                # Convert paths to WSL format
                wsl_script_path = to_wsl_path(self.dockermonkey_path)
                wsl_file_path = to_wsl_path(self.file_path)
                
                if self.verbose:
                    print(f"[DEBUG] WSL distro: {WSL_DISTRO}")
                    print(f"[DEBUG] Windows script: {self.dockermonkey_path}")
                    print(f"[DEBUG] WSL script: {wsl_script_path}")
                    print(f"[DEBUG] Windows file: {self.file_path}")
                    print(f"[DEBUG] WSL file: {wsl_file_path}")
                
                # Build command using wsl -d <distro>
                cmd = ['wsl', '-d', WSL_DISTRO, 'bash', wsl_script_path, wsl_file_path]
                cwd = None
                
            elif env_type in ["Linux", "WSL"]:
                # Check if ViperMonkey Docker image exists, pull if missing
                if not check_docker_image("haroldogden/vipermonkey:latest", use_wsl=False):
                    print("[*] ViperMonkey Docker image not found")
                    if not pull_docker_image("haroldogden/vipermonkey:latest", use_wsl=False):
                        results['errors'].append({
                            'error': 'Failed to pull ViperMonkey Docker image',
                            'type': 'DockerImageError',
                            'message': 'Could not pull haroldogden/vipermonkey:latest'
                        })
                        print("[!] Failed to pull Docker image - skipping emulation")
                        return results
                else:
                    print("[✓] ViperMonkey Docker image available")
                
                # Native Linux or already in WSL - run directly
                cmd = [self.dockermonkey_path, self.file_path]
                cwd = os.path.dirname(self.dockermonkey_path)
                
            else:
                results['errors'].append({
                    'error': f'Unsupported environment: {env_type}',
                    'type': 'PlatformError'
                })
                return results
            
            if self.verbose:
                print(f"[DEBUG] Command: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=cwd
            )
            
            stdout = process.stdout
            stderr = process.stderr
            
            # Debug output
            if self.verbose and env_type == "Windows":
                print(f"[DEBUG] Process return code: {process.returncode}")
                if stderr:
                    print(f"[DEBUG] stderr: {stderr[:500]}")
            
            # Check if execution was successful
            if process.returncode == 0 or (stdout and len(stdout) > 100):
                results['emulation_success'] = True
                print("[✓] dockermonkey.sh execution completed")
            else:
                results['warnings'].append(f"dockermonkey.sh returned code {process.returncode}")
                print(f"[!] dockermonkey.sh returned code {process.returncode}")
                
                # Provide specific guidance for exit code 127
                if process.returncode == 127:
                    print("[!] Exit code 127: Command not found in container/WSL")
                    print("    Most likely cause: Docker not accessible from WSL")
                    print("    Solution:")
                    print("    1. Open Docker Desktop")
                    print("    2. Settings → Resources → WSL Integration")
                    print(f"    3. Enable integration with '{WSL_DISTRO}'")
                    print("    4. Apply & Restart Docker Desktop")
                    print(f"\n    Then verify: wsl -d {WSL_DISTRO} docker --version")
                    if stderr:
                        print(f"\n    Error details: {stderr[:200]}")
            
            # Parse the output
            results = self._parse_vmonkey_output(stdout, stderr, results)
            
        except subprocess.TimeoutExpired:
            results['errors'].append({
                'error': f'Emulation timeout after {self.timeout} seconds',
                'type': 'TimeoutExpired'
            })
            print(f"[!] Emulation timed out after {self.timeout}s")
        except FileNotFoundError:
            results['errors'].append({
                'error': f'dockermonkey.sh not found at {self.dockermonkey_path}',
                'type': 'FileNotFoundError'
            })
            print(f"[!] dockermonkey.sh not found")
        except Exception as e:
            results['errors'].append({
                'error': str(e),
                'type': type(e).__name__,
                'traceback': traceback.format_exc()
            })
            print(f"[!] Emulation error: {e}")
        
        # Post-process results
        results = self._post_process_results(results)
        
        print("[✓] Emulation complete")
        return results
    
    def _get_vipermonkey_version(self) -> str:
        """Get ViperMonkey version from Docker container"""
        if not check_docker_available():
            return 'docker_not_available'
        
        if not self.dockermonkey_path:
            return 'not_installed'
        
        try:
            # Run dockermonkey.sh with -h to get version info
            cwd = os.path.dirname(self.dockermonkey_path)
            result = subprocess.run(
                [self.dockermonkey_path, '-h'],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=cwd
            )
            
            # Try to extract version from output
            version_match = re.search(r'(\d+\.\d+\.\d+)', result.stdout + result.stderr)
            if version_match:
                return version_match.group(1)
            
            return 'docker_latest'
        except:
            return 'unknown'
    
    def _parse_vmonkey_output(self, stdout: str, stderr: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Parse ViperMonkey Docker output"""
        
        combined_output = stdout + '\n' + stderr
        lines = combined_output.split('\n')
        
        # Patterns to match
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        file_pattern = re.compile(r'(?:[A-Z]:\\|/)(?:[^\s\\/:*?"<>|\r\n]+[\\\/])*[^\s\\/:*?"<>|\r\n]+\.\w+', re.IGNORECASE)
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        for line in lines:
            # Skip empty lines and Docker-specific output
            if not line.strip() or 'docker' in line.lower() or 'pulling from' in line.lower():
                continue
            
            # Store execution trace (limited to avoid bloat)
            if len(results['execution_trace']) < 1000:
                results['execution_trace'].append(line)
            
            # Detect file operations
            file_ops = ['open', 'write', 'create', 'delete', 'saveas', 'save', 'mkdir']
            if any(op in line.lower() for op in file_ops):
                if 'open' in line.lower() or 'create' in line.lower():
                    results['actions']['file_operations'].append({
                        'type': 'file_create' if 'create' in line.lower() else 'file_open',
                        'data': line.strip()
                    })
                elif 'write' in line.lower() or 'save' in line.lower():
                    results['actions']['file_operations'].append({
                        'type': 'file_write',
                        'data': line.strip()
                    })
                elif 'delete' in line.lower():
                    results['actions']['file_operations'].append({
                        'type': 'file_delete',
                        'data': line.strip()
                    })
            
            # Detect registry operations
            reg_keywords = ['regwrite', 'regread', 'regdelete', 'hkey_', 'registry']
            if any(keyword in line.lower() for keyword in reg_keywords):
                results['actions']['registry_operations'].append({
                    'type': 'registry_modification',
                    'data': line.strip()
                })
            
            # Detect network operations
            network_keywords = ['http', 'download', 'urldownloadtofile', 'winhttp', 'xmlhttp', 'request']
            if any(keyword in line.lower() for keyword in network_keywords):
                results['actions']['network_operations'].append({
                    'type': 'network_request',
                    'data': line.strip()
                })
            
            # Detect process/shell operations
            shell_keywords = ['shell', 'run', 'exec', 'wscript.shell', 'createobject("wscript.shell")']
            if any(keyword in line.lower() for keyword in shell_keywords):
                # Check for dropped files
                if 'dropped file' in line.lower() or 'wrote' in line.lower():
                    file_match = re.search(r'wrote\s+(.+)', line, re.IGNORECASE)
                    if file_match:
                        dropped_file = file_match.group(1).strip()
                        if dropped_file not in [f['path'] for f in results['dropped_files']]:
                            results['dropped_files'].append({
                                'path': dropped_file,
                                'source': 'emulation'
                            })
                
                results['actions']['shell_commands'].append({
                    'type': 'shell_execution',
                    'data': line.strip()
                })
            
            # Process creation
            if 'process' in line.lower() and ('create' in line.lower() or 'start' in line.lower()):
                results['actions']['process_operations'].append({
                    'type': 'process_create',
                    'data': line.strip()
                })
            
            # Extract URLs
            urls = url_pattern.findall(line)
            for url in urls:
                if url not in results['iocs']['urls']:
                    results['iocs']['urls'].append(url)
            
            # Extract IPs
            ips = ip_pattern.findall(line)
            for ip in ips:
                # Filter out common false positives
                if not ip.startswith('127.') and not ip.startswith('0.0.') and ip not in results['iocs']['ips']:
                    results['iocs']['ips'].append(ip)
            
            # Extract file paths
            files = file_pattern.findall(line)
            for file_path in files:
                if file_path not in results['iocs']['file_paths']:
                    results['iocs']['file_paths'].append(file_path)
            
            # Extract emails
            emails = email_pattern.findall(line)
            for email in emails:
                if email not in results['iocs']['emails']:
                    results['iocs']['emails'].append(email)
            
            # Detect obfuscation techniques
            obfuscation_keywords = ['chr(', 'asc(', 'strreverse', 'replace(', 'mid(', 'decode', 'base64']
            if any(keyword in line.lower() for keyword in obfuscation_keywords):
                results['obfuscation_detected'] = True
            
            # Detect anti-analysis
            anti_analysis_keywords = ['sleep', 'sandbox', 'virtual', 'vmware', 'vbox', 'debugger', 'analysis']
            if any(keyword in line.lower() for keyword in anti_analysis_keywords):
                results['anti_analysis_detected'] = True
            
            # Extract variable assignments (simplified)
            if '=' in line and not line.startswith('=') and 'Resolve' not in line:
                var_match = re.match(r'(\w+)\s*=\s*(.+)', line)
                if var_match:
                    var_name, var_value = var_match.groups()
                    # Only store if not too long and looks meaningful
                    if len(var_value) < 200 and not var_value.startswith('ViperMonkey'):
                        results['variables'][var_name] = var_value[:1000]
            
            # Extract function calls
            if 'CALL' in line.upper() or '()' in line:
                func_match = re.search(r'(\w+)\s*\(', line)
                if func_match:
                    func_name = func_match.group(1)
                    if func_name not in results['functions_called']:
                        results['functions_called'].append(func_name)
            
            # Detect external function calls
            external_keywords = ['CreateObject', 'WScript', 'Shell', 'Environ', 'GetObject']
            for keyword in external_keywords:
                if keyword.lower() in line.lower():
                    if keyword not in results['external_functions']:
                        results['external_functions'].append(keyword)
        
        # Parse domains from URLs
        for url in results['iocs']['urls']:
            domain_match = re.search(r'https?://([^/:\s]+)', url)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in results['iocs']['domains']:
                    results['iocs']['domains'].append(domain)
        
        # Identify executables from file paths
        for file_path in results['iocs']['file_paths']:
            if file_path.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.com')):
                if file_path not in results['iocs']['executables']:
                    results['iocs']['executables'].append(file_path)
        
        # Extract registry keys
        for action in results['actions']['registry_operations']:
            reg_match = re.search(r'(HKEY_[A-Z_]+\\[^\s,\]]+)', action['data'], re.IGNORECASE)
            if reg_match:
                reg_key = reg_match.group(1)
                if reg_key not in results['iocs']['registry_keys']:
                    results['iocs']['registry_keys'].append(reg_key)
        
        return results
    
    def _post_process_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process and deduplicate results"""
        try:
            # Deduplicate all lists
            for category in results['iocs']:
                if isinstance(results['iocs'][category], list):
                    results['iocs'][category] = list(set(results['iocs'][category]))
            
            results['functions_called'] = list(set(results['functions_called']))
            results['external_functions'] = list(set(results['external_functions']))
            
            # Remove empty variables
            results['variables'] = {k: v for k, v in results['variables'].items() if v and len(v.strip()) > 0}
            
            # Calculate summary statistics
            results['summary'] = {
                'total_actions': sum(len(v) for v in results['actions'].values()),
                'total_iocs': sum(len(v) for v in results['iocs'].values()),
                'dropped_files_count': len(results['dropped_files']),
                'variables_captured': len(results['variables']),
                'functions_called_count': len(results['functions_called']),
                'external_functions_count': len(results['external_functions']),
                'has_obfuscation': results['obfuscation_detected'],
                'has_anti_analysis': results['anti_analysis_detected'],
                'execution_trace_lines': len(results['execution_trace']),
                'error_count': len(results['errors']),
                'warning_count': len(results['warnings'])
            }
            
            # Add risk assessment
            risk_score = 0
            risk_factors = []
            
            if results['actions']['shell_commands']:
                risk_score += 3
                risk_factors.append(f"Shell command execution detected ({len(results['actions']['shell_commands'])} instances)")
            
            if results['actions']['file_operations']:
                risk_score += 2
                risk_factors.append(f"File operations detected ({len(results['actions']['file_operations'])} instances)")
            
            if results['actions']['registry_operations']:
                risk_score += 2
                risk_factors.append(f"Registry operations detected ({len(results['actions']['registry_operations'])} instances)")
            
            if results['actions']['network_operations']:
                risk_score += 3
                risk_factors.append(f"Network operations detected ({len(results['actions']['network_operations'])} instances)")
            
            if results['obfuscation_detected']:
                risk_score += 2
                risk_factors.append("Code obfuscation techniques detected")
            
            if results['anti_analysis_detected']:
                risk_score += 2
                risk_factors.append("Anti-analysis techniques detected")
            
            if results['iocs']['urls']:
                risk_score += 2
                risk_factors.append(f"{len(results['iocs']['urls'])} URLs detected")
            
            if results['dropped_files']:
                risk_score += 3
                risk_factors.append(f"{len(results['dropped_files'])} files dropped")
            
            if results['external_functions']:
                risk_score += 1
                risk_factors.append(f"External functions called: {', '.join(results['external_functions'][:5])}")
            
            results['risk_assessment'] = {
                'risk_score': risk_score,
                'risk_level': self._calculate_risk_level(risk_score),
                'risk_factors': risk_factors
            }
            
        except Exception as e:
            results['warnings'].append(f"Error in post-processing: {str(e)}")
        
        return results
    
    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from score"""
        if score >= 10:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        else:
            return "MINIMAL"


def main():
    """Main function for standalone execution"""
    if len(sys.argv) < 2:
        print("Usage: python OLE_emulator.py <ole_file> [timeout]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    
    emulator = OLEEmulator(file_path, timeout)
    results = emulator.emulate()
    
    # Output as JSON
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

    # TODO: now this is not working with the auto docker config, plus need to do the line endings fix