import os
import sys
import io
import argparse
import subprocess
import contextlib
import importlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any


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


yara = _safe_import_module('yara')


class YaraPEScanner:
    """
    Scanner class for analyzing PE files with YARA rules from Yara-Rules repository.
    
    Example usage as module:
        scanner = YaraPEScanner(rules_dir="./yara-rules")
        scanner.initialize(update=False)
        results = scanner.scan("malware.exe")
        
        for match in results:
            print(f"Matched: {match['rule_name']}")
    """
    
    def __init__(self, rules_dir: str = "./yara-rules"):
        """
        Initialize the scanner.
        
        Args:
            rules_dir: Directory to store/use YARA rules
        """
        self.rules_dir = rules_dir
        self.compiled_rules = {}
        self._initialized = False
    
    def clone_yara_rules(self, update: bool = False) -> bool:
        """
        Clone the Yara-Rules repository or update if it exists.
        
        Args:
            update: If True, update existing repository with git pull
            
        Returns:
            True if successful, False otherwise
        """
        repo_url = "https://github.com/Yara-Rules/rules.git"
        
        if os.path.exists(self.rules_dir):
            if update:
                print(f"[*] Updating existing rules in {self.rules_dir}...")
                try:
                    result = subprocess.run(
                        ["git", "-C", self.rules_dir, "pull"],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    print("[+] Repository updated successfully")
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"[-] Error updating repository: {e.stderr}")
                    print("[!] Continuing with existing rules...")
                    return True
                except FileNotFoundError:
                    print("[-] Git is not installed. Please install git to continue.")
                    return False
            else:
                print(f"[*] Rules directory already exists at {self.rules_dir}")
                return True
        
        print(f"[*] Cloning Yara-Rules repository to {self.rules_dir}...")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, self.rules_dir],
                capture_output=True,
                text=True,
                check=True
            )
            print("[+] Repository cloned successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error cloning repository: {e.stderr}")
            return False
        except FileNotFoundError:
            print("[-] Git is not installed. Please install git to continue.")
            return False
    
    def compile_rules(self, verbose: bool = True) -> Dict[str, Any]:
        """
        Compile all YARA rules from the repository.
        
        Args:
            verbose: Print compilation progress
            
        Returns:
            Dictionary mapping rule file paths to compiled rules
        """
        if verbose:
            print("[*] Compiling YARA rules...")
        
        rules = {}
        compiled_count = 0
        error_count = 0
        
        # Support compiling a single rule file or a directory of rule files
        if os.path.isfile(self.rules_dir):
            try:
                compiled_rule = yara.compile(filepath=self.rules_dir)
                rules[os.path.basename(self.rules_dir)] = compiled_rule
                compiled_count += 1
            except yara.SyntaxError as e:
                error_count += 1
                if verbose:
                    print(f"[!] Syntax error in {self.rules_dir}: {e}")
            except yara.Error as e:
                error_count += 1
                if verbose:
                    print(f"[!] Error compiling {self.rules_dir}: {e}")
        else:
            for root, dirs, files in os.walk(self.rules_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        rule_path = os.path.join(root, file)
                        relative_path = os.path.relpath(rule_path, self.rules_dir)
                        
                        try:
                            # Try to compile each rule individually
                            compiled_rule = yara.compile(filepath=rule_path)
                            rules[relative_path] = compiled_rule
                            compiled_count += 1
                        except yara.SyntaxError as e:
                            error_count += 1
                            if verbose:
                                print(f"[!] Syntax error in {relative_path}: {e}")
                        except yara.Error as e:
                            error_count += 1
                            if verbose:
                                print(f"[!] Error compiling {relative_path}: {e}")
        
        if verbose:
            print(f"[+] Compiled {compiled_count} rules successfully")
            if error_count > 0:
                print(f"[!] {error_count} rules failed to compile")
        
        self.compiled_rules = rules
        return rules
    
    def initialize(self, skip_clone: bool = False, update: bool = False, verbose: bool = True) -> bool:
        """
        Initialize the scanner by cloning/updating rules and compiling them.
        
        Args:
            skip_clone: Skip cloning the repository (use existing rules)
            update: Update rules from repository if already cloned
            verbose: Print progress messages
            
        Returns:
            True if initialization successful, False otherwise
        """
        if yara is None:
            if verbose:
                print("[-] yara-python is not available. Cannot initialize YARA scanner.")
            return False

        # Clone or update repository if needed
        if not skip_clone:
            if not self.clone_yara_rules(update=update):
                return False
        elif not os.path.exists(self.rules_dir):
            if verbose:
                print(f"[-] Rules directory not found: {self.rules_dir}")
            return False
        
        # Compile rules
        self.compile_rules(verbose=verbose)
        
        if not self.compiled_rules:
            if verbose:
                print("[-] No rules were compiled successfully")
            return False
        
        self._initialized = True
        return True
    
    def scan(self, pe_path: str, verbose: bool = True) -> List[Dict]:
        """
        Scan a PE file with compiled YARA rules.
        
        Args:
            pe_path: Path to the PE file to scan
            verbose: Print scanning progress
            
        Returns:
            List of match dictionaries containing rule_file, rule_name, tags, meta, and strings
        """
        if not self._initialized:
            raise RuntimeError("Scanner not initialized. Call initialize() first.")
        
        if verbose:
            print(f"\n[*] Scanning {pe_path}...")
        
        if not os.path.exists(pe_path):
            if verbose:
                print(f"[-] File not found: {pe_path}")
            return []
        
        all_matches = []
        
        for rule_name, rule in self.compiled_rules.items():
            try:
                matches = rule.match(pe_path)
                if matches:
                    for match in matches:
                        all_matches.append({
                            'rule_file': rule_name,
                            'rule_name': match.rule,
                            'tags': match.tags,
                            'meta': match.meta,
                            'strings': [(s[0], s[1], s[2]) for s in match.strings]
                        })
            except yara.Error as e:
                if verbose:
                    print(f"[!] Error scanning with {rule_name}: {e}")
        
        return all_matches
    
    def format_results(self, matches: List[Dict]) -> str:
        """
        Format scan results as a string.
        
        Args:
            matches: List of match dictionaries from scan()
            
        Returns:
            Formatted string representation of results
        """
        if not matches:
            return "\n[+] No YARA rules matched"
        
        lines = [f"\n[+] Found {len(matches)} matching rules:\n", "=" * 80]
        
        for i, match in enumerate(matches, 1):
            lines.append(f"\n[{i}] Rule: {match['rule_name']}")
            lines.append(f"    File: {match['rule_file']}")
            
            if match['tags']:
                lines.append(f"    Tags: {', '.join(match['tags'])}")
            
            if match['meta']:
                lines.append("    Metadata:")
                for key, value in match['meta'].items():
                    lines.append(f"      {key}: {value}")
            
            if match['strings']:
                lines.append(f"    Matched strings: {len(match['strings'])}")
                for name, offset, data in match['strings'][:5]:  # Show first 5
                    try:
                        display_data = data.decode('utf-8', errors='replace')[:50]
                    except:
                        display_data = str(data[:50])
                    lines.append(f"      {name} at 0x{offset:x}: {display_data}")
                
                if len(match['strings']) > 5:
                    lines.append(f"      ... and {len(match['strings']) - 5} more")
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)
    
    def print_results(self, matches: List[Dict]):
        """
        Print scan results to stdout.
        
        Args:
            matches: List of match dictionaries from scan()
        """
        print(self.format_results(matches))


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Scan PE files using YARA rules from Yara-Rules repository'
    )
    parser.add_argument('pe_file', help='Path to the PE file to scan')
    parser.add_argument(
        '-r', '--rules-dir',
        default='./yara-rules',
        help='Directory to clone/use for YARA rules (default: ./yara-rules)'
    )
    parser.add_argument(
        '--skip-clone',
        action='store_true',
        help='Skip cloning the repository (use existing rules)'
    )
    parser.add_argument(
        '--update',
        action='store_true',
        help='Update rules from repository if already cloned'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Reduce output verbosity'
    )
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = YaraPEScanner(rules_dir=args.rules_dir)
    
    # Initialize scanner
    verbose = not args.quiet
    if not scanner.initialize(skip_clone=args.skip_clone, update=args.update, verbose=verbose):
        sys.exit(1)
    
    # Scan the PE file
    matches = scanner.scan(args.pe_file, verbose=verbose)
    
    # Print results
    scanner.print_results(matches)
    
    return 0 if matches else 1


if __name__ == '__main__':
    sys.exit(main())
