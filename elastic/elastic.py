r"""
Go to C:\elasticsearch in File Explorer

run the bin\elasticsearch.bat file to start Elasticsearch

username: elastic
password: 

view at https://localhost:9200
"""













# Windows Installation
# Step 1: Install Java
# Elasticsearch requires Java 11 or later.
# powershell# Check if Java is installed
# java -version

# # If not installed, download from:
# # https://www.oracle.com/java/technologies/downloads/
# Step 2: Download Elasticsearch

# Go to https://www.elastic.co/downloads/elasticsearch
# Download the Windows ZIP file (elasticsearch-8.11.0-windows-x86_64.zip)
# Extract to C:\elasticsearch

# Step 3: Configure Elasticsearch
# Edit C:\elasticsearch\config\elasticsearch.yml:
# yaml# Disable security for local development
# xpack.security.enabled: false

# # Set cluster name
# cluster.name: malware-analysis

# # Bind to localhost
# network.host: 127.0.0.1

# # HTTP port
# https.port: 9200
# Step 4: Start Elasticsearch
# powershell# Open PowerShell as Administrator
# cd C:\elasticsearch\bin
# .\elasticsearch.bat
# Step 5: Install as Windows Service (Optional)
# powershell# Run as Administrator
# cd C:\elasticsearch\bin
# .\elasticsearch-service.bat install
# .\elasticsearch-service.bat start

# # To stop
# .\elasticsearch-service.bat stop

# # To uninstall
# .\elasticsearch-service.bat remove
# Step 6: Verify Installation
# Open browser: https://localhost:9200

"""
Elasticsearch Indexer for Malware Analysis Results
Indexes JSON analysis files into Elasticsearch with proper mapping
"""

from elasticsearch import Elasticsearch, helpers
from datetime import datetime, timezone
import json
import hashlib
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MalwareAnalysisIndexer:
    """
    Handles indexing of malware analysis JSON files into Elasticsearch
    """
    
    def __init__(self, es_host: str = "localhost", es_port: int = 9200,
                 index_name: str = "malware-analysis", username: str = None, 
                 password: str = None):
        """
        Initialize Elasticsearch connection
        
        Args:
            es_host: Elasticsearch host
            es_port: Elasticsearch port
            index_name: Name of the index to create/use
            username: Optional username for authentication
            password: Optional password for authentication
        """
        # Connect to Elasticsearch
        if username and password:
            self.es = Elasticsearch(
                [f"https://{es_host}:{es_port}"],
                basic_auth=(username, password),
                ca_certs=r"C:\\elasticsearch\\elasticsearch-9.2.3\\config\\certs\\http_ca.crt"
            )
        else:
            self.es = Elasticsearch([f"https://{es_host}:{es_port}"])
        
        self.index_name = index_name
        
        # Test connection
        if not self.es.ping():
            raise ConnectionError("Could not connect to Elasticsearch")
        
        logger.info(f"Connected to Elasticsearch at {es_host}:{es_port}")
        
        # Create index with mapping if it doesn't exist
        self._create_index_if_not_exists()
    
    def _create_index_if_not_exists(self):
        """Create the index with appropriate mapping if it doesn't exist"""
        
        if self.es.indices.exists(index=self.index_name):
            logger.info(f"Index '{self.index_name}' already exists")
            return
        
        # Define index mapping
        mapping = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "30s",
                "index": {
                "codec": "best_compression"
                }
            },
            "mappings": {
                "dynamic": "strict",
                "properties": {
                "sha256": { "type": "keyword" },
                "sha1": { "type": "keyword" },
                "md5": { "type": "keyword" },

                "filename": { "type": "keyword" },
                "original_filename": { "type": "text" },
                "file_size": { "type": "long" },
                "file_type": { "type": "keyword" },
                "mime_type": { "type": "keyword" },

                "ingest_timestamp": { "type": "date" },
                "original_mtime": { "type": "date" },
                "indexed_at": { "type": "date" },

                "pe_info": {
                    "properties": {
                    "is_exe": { "type": "boolean" },
                    "is_dll": { "type": "boolean" },
                    "is_driver": { "type": "boolean" },
                    "imphash": { "type": "keyword" },
                    "compile_timestamp": { "type": "date" },
                    "machine_type": { "type": "keyword" },
                    "subsystem": { "type": "keyword" }
                    }
                },

                "security_features": {
                    "properties": {
                    "ASLR": { "type": "boolean" },
                    "DEP": { "type": "boolean" },
                    "SEH": { "type": "boolean" },
                    "CFG": { "type": "boolean" },
                    "SafeSEH": { "type": "boolean" },
                    "Signed": { "type": "boolean" }
                    }
                },

                "sections": {
                    "type": "nested",
                    "properties": {
                    "name": { "type": "keyword" },
                    "entropy": { "type": "float" },
                    "size": { "type": "long" },
                    "characteristics": { "type": "keyword" },
                    "md5": { "type": "keyword" }
                    }
                },

                "imports": {
                    "type": "nested",
                    "properties": {
                    "dll": { "type": "keyword" },
                    "functions": {
                        "type": "keyword"
                    }
                    }
                },

                "imported_dlls": { "type": "keyword" },
                "imported_functions": { "type": "keyword" },
                "dll_function_pairs": { "type": "keyword" },

                "strings": {
                    "properties": {
                    "ascii": { "type": "match_only_text" },
                    "unicode": { "type": "match_only_text" },
                    "urls": { "type": "keyword" },
                    "ips": { "type": "ip" },
                    "emails": { "type": "keyword" },
                    "file_paths": { "type": "match_only_text" }
                    }
                },

                "disassembly": {
                    "properties": {
                    "function_count": { "type": "integer" },
                    "similar_binaries": {
                        "type": "nested",
                        "properties": {
                        "sha256": { "type": "keyword" },
                        "similarity": { "type": "float" }
                        }
                    }
                    }
                },

                "raw_data": {
                    "type": "object",
                    "enabled": False
                }
                }
            }
        }

        
        self.es.indices.create(index=self.index_name, body=mapping)
        logger.info(f"Created index '{self.index_name}' with mapping")
    
    def _transform_document(self, data: Dict) -> Dict:
        """
        Transform the analysis JSON into an Elasticsearch-friendly format
        
        Args:
            data: Raw analysis JSON data
            
        Returns:
            Transformed document ready for indexing
        """
        doc = {
            "indexed_at": datetime.now(timezone.utc).isoformat(),
            "raw_data": data  # Store original for reference
        }
        
        # Extract ingest analysis
        if "ingest_analysis" in data:
            ingest = data["ingest_analysis"]
            doc["sha256"] = ingest.get("sha256")
            doc["filename"] = ingest.get("filename")
            doc["file_size"] = ingest.get("size_bytes")
            doc["file_type"] = ingest.get("detected_type")
            doc["mime_type"] = ingest.get("mime_type_guess")
            doc["ingest_timestamp"] = ingest.get("ingest_timestamp")
            doc["original_mtime"] = ingest.get("original_mtime")
            doc["original_filename"] = ingest.get("original_path")
        
        # Extract static analysis
        if "static_analysis" in data:
            static = data["static_analysis"]
            
            # Hashes
            if "hashes" in static:
                doc["md5"] = static["hashes"].get("md5")
                doc["sha1"] = static["hashes"].get("sha1")
                if not doc.get("sha256"):
                    doc["sha256"] = static["hashes"].get("sha256")
            
            # Basic info
            if "basic_info" in static:
                doc["pe_info"] = {
                    "is_exe": static["basic_info"].get("is_exe"),
                    "is_dll": static["basic_info"].get("is_dll"),
                    "is_driver": static["basic_info"].get("is_driver")
                }
                if "imphash" in static.get("hashes", {}):
                    doc["pe_info"]["imphash"] = static["hashes"]["imphash"]
            
            # File header info
            if "file_header" in static:
                fh = static["file_header"]
                if "TimeDateStamp" in fh:
                    doc["pe_info"]["compile_timestamp"] = fh["TimeDateStamp"].get("readable")
                if "Machine" in fh:
                    doc["pe_info"]["machine_type"] = fh["Machine"].get("decoded")
            
            # Optional header
            if "optional_header" in static:
                oh = static["optional_header"]
                if "Subsystem" in oh:
                    doc["pe_info"]["subsystem"] = oh["Subsystem"].get("decoded")
            
            # Security features
            if "security_features" in static:
                doc["security_features"] = static["security_features"]
            
            # Sections
            if "sections" in static:
                doc["sections"] = []
                for section in static["sections"]:
                    sec_data = {
                        "name": section.get("Name"),
                        "entropy": section.get("Entropy"),
                        "size": section.get("RawSize"),
                        "md5": section.get("MD5")
                    }
                    if "Characteristics" in section:
                        sec_data["characteristics"] = section["Characteristics"].get("flags", [])
                    doc["sections"].append(sec_data)
            
            # Imports
            if "imports" in static:
                doc["imports"] = []
                doc["imported_dlls"] = []
                doc["imported_functions"] = []
                doc["dll_function_pairs"] = []
                
                for imp in static["imports"]:
                    dll = imp.get("dll")
                    functions = [f.get("name") for f in imp.get("functions", []) if f.get("name")]
                    
                    imp_data = {
                        "dll": dll,
                        "functions": functions
                    }
                    doc["imports"].append(imp_data)
                    
                    # Add to flattened lists for easy searching
                    if dll:
                        doc["imported_dlls"].append(dll)
                        
                        # Create DLL:Function pairs for specific searches
                        for func in functions:
                            doc["imported_functions"].append(func)
                            doc["dll_function_pairs"].append(f"{dll}:{func}")
            
            # Strings
            if "strings" in static:
                strings = static["strings"]
                doc["strings"] = {}
                
                # Limit string arrays to prevent doc size issues
                if "ascii" in strings:
                    doc["strings"]["ascii"] = strings["ascii"][:1000]
                if "unicode" in strings:
                    doc["strings"]["unicode"] = strings["unicode"][:1000]
                
                if "interesting" in strings:
                    interesting = strings["interesting"]
                    doc["strings"]["urls"] = interesting.get("urls", [])
                    doc["strings"]["ips"] = interesting.get("ips", [])
                    doc["strings"]["emails"] = interesting.get("emails", [])
                    doc["strings"]["file_paths"] = interesting.get("file_paths", [])
        
        # Extract disassembly info
        if "disassembly" in data:
            disasm = data["disassembly"]
            doc["disassembly"] = {
                "function_count": disasm.get("function_count"),
                "similar_binaries": disasm.get("similar_binaries", [])
            }
        
        return doc
    
    def index_file(self, json_file_path: str) -> bool:
        """
        Index a single JSON file
        
        Args:
            json_file_path: Path to the JSON file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            doc = self._transform_document(data)
            
            # Use SHA256 as document ID for deduplication
            doc_id = doc.get("sha256")
            if not doc_id:
                logger.warning(f"No SHA256 found in {json_file_path}, generating ID")
                doc_id = hashlib.sha256(json_file_path.encode()).hexdigest()
            
            self.es.index(index=self.index_name, id=doc_id, document=doc)
            logger.info(f"Indexed {json_file_path} with ID {doc_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error indexing {json_file_path}: {e}")
            return False
    
    def bulk_index_files(self, json_file_paths: List[str]) -> Dict:
        """
        Bulk index multiple JSON files
        
        Args:
            json_file_paths: List of paths to JSON files
            
        Returns:
            Dictionary with success/failure counts
        """
        actions = []
        
        for file_path in json_file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                doc = self._transform_document(data)
                doc_id = doc.get("sha256", hashlib.sha256(file_path.encode()).hexdigest())
                
                actions.append({
                    "_index": self.index_name,
                    "_id": doc_id,
                    "_source": doc
                })
                
            except Exception as e:
                logger.error(f"Error preparing {file_path}: {e}")
        
        if not actions:
            logger.warning("No documents to index")
            return {"success": 0, "failed": 0}
        
        # Bulk index
        success, failed = helpers.bulk(self.es, actions, stats_only=True, raise_on_error=False)
        
        logger.info(f"Bulk indexing complete: {success} succeeded, {failed} failed")
        return {"success": success, "failed": failed}
    
    def search(self, query: Dict) -> Dict:
        """
        Execute a search query
        
        Args:
            query: Elasticsearch query DSL
            
        Returns:
            Search results
        """
        return self.es.search(index=self.index_name, body=query)
    
    def get_by_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[Dict]:
        """
        Retrieve a document by hash
        
        Args:
            hash_value: Hash value to search for
            hash_type: Type of hash (sha256, md5, sha1)
            
        Returns:
            Document if found, None otherwise
        """
        query = {
            "query": {
                "term": {
                    hash_type: hash_value
                }
            }
        }
        
        result = self.search(query)
        hits = result.get("hits", {}).get("hits", [])
        
        return hits[0]["_source"] if hits else None
    
    def delete_index(self):
        """Delete the entire index"""
        if self.es.indices.exists(index=self.index_name):
            self.es.indices.delete(index=self.index_name)
            logger.info(f"Deleted index '{self.index_name}'")
    
    def search_by_import(self, function_name: str, dll_name: str = None, size: int = 5) -> List[Dict]:
        """
        Search for files that import a specific function
        
        Args:
            function_name: Name of the imported function
            dll_name: Optional DLL name to narrow search
            size: Number of results to return (default: 5)
            
        Returns:
            List of matching documents
        """
        if dll_name:
            # Search for specific DLL:Function pair
            query = {
                "query": {
                    "term": {
                        "dll_function_pairs": f"{dll_name}:{function_name}"
                    }
                },
                "size": size,
                "_source": ["filename", "sha256", "file_size", "imported_dlls", "imported_functions"]
            }
        else:
            # Search for function across all DLLs
            query = {
                "query": {
                    "term": {
                        "imported_functions": function_name
                    }
                },
                "size": size,
                "_source": ["filename", "sha256", "file_size", "imported_dlls", "imported_functions"]
            }
        
        result = self.search(query)
        return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
    
    def search_by_dll(self, dll_name: str, size: int = 5) -> List[Dict]:
        """
        Search for files that import from a specific DLL
        
        Args:
            dll_name: Name of the DLL (e.g., "KERNEL32.dll")
            size: Number of results to return (default: 5)
            
        Returns:
            List of matching documents
        """
        query = {
            "query": {
                "term": {
                    "imported_dlls": dll_name
                }
            },
            "size": size,
            "_source": ["filename", "sha256", "file_size", "imported_dlls"]
        }
        
        result = self.search(query)
        return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
    
    def get_top_importers(self, function_name: str, dll_name: str = None, limit: int = 5) -> List[Dict]:
        """
        Get top N files that import a specific function, with counts
        
        Args:
            function_name: Name of the imported function
            dll_name: Optional DLL name to narrow search
            limit: Number of results to return (default: 5)
            
        Returns:
            List of files with their details
        """
        return self.search_by_import(function_name, dll_name, size=limit)
    
    def aggregate_imports(self, field: str = "imported_functions", size: int = 20) -> Dict:
        """
        Get aggregated statistics on imports
        
        Args:
            field: Field to aggregate (imported_functions, imported_dlls, dll_function_pairs)
            size: Number of top results to return
            
        Returns:
            Aggregation results showing most common imports
        """
        query = {
            "size": 0,
            "aggs": {
                "top_imports": {
                    "terms": {
                        "field": field,
                        "size": size
                    }
                }
            }
        }
        
        result = self.search(query)
        return result.get("aggregations", {}).get("top_imports", {}).get("buckets", [])
    
    def parse_natural_language_query(self, query_string: str, debug: bool = False) -> Dict:
        """
        Parse natural language queries into Elasticsearch queries with robust error handling
        
        Supports patterns like:
        - "top 5 files with highest entropy and is executable"
        - "find files that import CreateProcessA"
        - "executables with imported KERNEL32.dll"
        - "DLLs with entropy > 7.5"
        - "files signed or unsigned with security features"
        
        Args:
            query_string: Natural language query
            debug: If True, returns debug info with query explanation
            
        Returns:
            Elasticsearch query dictionary ready for execution
            If debug=True, returns tuple: (es_query, debug_info)
        """
        import re
        
        if not query_string or not isinstance(query_string, str):
            logger.warning("Invalid query string provided")
            return {"query": {"match_all": {}}, "size": 10}
        
        original_query = query_string
        query_string = query_string.lower().strip()
        must_clauses = []
        should_clauses = []
        sort_clause = []
        size = 10
        debug_info = {"original_query": original_query, "parsed_conditions": []}
        
        try:
            # Extract limit/top N
            top_match = re.search(r'\b(?:top|limit|first)\s+(\d+)\b', query_string)
            if top_match:
                size = max(1, min(int(top_match.group(1)), 1000))  # Clamp between 1 and 1000
                debug_info["parsed_conditions"].append(f"Limit: {size} results")
            
            # File type filters
            if re.search(r'\b(?:executable|exe|is_exe|is exe|\.exe)\b', query_string):
                must_clauses.append({"term": {"pe_info.is_exe": True}})
                debug_info["parsed_conditions"].append("Filter: Executable")
            elif re.search(r'\bdll(?:s)?\b', query_string) and not re.search(r'\bimport.*dll\b', query_string):
                must_clauses.append({"term": {"pe_info.is_dll": True}})
                debug_info["parsed_conditions"].append("Filter: DLL")
            elif re.search(r'\bdriver(?:s)?\b', query_string):
                must_clauses.append({"term": {"pe_info.is_driver": True}})
                debug_info["parsed_conditions"].append("Filter: Driver")
            
            # Security features - handle "signed or unsigned" case
            if re.search(r'\bunsigned\b', query_string):
                must_clauses.append({"term": {"security_features.Signed": False}})
                debug_info["parsed_conditions"].append("Filter: Unsigned")
            elif re.search(r'\bsigned\b', query_string):
                must_clauses.append({"term": {"security_features.Signed": True}})
                debug_info["parsed_conditions"].append("Filter: Signed")
            
            if re.search(r'\baslr\b', query_string):
                must_clauses.append({"term": {"security_features.ASLR": True}})
                debug_info["parsed_conditions"].append("Filter: ASLR enabled")
            if re.search(r'\b(?:dep|data execution prevention)\b', query_string):
                must_clauses.append({"term": {"security_features.DEP": True}})
                debug_info["parsed_conditions"].append("Filter: DEP enabled")
            if re.search(r'\b(?:cfg|control flow guard)\b', query_string):
                must_clauses.append({"term": {"security_features.CFG": True}})
                debug_info["parsed_conditions"].append("Filter: CFG enabled")
            
            # Entropy searches with validation
            entropy_match = re.search(r'\bentropy\s*([><=]+)\s*([\d.]+)\b', query_string)
            if entropy_match:
                try:
                    operator = entropy_match.group(1)
                    value = float(entropy_match.group(2))
                    
                    # Validate entropy values (0-8 range typical)
                    if not (0 <= value <= 8):
                        logger.warning(f"Entropy value {value} outside typical range [0-8]")
                    
                    if '>=' in operator:
                        must_clauses.append({"range": {"sections.entropy": {"gte": value}}})
                        debug_info["parsed_conditions"].append(f"Filter: Entropy >= {value}")
                    elif '>' in operator:
                        must_clauses.append({"range": {"sections.entropy": {"gt": value}}})
                        debug_info["parsed_conditions"].append(f"Filter: Entropy > {value}")
                    elif '<=' in operator:
                        must_clauses.append({"range": {"sections.entropy": {"lte": value}}})
                        debug_info["parsed_conditions"].append(f"Filter: Entropy <= {value}")
                    elif '<' in operator:
                        must_clauses.append({"range": {"sections.entropy": {"lt": value}}})
                        debug_info["parsed_conditions"].append(f"Filter: Entropy < {value}")
                    elif '=' in operator:
                        must_clauses.append({"range": {"sections.entropy": {"gte": value, "lte": value}}})
                        debug_info["parsed_conditions"].append(f"Filter: Entropy = {value}")
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error parsing entropy condition: {e}")
            elif re.search(r'\b(?:high|highest)\s+entropy\b', query_string):
                sort_clause.append({"sections.entropy": {"order": "desc", "mode": "max"}})
                debug_info["parsed_conditions"].append("Sort: Highest entropy first")
            elif re.search(r'\b(?:low|lowest)\s+entropy\b', query_string):
                sort_clause.append({"sections.entropy": {"order": "asc", "mode": "min"}})
                debug_info["parsed_conditions"].append("Sort: Lowest entropy first")
            
            # Import searches with validation
            import_match = re.search(r'\bimport(?:s)?\s+(?:from\s+)?([A-Za-z0-9_]+(?::[A-Za-z0-9_]+)?)\b', query_string)
            if import_match:
                func_spec = import_match.group(1)
                if ':' in func_spec:
                    try:
                        dll, func = func_spec.split(':')
                        if dll and func:
                            must_clauses.append({"term": {"dll_function_pairs": f"{dll}:{func}"}})
                            debug_info["parsed_conditions"].append(f"Filter: Import {dll}:{func}")
                    except ValueError as e:
                        logger.warning(f"Error parsing import spec {func_spec}: {e}")
                else:
                    must_clauses.append({"term": {"imported_functions": func_spec}})
                    debug_info["parsed_conditions"].append(f"Filter: Import function {func_spec}")
            
            # DLL searches with validation
            dll_match = re.search(r'\b([A-Za-z0-9_]+\.dll)\b', query_string)
            if dll_match:
                dll_name = dll_match.group(1)
                must_clauses.append({"term": {"imported_dlls": dll_name}})
                debug_info["parsed_conditions"].append(f"Filter: DLL {dll_name}")
            
            # File size searches with validation
            filesize_match = re.search(r'\b(?:size|filesize)\s*([><=]+)\s*([\d.]+)\s*([kmg]?b)?', query_string)
            if filesize_match:
                try:
                    operator = filesize_match.group(1)
                    value = float(filesize_match.group(2))
                    unit = (filesize_match.group(3) or 'b').lower()
                    
                    multipliers = {'b': 1, 'kb': 1024, 'mb': 1024**2, 'gb': 1024**3}
                    value_bytes = value * multipliers.get(unit, 1)
                    
                    if value_bytes < 0:
                        logger.warning(f"Negative file size: {value_bytes}")
                        value_bytes = abs(value_bytes)
                    
                    range_query = {}
                    if '>=' in operator:
                        range_query = {"gte": value_bytes}
                        debug_info["parsed_conditions"].append(f"Filter: Size >= {value}{unit}")
                    elif '>' in operator:
                        range_query = {"gt": value_bytes}
                        debug_info["parsed_conditions"].append(f"Filter: Size > {value}{unit}")
                    elif '<=' in operator:
                        range_query = {"lte": value_bytes}
                        debug_info["parsed_conditions"].append(f"Filter: Size <= {value}{unit}")
                    elif '<' in operator:
                        range_query = {"lt": value_bytes}
                        debug_info["parsed_conditions"].append(f"Filter: Size < {value}{unit}")
                    
                    if range_query:
                        must_clauses.append({"range": {"file_size": range_query}})
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error parsing file size: {e}")
            
            # Compile timestamp searches
            if re.search(r'\b(?:recent|new|recent)\b', query_string):
                sort_clause.append({"pe_info.compile_timestamp": {"order": "desc"}})
                debug_info["parsed_conditions"].append("Sort: Recent compilation first")
            elif re.search(r'\b(?:old|ancient)\b', query_string):
                sort_clause.append({"pe_info.compile_timestamp": {"order": "asc"}})
                debug_info["parsed_conditions"].append("Sort: Old compilation first")
            
            # URL/IP searches with validation
            url_match = re.search(r'(?:url[s]?\s+)?(?:containing|with|like|=)\s+["\']?([^\s"\']+)["\']?', query_string)
            if url_match and 'url' in query_string:
                url = url_match.group(1)
                if len(url) > 3:  # Minimum URL length validation
                    must_clauses.append({"match": {"strings.urls": url}})
                    debug_info["parsed_conditions"].append(f"Filter: URL contains '{url}'")
            
            # IP search with validation
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query_string)
            if ip_match:
                ip = ip_match.group(0)
                # Basic IP validation
                octets = [int(x) for x in ip.split('.')]
                if all(0 <= x <= 255 for x in octets):
                    must_clauses.append({"term": {"strings.ips": ip}})
                    debug_info["parsed_conditions"].append(f"Filter: IP {ip}")
                else:
                    logger.warning(f"Invalid IP format: {ip}")
            
            # Sort by file size
            if re.search(r'\b(?:largest|biggest)\b', query_string):
                sort_clause.append({"file_size": {"order": "desc"}})
                debug_info["parsed_conditions"].append("Sort: Largest files first")
            elif re.search(r'\b(?:smallest|minimal)\b', query_string):
                sort_clause.append({"file_size": {"order": "asc"}})
                debug_info["parsed_conditions"].append("Sort: Smallest files first")
            
            # Build final query
            es_query = {
                "size": size,
                "_source": ["filename", "sha256", "file_size", "pe_info", "file_type", "sections"]
            }
            
            # Add query clauses
            if must_clauses or should_clauses:
                bool_query = {}
                if must_clauses:
                    bool_query["must"] = must_clauses
                if should_clauses:
                    bool_query["should"] = should_clauses
                es_query["query"] = {"bool": bool_query}
            else:
                es_query["query"] = {"match_all": {}}
            
            # Add sort
            if sort_clause:
                es_query["sort"] = sort_clause
            
            if debug:
                return es_query, debug_info
            
            logger.debug(f"Parsed query: {json.dumps(es_query, indent=2)}")
            return es_query
            
        except Exception as e:
            logger.error(f"Error parsing query '{original_query}': {e}")
            debug_info["error"] = str(e)
            
            if debug:
                return {"query": {"match_all": {}}, "size": size}, debug_info
            
            return {"query": {"match_all": {}}, "size": size}
    
    def search_natural_language(self, query_string: str, debug: bool = False) -> Dict:
        """
        Execute a natural language query with optional debug output
        
        Args:
            query_string: Plain English query
            debug: If True, includes query explanation and parsed conditions
            
        Returns:
            Dictionary with results and optionally debug info:
            {
                "results": [...],
                "debug": {...}  # only if debug=True
            }
        """
        try:
            result = self.parse_natural_language_query(query_string, debug=debug)
            
            if debug:
                es_query, debug_info = result
            else:
                es_query = result
            
            search_result = self.search(es_query)
            documents = [hit["_source"] for hit in search_result.get("hits", {}).get("hits", [])]
            
            response = {
                "results": documents,
                "total_hits": search_result.get("hits", {}).get("total", {}).get("value", 0)
            }
            
            if debug:
                response["debug"] = debug_info
                response["debug"]["elasticsearch_query"] = es_query
                response["debug"]["total_hits"] = response["total_hits"]
            
            return response
            
        except Exception as e:
            logger.error(f"Error executing natural language search: {e}")
            if debug:
                return {"results": [], "debug": {"error": str(e)}, "total_hits": 0}
            return {"results": [], "total_hits": 0}
    

def add_file_to_index(sample_report = None):
    # Initialize indexer
    indexer = MalwareAnalysisIndexer(
        es_host="localhost",
        es_port=9200,
        index_name="malware-analysis",
        username="elastic",
        password=""
    )

    # Index the provided file
    success = indexer.index_file(sample_report)
    if success:
        print(f"Successfully indexed {sample_report}")
    else:
        print(f"Failed to index {sample_report}")


# Example usage
if __name__ == "__main__":
    # Initialize indexer
    indexer = MalwareAnalysisIndexer(
        es_host="localhost",
        es_port=9200,
        index_name="malware-analysis",
        username="elastic",
        password=""
    )
    
    # Index a single file
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\326f11e54eb9ba91af95f629ad041c461066c3cd88dc73b6f3bccf5eedecae54.json")
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\832dee5c1544cdcc6231fcd4dc5f63525f7082a43782518913093c700c8d1555.json")
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\adc5e56538368cf7813741c802a128a247191276cf8cfff9ada0aa06d83a7bfa.json")
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\0ce805fdbf012822bf83a6c61989651cde1d70cb6be8a2991f4e68abfc25839c_normalized.json")
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\0f6d3be_merged.json")
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\b7ad996132de4f379dc58267b91b6c075a625ab3b7c29099fb79ce289abd5121_normalized.json")
    # indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\ac5fc65ae9500c1107cdd72ae9c271ba9981d22c4d0c632d388b0d8a3acb68f4_normalized.json")
    indexer.index_file(r"C:\\Users\\lcbba\\OneDrive\\Desktop\\INFLEX\\results\\a8dabe249da520a24de691d48bf2549dda65bbb3e62cecd148b1ff0080533cac_normalized.json")

    # Bulk index multiple files
    # files = ["file1.json", "file2.json", "file3.json"]
    # results = indexer.bulk_index_files(files)
    # print(f"Indexed {results['success']} files successfully")
    
    # Search example
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"pe_info.is_exe": True}},
                    {"term": {"security_features.ASLR": False}}
                ]
            }
        }
    }
    results = indexer.search(query)
    
    # Get by hash
    doc = indexer.get_by_hash("326f11e54eb9ba91af95f629ad041c461066c3cd88dc73b6f3bccf5eedecae54")
    if doc:
        print(f"Found file: {doc['filename']}")
    
    # === IMPORT SEARCH EXAMPLES ===
    
    # Get top 5 files that import CreateFileW
    results = indexer.search_by_import("CreateFileW", size=5)
    for doc in results:
        print(f"{doc['filename']}: {doc['sha256']}")
    
    # Get top 5 files that import CreateFileW from KERNEL32.dll specifically
    results = indexer.search_by_import("CreateFileW", dll_name="KERNEL32.dll", size=5)
    
    # Get top 5 files that import from ADVAPI32.dll
    results = indexer.search_by_dll("ADVAPI32.dll", size=5)
    
    # Get top importers using the convenience method
    top_files = indexer.get_top_importers("WriteFile", limit=5)
    
    # Get statistics on most commonly imported functions
    top_functions = indexer.aggregate_imports("imported_functions", size=20)
    print("\nMost commonly imported functions:")
    for item in top_functions:
        print(f"{item['key']}: {item['doc_count']} files")
    
    # Get statistics on most commonly imported DLLs
    top_dlls = indexer.aggregate_imports("imported_dlls", size=10)
    print("\nMost commonly imported DLLs:")
    for item in top_dlls:
        print(f"{item['key']}: {item['doc_count']} files")
