"""
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
from datetime import datetime
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
            "indexed_at": datetime.utcnow().isoformat(),
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
    indexer.index_file(r"C:\\Users\\USER\\OneDrive\\Desktop\\INFLEX\\results\\adc5e56538368cf7813741c802a128a247191276cf8cfff9ada0aa06d83a7bfa.json")

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
