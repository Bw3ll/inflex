# INFLEX

## Overview
INFLEX is a heterogenous malware analysis framework designed to parse, analyze, and correlate diverse file formats including PE, ELF, shellcode, and OLE documents. The system combines static analysis, optional dynamic sandboxing, and multiple emulation engines to extract comprehensive behavioral and structural features from malicious samples. INFLEX automatically computes cross-domain correlations to identify malware families, shared infrastructure, and novel indicators while supporting user defined correlation through an intuitive search interface. All analysis results are stored in a queryable Elasticsearch database, enabling rapid threat intelligence enrichment and scalable sample processing. 

## How INFLEX Works
INFLEX operates as a modular pipeline where each analysis stage functions independently: 

1. Ingestion and Preprocessing: 

2. Parsing and Static Analysis: 

3. Optional Dynamic Analysis: 

4. Emulation:
* BEAST: 
* SHAREM: for more information on this tool vist (https://github.com/Bw3ll/sharem)
* ViperMonkey: for more information on this tool vist (https://github.com/decalage2/ViperMonkey)

5. Normalization: 

6. Threat Inteligence Enrichment: 

7. Correlation Engine: 

8. Storage and Retrieval: 

## Novel Features

* Heterogenous Correlation Across File Types: 

* Multi-Engine Emulation: 

* Automated MITRE ATT&CK Mapping from Multiple Sources: 

* Integrated User-Defined Correlation Interface: 

## General Features

* Multi-format ingestion supporting PE, ELF, shellcode, and OLE documents.

* Static analysis with entropy computation, string extraction, and function hashing.

* Disassembly and control flow analsyis via radare2.

* Optional CAPEv2 sandbox integration for dynamic behavior capture.

* YARA rule matching with support for custom rule uploads.

* Threat intelligence enrichment from VirusTotal, AbuseCH, AbuseIPDB, and automated OSINT searches.

* NoSQL storage in Elasticsearch with horizontal scaling support.

* ...

## Features Extraction List

### Ingest Analysis

* File size (bytes)

* Ingest timestamp (UTC)

* File format metadata (magic bytes, architecture, signatures)

* File extension validation

* Cryptographic hashes (SHA-256, MD5, SHA-1, TLSH)

### Static Analysis

* Headers: PE/ELF/OLE format specific header strucuters. 

* Sections: Names, sizes, entropy, characteristics, virtual address mappings.

* Imports: Function imports, libaries, resolved API signatures. 

* Exports: Exported functions and ordinals. 

* Strings: Printable and wide strings with offsets and encodings.

* Resources: Embedded resources and digital signatures (PE)

* Security Characterstics: ASLE, DEP, SEH flags.

* Function Hashes: ssdeep, imphash, and user function disassembly hashing.

* Entropy Measurements: Section and overall file entropy. 

* IOC Patterns: Regular expression indicator extraction.

* YARA Rule Matches: Detection signatures and classifications.

### Optional Dynamic Analysis

* Process Events: Process creation, module loading, system call events.

* Network Activity: Domain names, IP addresses, URLs, DNS queries.

* File Operations: Writes, reads, dropped files, temporary files.

* Registry Operations: Queried or modified registry keys (Windows)

* Behavioral Signatures: Known behavioral patterns and anomaly indicators. 

### Emulation

* Instruction Trace: Ordered list of executed instructions.

* API Calls: Invoked APIs with parameters and return values.

* Decoded Buffers: Memory regions from decryption/unpacking routines.

* Side Effects: Register changes, memory writes, control-flow transitions.

### Threat Intelligence 

* VirusTotal: Vendor detections, sandbox observations, reputation scores, community labels.

* AbuseCH: Malware URLs, C2 domains, botnet trackers, family classifications, TLS fingerprints.

* AbuseIPDB: Abuse confidence scores, attack categories, report frequency, geographic attribution.

* OSINT Context: Automated Google search results for sample related intelligence. 

### Corelation Metrics

* Function Hash Simularity: User function disassembly hash comparisons.

* Behavior Similarity: Dynamic/Emulation behavior alignment.

* Attribute Simulairty: Structural, metadata, and import library comparisons.

* Combined Scoring: Weighted score combining static, dynamic, emulation, and IOC metrics. 

## Usage

### CLI


### GUI


## Setup


### Dependencies 


## Background and Rational of INFLEX

