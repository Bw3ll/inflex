project image here - the one you shared with me on slack

# INFLEX

## Overview
INFLEX is a **heterogenous malware analysis framework** designed to analyze and relate malicious artifacts across multiple file formats. The system combines static analysis, emulation, optional dynamic sandboxing, and threat intelligence enrichment to extract behavioral and structural features from malware samples.

Unlike traditional tools that focus on a single file format or analysis technique, INFLEX normalizes analysis outputs across formats such as PE, ELF, shellcode, and OLE documents, enabling cross-domain correlation of malware families, shared infrastructure, novel indicators, and behavioral patterns.

All results are stored in scalable Elasticsearch database and indexed for rapid search, enabling analysts to perform automated and user-driven correlation across large malware collections through an intuitive search interface to achieve rapid threat intelligence enrichment and scalable sample processing.

---

# Key Capabilities

## 1. Multi-Format Malware Analysis
INFLEX supports heterogeneous malware analysis across multiple artifact types:

- Windows PE executables  
- Linux ELF binaries  
- Shellcode  
- OLE / malicious documents  

Each format is parsed using specialized tooling and normalized into a common analysis structure.

## 2. Multi-Modal Analysis Pipeline
INFLEX extracts features using multiple complementary analysis techniques:

- **Static analysis**
- **Emulation**
- **Optional dynamic sandbox execution**

This allows INFLEX to recover structural, behavioral, and runtime features from malware samples.

## 3. Deep Code-Level Similarity
INFLEX performs **function-level disassembly and hashing** to identify shared code structures across samples.

This allows the system to detect:

- Code reuse across malware families
- Variant generation
- Shared developer toolchains

## 4. Threat Intelligence Enrichment
INFLEX enriches samples using external intelligence sources including:

- VirusTotal
- AbuseCH
- AbuseIPDB
- MITRE ATT&CK mappings
- YARA rules
- OSINT enrichment

These integrations provide contextual intelligence to support malware triage and attribution.

## 5. Automated and User-Defined Correlation
INFLEX includes a **correlation engine** capable of linking samples based on:

- Structural similarity
- Behavioral similarity
- Code reuse
- Shared infrastructure indicators
- Threat intelligence overlaps

Analysts can also perform **custom correlation queries** through the UI.

---

# System Architecture

INFLEX is implemented as a **modular Python-based pipeline** designed for scalability and parallel analysis.

Each uploaded sample passes through several independent analysis stages:

## 1. Ingestion and Preprocessing
Samples are uploaded, hashed, and categorized by file type. Metadata and artifacts are stored for downstream analysis.

## 2. Parsing
File-type specific parsers extract format structures and metadata.

Examples include:

| File Type | Tools |
|-----------|------|
| PE | pefile, LIEF |
| ELF | pyelftools, LIEF |
| Shellcode | SHAREM |
| OLE | oletools, oledump |

Outputs are normalized into structured JSON.

## 3. Static Analysis
Static analysis extracts structural and semantic features such as:

- Strings and regex indicators
- Import tables
- Function disassembly
- Entropy measurements
- YARA rule matches
- File metadata

Imports and behaviors can be mapped to **MITRE ATT&CK techniques**.

## 4. Emulation
INFLEX integrates multiple emulation engines to extract runtime behaviors.

- API tracing
- code coverage
- unpacking detection
- behavioral extraction

Engines:
- BEAST
- SHAREM (shellcode) https://github.com/Bw3ll/sharem
- ViperMonkey (malicious macros) https://github.com/decalage2/ViperMonkey

## 5. Optional Dynamic Analysis
INFLEX optionally integrates sandbox analysis (CAPEv2 https://github.com/kevoreilly/CAPEv2) to capture runtime behaviors including:

- process activity
- network communications
- file operations
- registry changes

## 6. Postprocessing and Enrichment
Analysis results are aggregated and enriched with:

- VirusTotal intelligence
- reputation sources
- fuzzy hashing (ssdeep)
- function hash similarity
- OSINT indicators

## 7. Correlation Engine
INFLEX performs automated similarity analysis across samples using multiple signals:

- function hash similarity
- behavioral similarity
- structural similarity
- IOC overlap

This enables clustering of related malware families and campaign artifacts.

## 8. Storage and Search
INFLEX uses Elasticsearch for fast search and analyst-driven correlation queries, maximizing performance and scalability.

---

# Analysis Workflow

picture of the workflow here. reference Slack for more info

---

# Novel Features

- **Cross-Format Malware Correlation**: INFLEX enables correlation **across heterogeneous artifact types**, allowing analysts to identify campaigns spanning multiple delivery mechanisms.

- **Multi-Engine Behavioral Extraction**: Combining **static analysis, emulation, and sandboxing** allows deeper extraction of malicious behaviors than single-mode tools.

- **Function-Level Code Reuse Detection**: Normalized disassembly and function hashing allow identification of shared code structures across malware samples.

- **Integrated Analyst Correlation Interface**: INFLEX allows analysts to construct custom correlation queries using extracted features and threat intelligence data.

---

# General Features

* Multi-format ingestion supporting PE, ELF, shellcode, and OLE documents.
* Static analysis with entropy computation, string extraction, and function hashing.
* Disassembly and control flow analsyis via radare2.
* Optional CAPEv2 sandbox integration for dynamic behavior capture.
* YARA rule matching with support for custom rule uploads.
* Threat intelligence enrichment from VirusTotal, AbuseCH, AbuseIPDB, and automated OSINT searches.
* NoSQL storage in Elasticsearch with horizontal scaling support.

---

# Feature Extraction Summary

INFLEX extracts a wide range of features across analysis stages.

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

---

# Planned / Upcoming Features

- **AI-Assisted Malware Summaries**: LLM-based summarization will assist analysts in generating rapid reports from analysis data.

- **Automated Campaign Detection**: INFLEX will support automated clustering of related samples across file types.

- **Expanded Format Support**: Future versions will support additional formats including scripts and macro-based malware.

---

# Usage

## CLI
INFLEX provides a command-line interface for automated malware analysis workflows.

put commands here

## GUI
A web-based interface allows analysts to:

- upload samples
- search analysis reports
- perform correlation queries
- explore relationships between artifacts

---

# Research Context

INFLEX is developed as part of an ongoing research effort to improve **automated malware analysis and cross-artifact correlation at scale**.

The system is designed to analyze hundreds of samples concurrently and identify relationships between malware artifacts, infrastructure, and behaviors.

---

# Setup


## Dependencies 


---
