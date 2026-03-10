# INFLEX

## Overview
INFLEX is a heterogenous malware analysis framework designed to parse, analyze, and correlate diverse file formats including PE, ELF, shellcode, and OLE documents. The system combines static analysis, optional dynamic sandboxing, and multiple emulation engines to extract comprehensive behavioral and structural features from malicious samples. INFLEX automatically computes cross-domain correlations to identify malware families, shared infrastructure, and novel indicators while supporting user defined correlation through an intuitive search interface. All analysis results are stored in a queryable Elasticsearch database, enabling rapid threat intelligence enrichment and scalable sample processing. 

## INFLEX DEMO DESCRIPTION

### Analysis Dashboard 
INFLEX supplies analysits with a concise dashboard to quickly search through sample reports and know which samples warrant analysis manual inspection. 

### Heterogenous File Upload
INFLEX supports PE, ELF, OLE, and Shellcode analysis and report generation enabling a one stop shop for malware analysis. 

### Optional Dynamic Analysis
To enhace the static and emulation analysis INFLEX supports public CAPEv2 sandbox analysis and local sandbox configureations.

### Heterogenous File Reports 
INFLEX processes PE, ELF, OLE, and Shellcode samples and normalizes the output into common features when possible while maintaing the detailed structure of each type to enhance heterogenous correlations. 

### Integrated Threat Intelligence 
To enrich the analysis threat sources like VirusTotal, AbuseCH, AbuseIPDB, Targeted Google Searches, MITRE STIX database, CAPA rules, YARA rules, and more are combined to flag new malware and identify threat vectors. 

### Full Function Disassembly and Hashing
To ebable the possibly of identifying code reuse and improve file simularity each sample's dissassembly is normalized and hashed by function with the target of finding code structures that are shared between files at a deeper level than done before. 

### Static, Dynamic, and Emulation Analysis
INFLEX aims to extract and enrich the maximum data out of uploaded samples by perfomrming deep static analysis, sample emulation, and dynamic analysis to provide analysit with feature and function descriptions. 

### User Defined Correlations
Assisting the triage process INFLEX leverages ElasticSearch to fule a user defined corelation engine to discover simular samples and cross sample analysis. 

### Automatic Report Updates
Once INFLEX is done anlyizing the uploaded samples automatic sample comparisons and reports are generated and displayed to the dashboard. 

## Upcoming Features

### AI Summerization
INFLEX will use LLM summerization to give detailed analysis and reports to expidiate reporting of malicous samples. 

### Automated Correlations 
Ontop of the user defined correlations INFLEX will support automated correlations ran off of the features extracted for rapid deep file comparisions. 

### Heterogenous Capaign Tracking
Utlizing the normalized extracted features and threat intelligence INFLEX will be able to identifiy samples that are simular across file types.

### PE, ELF, OLE, and Shellcode support 
INFLEX will support the full analysis of PE, ELF, OLE, and Shellcode giving analysists a one stop shop for malware analysis. 

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

