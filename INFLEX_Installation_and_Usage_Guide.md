# INFLEX Installation and Usage Guide

INFLEX is a malware analysis framework that combines static analysis, emulation, threat intelligence, similarity analysis, and reporting in a single application. The primary interface is a Flask web application. Users can submit samples, monitor processing, review analysis reports, search completed results, and visualize relationships between samples.

INFLEX is an active research project. Some components are still being integrated. The steps below cover the current Windows-based development environment and identify the configuration needed for each analysis component.

## Contents

1. [Overview](#overview)
2. [System requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Starting INFLEX](#starting-inflex)
6. [Using INFLEX](#using-inflex)
7. [Supported file types](#supported-file-types)
8. [Analysis and reporting](#analysis-and-reporting)
9. [Troubleshooting](#troubleshooting)
10. [Current limitations](#current-limitations)
11. [Repository structure](#repository-structure)
12. [Security considerations](#security-considerations)

## Overview

INFLEX supports several types of analysis:

- **PE and ELF analysis:** File metadata, imports, sections, strings, disassembly, hashes, entropy, packing indicators, and other static features.
- **Office and OLE analysis:** Document structure, VBA indicators, embedded content, and ViperMonkey-assisted analysis where supported.
- **Shellcode analysis:** Heuristic identification and integration with SHAREM.
- **Threat intelligence:** Enrichment through VirusTotal, AbuseIPDB, and MalwareBazaar/Abuse.ch.
- **Detection and correlation:** YARA, capa-related MITRE ATT&CK indicators, similarity comparisons, and malware family analysis.
- **Steganography analysis:** Optional StegoScan integration for applicable files and embedded resources.
- **Dynamic analysis:** Optional CAPE Sandbox submission and report integration.
- **Reporting:** JSON analysis results, Elasticsearch indexing, report search, and relationship graphs.

INFLEX is intended for controlled cybersecurity research. It should be installed and operated in an environment approved for handling potentially malicious files.

## System requirements

### Operating environment

The current installation is oriented toward **Windows with WSL2 and Ubuntu**. Some individual analysis functions may operate on other systems, but the full workflow has not been validated across operating systems.

| Component | Purpose |
| --- | --- |
| Windows | Primary development and application environment. |
| Python 3.10+ | Runs the Flask application and analysis modules. Python 3.11 is a reasonable starting point, but dependency compatibility must be checked. |
| Git | Cloning INFLEX and other analysis repositories. |
| Elasticsearch | Stores analysis records and supports search. |
| radare2 | Disassembly and static code analysis. |
| 7-Zip | Extracts supported ZIP and 7z archives submitted through the web interface. |
| WSL2 with Ubuntu | Provides a Linux environment for selected analysis utilities. |
| Docker | Used by the ViperMonkey execution path when enabled. |
| ViperMonkey | VBA emulation for supported Office documents. |
| SHAREM | Shellcode analysis and emulation. |
| StegoScan | Optional steganography analysis. |
| capa and YARA tooling | Detection rules and capability/ATT&CK-related findings. |
| CAPE Sandbox | Dynamic-analysis integration. A separate, isolated CAPE environment is required when enabled. |

CPU, memory, and storage requirements depend on the workload. INFLEX defaults to five concurrent top-level sample jobs, but individual jobs may create additional processes and threads. Begin with a low concurrency limit and confirm resource usage before increasing it.

### Python dependencies

The current repository does not include a complete `requirements.txt` or `pyproject.toml`. Python packages must be installed for the analysis paths being used. The following packages are used by modules in the repository:

| Package | Used for |
| --- | --- |
| `Flask` | Web application. |
| `requests` | HTTP requests and API integrations. |
| `elasticsearch` | Elasticsearch client. |
| `pefile` | PE parsing. |
| `pyelftools` | ELF parsing. |
| `capstone` | Disassembly and shellcode analysis. |
| `olefile`, `oletools` | Office/OLE and macro analysis. |
| `dnfile` | .NET file parsing. |
| `Pillow`, `numpy` | Image and numerical processing. |
| `malwarebazaar` | MalwareBazaar integration. |
| `abuseipdb-wrapper` | AbuseIPDB integration. |
| `ssdeep`, `pyssdeep`, `ppdeep` | Fuzzy hashing and similarity analysis. |
| `pywin32` | Windows COM features used by some Office analysis functions. |

Some packages require native libraries, build tools, or a compatible Python version. In particular, the fuzzy-hashing packages may need additional setup on Windows.

## Installation

### 1. Download INFLEX

Clone the repository using Git:

```powershell
git clone https://github.com/Bw3ll/inflex.git
cd inflex
```

Alternatively, download the repository as a ZIP from GitHub, extract it, and open a terminal in the directory containing `app.py`.

The project root should contain the following items:

```text
app.py
ingest/
parsers/
static_analysis/
threat_intelligence/
elastic/
templates/
```

### 2. Create a Python virtual environment

From the INFLEX project root, run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
```

If multiple Python versions are installed, you can explicitly select one:

```powershell
py -3.11 -m venv .venv
```

For Windows Command Prompt instead of PowerShell:

```bat
.venv\Scripts\activate.bat
```

**PowerShell execution policy**

If PowerShell prevents the activation script from running, you can use the virtual environment's Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip --version
```

If permitted by your organization, the following command allows locally created scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 3. Install Python packages

If your branch contains a maintained requirements file, use:

```powershell
python -m pip install -r requirements.txt
```

Otherwise, begin with the application and primary parser dependencies:

```powershell
python -m pip install Flask requests elasticsearch pefile pyelftools capstone olefile oletools dnfile Pillow numpy
python -m pip install malwarebazaar abuseipdb-wrapper
```

Install Windows COM support if using the relevant Office analysis functions:

```powershell
python -m pip install pywin32
```

Install and test any additional packages used by your enabled analysis components, including `ssdeep`, `pyssdeep`, and `ppdeep`. The commands above are not a complete dependency installation for every feature.

Confirm the environment:

```powershell
python --version
python -m pip --version
python -m pip list
```

### 4. Install external analysis tools

**radare2**

Install radare2 and ensure its executable is accessible from the environment where INFLEX runs. Test with:

```powershell
r2 -v
```

**7-Zip**

Install the Windows version of 7-Zip. INFLEX looks for `7z.exe` in standard `Program Files` locations when extracting supported archives.

**WSL2 and Ubuntu**

Install WSL2 and an Ubuntu distribution if not already present. Verify the installed distributions:

```powershell
wsl --status
wsl -l -v
wsl -d Ubuntu -- bash -lc "python3 --version"
```

Some INFLEX components explicitly reference the distribution name `Ubuntu`. If you use a differently named distribution, those commands or paths may need adjustment.

**Docker and ViperMonkey**

ViperMonkey's current integration uses a WSL/Docker execution path. Docker must be available within WSL when this feature is used. Confirm with:

```powershell
wsl -d Ubuntu -- bash -lc "docker --version"
```

Confirm that the Docker daemon is available as well. Install and validate ViperMonkey according to the version expected by the INFLEX wrapper. The integration references `dockermonkey.sh`.

**SHAREM**

SHAREM is used for shellcode analysis. The INFLEX wrapper includes installation logic, but SHAREM and its dependencies should be validated independently before processing samples.

**StegoScan, capa, and YARA**

These tools support optional or format-specific analysis functions. Confirm that each tool and its rules or supporting files are available when the relevant feature is enabled.

### 5. Install Elasticsearch

INFLEX uses Elasticsearch for storing and searching analysis reports. The current Windows startup path references **Elasticsearch 9.2.3**, installed under `C:\elasticsearch`.

#### Download and extract

Download the Windows distribution from <https://www.elastic.co/downloads/elasticsearch>.

The expected directory structure is:

```text
C:\elasticsearch\elasticsearch-9.2.3\
    bin\elasticsearch.bat
    bin\elasticsearch-service.bat
    config\elasticsearch.yml
    config\certs\http_ca.crt
```

The certificate location above assumes TLS has been configured and the certificate is available at that path. If your installation uses a different version or directory, update the relevant paths in `app.py` and `elastic/elastic.py`.

#### Java runtime

Check the requirements for the Elasticsearch version being installed. Some distributions include the Java runtime they need. If using a separately installed Java runtime, check its version with:

```powershell
java -version
```

#### Configure Elasticsearch

Open `config\elasticsearch.yml`. For a local development instance, basic configuration may include:

```yaml
cluster.name: malware-analysis
network.host: 127.0.0.1
http.port: 9200
```

INFLEX currently expects an **HTTPS connection** to Elasticsearch. Keep TLS, authentication, the Python client, and the Elasticsearch server configuration consistent. Do not disable Elasticsearch security without also revising the application connection settings and considering the security implications.

#### Start Elasticsearch

Open PowerShell and run:

```powershell
cd C:\elasticsearch\elasticsearch-9.2.3\bin
.\elasticsearch.bat
```

Leave the process running during initial testing. Follow the Elasticsearch startup instructions to configure the user credentials and obtain the CA certificate.

#### Optional Windows service

Elasticsearch can also be installed as a Windows service where the service script is available. Open PowerShell with appropriate permissions and run the following commands from the Elasticsearch `bin` directory:

```powershell
.\elasticsearch-service.bat install
.\elasticsearch-service.bat start
```

To stop or remove the service:

```powershell
.\elasticsearch-service.bat stop
.\elasticsearch-service.bat remove
```

#### Verify the connection

Open <https://localhost:9200> in your browser. An authentication prompt or response is normal when security is enabled.

You can also test the connection using the CA certificate:

```powershell
curl.exe --cacert "C:\elasticsearch\elasticsearch-9.2.3\config\certs\http_ca.crt" -u elastic https://localhost:9200/
```

Enter the Elasticsearch password when prompted. Do not include real passwords in shared commands or screenshots.

#### Configure the INFLEX connection

Elasticsearch connections are currently configured in two main locations:

- `app.py`: `start_elasticsearch_if_needed()` checks `https://localhost:9200` and uses a fixed path to start Elasticsearch if it cannot confirm an active instance.
- `elastic/elastic.py`: `MalwareAnalysisIndexer` connects to Elasticsearch and may use a CA certificate and authentication credentials.

Update the version, certificate location, and authentication values for your environment. Use local or environment-based secrets rather than saving credentials in a public repository.

There is a known issue with the startup check: the request from `app.py` does not include credentials and only recognizes an HTTP `200` response. A healthy secured Elasticsearch instance may respond with `401`, causing INFLEX to attempt starting Elasticsearch again. Confirm Elasticsearch is running independently if this occurs.

### 6. CAPE Sandbox integration (work in progress)

CAPE is intended to provide dynamic malware-analysis results that can be combined with INFLEX's static and threat-intelligence findings. The code includes partial logic for file submission, polling task status, retrieving reports, and merging selected results.

Until the integration is completed, please leave the CAPE disabled until the module, sandbox connection, and report-merging workflow have been tested together.

The CAPE configuration includes:

- `cape_enabled`: Enables or disables CAPE processing.
- `cape_url`: URL for the CAPE API service.
- `cape_api_key`: API token where required.
- `cape_timeout`: Time allowed for analysis and polling.

CAPE should run in a separately secured and isolated sandbox environment. Its installation and guest VM configuration are outside the current INFLEX installation steps.

### 7. Configure threat-intelligence API keys

INFLEX uses two configuration locations for threat-intelligence settings:

- `config.json` in the INFLEX project root stores application settings, including paid API tier flags.
- `threat_intelligence/keys.csv` stores the keys used by the active threat-intelligence module.

Create `threat_intelligence/keys.csv` locally with the following structure:

```csv
service,api_key
VT_API_KEY,REPLACE_WITH_YOUR_VIRUSTOTAL_KEY
ABUSEIPDB_KEY,REPLACE_WITH_YOUR_ABUSEIPDB_KEY
MALWAREBAZAAR_KEY,REPLACE_WITH_YOUR_MALWAREBAZAAR_KEY
```

The CSV column names are `service` and `api_key`. Use the service names shown above so the current loader can find the keys.

**Do not commit populated credentials to GitHub.** Exclude `keys.csv` and any secret-bearing `config.json` from version control. The existing code does not consistently handle missing keys across all analysis paths, so check the configuration before enabling threat-intelligence enrichment.

The Settings page also contains several API-key fields. These are not all connected to the same credential loader. In particular, adding a VirusTotal key to the Settings page does not necessarily populate `keys.csv` for the threat-intelligence module.

### 8. Working directories

INFLEX uses the following directories during analysis:

```text
uploads/
results/
yara_rules/
```

The application creates some directories automatically. Keep sufficient storage available for submitted files, extracted content, generated reports, and Elasticsearch data.

### 9. Installation verification

Before analyzing any malware samples, verify the basic installation:

- [ ] INFLEX is running from the project directory containing `app.py`.
- [ ] Python and the selected virtual environment work correctly.
- [ ] Required Python packages import without errors.
- [ ] radare2 is installed and accessible.
- [ ] WSL2 starts the intended Ubuntu distribution.
- [ ] Elasticsearch is running and responds using the configured HTTPS/TLS and credentials.
- [ ] Threat-intelligence credentials and paid/free settings are configured where needed.
- [ ] The Flask application opens at `http://127.0.0.1:9000/`.
- [ ] A non-malicious test file can be uploaded, analyzed, and found in report search.

Check optional analysis components individually before relying on them in a full analysis workflow.

## Configuration

Open **Settings** in the web application to configure the available options. Settings are stored in `config.json`. Defaults are defined in `app.py`.

| Setting | Default | Description |
| --- | --- | --- |
| `max_concurrent_processes` | `5` | Maximum number of concurrent top-level sample-processing workers. Allowed values: 1 to 64. Requires an INFLEX restart. |
| `max_file_size` | `50` | Intended maximum file size in MB. Enforcement may differ between upload paths. |
| `stego_enabled` | `true` | Enables StegoScan-related processing for supported inputs. |
| `cape_enabled` | `false` | CAPE analysis toggle |
| `vt_paid_key` | `false` | Removes INFLEX's fixed VirusTotal delay when enabled. |
| `abuseipdb_paid_key` | `false` | Removes INFLEX's fixed AbuseIPDB delay when enabled. |
| `abusech_paid_key` | `false` | Removes INFLEX's fixed MalwareBazaar/Abuse.ch delay when enabled. |
| `upload_path` | `./uploads` | Intended upload directory. Some paths are fixed in the application. |
| `results_path` | `./results` | Intended reports directory. Some paths are fixed in the application. |
| `yara_path` | `./yara_rules` | YARA rules directory. |
| `auto_analyze` | `true` | Auto-analysis setting. Verify behavior for the chosen workflow. |
| `delete_after_analysis` | `false` | Deletion option. Do not rely on this until the selected workflow has been tested. |
| `default_zip_password` | `infected` | Configured default archive password. The upload route also accepts a password supplied with the upload. |
| `email_notifications` | `false` | Notification setting. Confirm configuration before use. |

Additional settings include API keys, SMTP information, and notification preferences. Not all configuration fields are used uniformly by each analysis component.

### Free and paid threat-intelligence keys

INFLEX includes fixed delays for free-tier API usage:

| Service | Default delay | Paid-key setting |
| --- | --- | --- |
| VirusTotal | 15 seconds | `vt_paid_key` |
| AbuseIPDB | 2 seconds | `abuseipdb_paid_key` |
| MalwareBazaar/Abuse.ch | 3 seconds | `abusech_paid_key` |

When a paid-key setting is enabled, INFLEX skips the corresponding fixed delay. These settings do not bypass rate limits or quotas enforced by the provider. Retry and backoff handling for actual API/server errors remains separate.

Only enable a paid-key setting when the account supports the intended query volume. The paid paths still need to be tested using valid paid credentials.

### Concurrent processing

`max_concurrent_processes` determines how many sample jobs INFLEX submits for active processing at one time. The default value is `5`. Additional jobs are queued until a worker becomes available.

This setting controls the top-level processing pool. Individual analysis components may use their own subprocesses or threads, so overall CPU utilization may exceed the configured worker count.

Changing this setting requires restarting INFLEX because the process pool is created when the application starts.

## Starting INFLEX

1. Start Elasticsearch and verify its connection.
2. Activate the Python virtual environment.
3. Confirm that required external tools are available.
4. Run the application from the project root:

```powershell
python app.py
```

Open the application at:

<http://127.0.0.1:9000/>

The current application uses Flask's development server with `debug=True`. Do not expose this server to the internet or an untrusted network.

The supported primary interface is the web application. A separate `inflex.py` command-line entry point is not included in the current repository.

## Using INFLEX

### Dashboard

The dashboard displays previously analyzed samples, summary information, and links to reports. Report data is retrieved primarily from Elasticsearch, with a local-results fallback in some paths.

### Upload a sample

1. Open **Uploads** in the navigation menu.
2. Select a file or supported archive.
3. Supply an archive password if needed.
4. Submit the upload.
5. Monitor the job status until analysis is complete.

The web application queues each accepted sample for processing. The `POST /api/upload` endpoint returns HTTP `202 Accepted` with job IDs once jobs are queued. This response does not indicate that the analysis has finished.

For testing the upload API with a harmless file:

```powershell
curl.exe -F "file=@C:\path\to\test-sample.exe" http://127.0.0.1:9000/api/upload
```

Job status can be checked using `GET /api/job/<job_id>`.

### Review a report

Reports can include hashes, file metadata, PE/ELF/OLE analysis, import and string findings, YARA or capa indicators, threat-intelligence information, similarity evidence, verdict information, and results from other enabled analysis components.

Analysis results are generally stored as JSON in `results/` and may also be indexed in Elasticsearch. The application provides a report page and an `/api/report/<hash>` endpoint.

Not every sample produces every type of finding. Unsupported formats, incomplete dependencies, unavailable external services, and disabled modules may result in partial analysis output.

### Search reports

Use **Search Reports** to locate previous analyses and filter the results. Advanced search depends on the report fields available in Elasticsearch and the normalized JSON output. Some advanced filters are still being validated, so confirm important matches against the underlying reports.

### View relationships

Use **Graphs** to explore relationships between processed samples. These views use available similarity and correlation results.

### Update settings

Use **Settings** to change processing limits, analysis options, paths, API configuration, and CAPE parameters. Restart INFLEX after changing the concurrency limit.

## Supported file types

### Direct uploads

The current upload allowlist in `app.py` includes:

```text
.bat .exe .dll .elf .bin .txt .vbs .vbe .wsf .wsh
.doc .docx .xls .xlsx .ppt .pptx .rtf .pdf
.zip .7z .gz .tar
```

An accepted extension does not guarantee that all analysis modules support the format. Some macro-enabled Office formats, including `.docm`, `.xlsm`, and `.pptm`, are recognized by parts of the ingestion pipeline but are not in the current web upload allowlist.

### Archives

INFLEX extracts `.zip` and `.7z` uploads using 7-Zip, then queues eligible extracted files for analysis. Although `.gz` and `.tar` are in the upload allowlist, they do not use the same extraction flow in the current upload route.

### Unsupported VBA project files

Standalone VBA files and project artifacts are not supported by the current Office/OLE analysis toolchain. INFLEX explicitly rejects these extensions:

```text
.rvba .rbva .vba .bas .cls .frm .frx .vbp .vbproj
```

Direct uploads return HTTP `415 Unsupported Media Type`. Unsupported files found inside an archive are skipped and included in the `rejected_files` response. Ingestion also checks for unsupported VBA extensions to prevent them from reaching the analysis tools through another path.

### Shellcode

INFLEX can attempt to identify shellcode in unknown or binary files and route detected samples to SHAREM. The current SHAREM invocation defaults to 32-bit architecture. Interactive selection of 32-bit or 64-bit architecture is not yet implemented in this version.

## Analysis and reporting

The overall workflow is:

```text
File upload / archive extraction
            |
            v
File identification and hashing
            |
            v
Format-specific parsing and static analysis
            |
            +-- PE / ELF analysis
            +-- Office / OLE / VBA analysis
            +-- Shellcode / SHAREM
            +-- StegoScan (when enabled)
            |
            v
Threat-intelligence enrichment
            |
            v
Verdict scoring, similarity and family analysis
            |
            v
JSON report and Elasticsearch indexing
            |
            +-- CAPE dynamic results (integration in progress)
            |
            v
Dashboard / Reports / Search / Graphs
```

INFLEX currently uses separate verdict paths for general file analysis and Office/OLE analysis. The general scoring logic is in `ingest/verdict_scorer.py`, and Office/OLE scoring is in `parsers/OLE_analysis/OLE_driver.py`. Scores and verdicts should be interpreted alongside the underlying findings, not as calibrated probabilities.

## Troubleshooting

| Issue | Check |
| --- | --- |
| A Python module cannot be imported | Verify the active virtual environment, Python version, package installation, and native dependencies. |
| PowerShell blocks virtual environment activation | Use `.venv\Scripts\python.exe` directly or review the execution policy. |
| Elasticsearch connection refused | Confirm Elasticsearch is running and the host, port, TLS settings, certificate, and credentials are correct. |
| Elasticsearch is running but INFLEX tries starting another instance | The startup check may interpret an unauthenticated `401` response as a failed connection. |
| Elasticsearch startup path is incorrect | Update the `elasticsearch.bat` path in `app.py` to match the installed version. |
| Elasticsearch works over HTTP but INFLEX cannot connect | INFLEX currently expects HTTPS. Align the application connection configuration with the server. |
| `requirements.txt` does not exist | The dependency manifest is not included in this version. Install the required packages manually and document the tested versions. |
| Threat intelligence reports a missing API key | Check `threat_intelligence/keys.csv` and the required service names. |
| API returns `401`, `403`, or `429` | Verify credentials, account permissions, subscription limits, and actual provider rate limiting. |
| WSL/ViperMonkey fails | Check `wsl -l -v`, the Ubuntu distribution name, Docker connectivity, and ViperMonkey installation. |
| SHAREM fails to run | Verify SHAREM installation, Python dependencies, Git access, and the invocation environment. |
| Archive extraction fails | Confirm `7z.exe` is installed, the archive is supported, and any password is correct. |
| Upload returns HTTP `415` | Check whether the file has an unsupported standalone VBA extension. |
| Reports are missing or search returns no results | Check the `results/` directory, Elasticsearch connection, indexing, and report schema. |
| Concurrency setting has not changed | Restart INFLEX after saving the new limit. |

For bug reports, include the operating system, Python version, relevant tool versions, exact command or action, sanitized error output, and file type. Do not include credentials or live malware in public issues.

## Current limitations

The following items are still being addressed:

- **Dependency installation:** A complete, tested requirements file is not yet included.
- **Elasticsearch:** Startup and certificate paths are environment-specific. Authentication handling and the initial health check require cleanup.
- **Threat intelligence:** Credentials are managed in both `config.json` and `keys.csv`. Paid API paths still require testing with paid accounts.
- **WSL/tool compatibility:** External analysis tools and their dependencies may require environment-specific adjustments.
- **File handling:** The upload allowlist and the formats recognized by ingestion are not fully aligned. Unsupported standalone VBA files are intentionally rejected.
- **Shellcode:** SHAREM currently defaults to 32-bit architecture without a user selection prompt.
- **Advanced search:** Some report filters require additional validation.
- **Scoring:** General malware scoring and OLE scoring use separate logic. The scoring approach is still being evaluated.

## Repository structure

| Path | Description |
| --- | --- |
| `app.py` | Flask application, uploads, job processing, Settings, reports, and CAPE orchestration code. |
| `templates/` | HTML pages for the dashboard, upload, report, search, graph, and Settings interfaces. |
| `static/` | Web application styles. |
| `ingest/ingest.py` | Analysis orchestration and report generation. |
| `ingest/verdict_scorer.py` | General malware verdict scoring. |
| `parsers/` | File-type parsers and SHAREM-related processing. |
| `parsers/OLE_analysis/` | OLE and VBA analysis and verdict logic. |
| `static_analysis/` | Disassembly, packing, YARA, similarity, and StegoScan integrations. |
| `threat_intelligence/threat_intel.py` | Threat-intelligence lookups and paid/free rate-limit handling. |
| `threat_intelligence/MITRE/` | ATT&CK, capa, and related evidence handling. |
| `elastic/elastic.py` | Elasticsearch indexing and access. |
| `postprocessing/` | Analysis-result processing. |
| `Resources/` | Screenshots and project images. |
| `uploads/`, `results/`, `yara_rules/` | Local processing and output directories. |

## Security considerations

- Run INFLEX in an isolated environment approved for malware research. Submitted samples and extracted content may be dangerous.
- Do not expose the Flask development server or malware-upload endpoints to untrusted networks.
- Keep CAPE analysis guests isolated, with network restrictions appropriate for the research environment, when CAPE integration is enabled.
- Do not commit API keys, Elasticsearch credentials, local configuration secrets, certificates, uploaded samples, or generated malware-analysis data to GitHub.
- Review credential handling before a public release. The current application includes hard-coded Elasticsearch authentication values in some routes, and local debug output should be checked for sensitive information.
- Avoid broad antivirus exclusions on regular workstations. If exclusions are necessary in a research environment, apply them under approved procedures and with compensating controls.
- Exclude generated files such as `__pycache__/`, `*.pyc`, `.venv/`, `.DS_Store`, and runtime artifacts from version control.
- Confirm that samples and indicators may be shared with any third-party threat-intelligence services before enabling external lookups.
