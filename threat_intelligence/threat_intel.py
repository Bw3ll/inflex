# TODO: Make this the driver that is called form above to then run all of the threat intell sources
# TODO: Merge the found data here into the files analysis and actually pipeline it now that these have been tested
import csv
import json
import os
import time
from pathlib import Path
import requests
from abuseipdb_wrapper import AbuseIPDB  # pip install abuseipdb-wrapper
from malwarebazaar import Bazaar, Yaraify  # pip install malwarebazaar
from malwarebazaar.models import YaraRule
from threat_intelligence.MITRE.mitre_updator import run_mitre

# ======================================
# CONFIGURATION
# ======================================

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
ABUSECH_URL = "https://mb-api.abuse.ch/api/v1/"

STATIC_ANALYSIS_JSON = "results/326f11e54eb9ba91af95f629ad041c461066c3cd88dc73b6f3bccf5eedecae54.json"
OUTPUT_FILE = "threat_intel_full.json"



def load_runtime_config() -> dict:
    """Load non-secret runtime settings from the project-level config.json."""
    config_path = Path(__file__).resolve().parents[1] / "config.json"
    if not config_path.exists():
        return {}
    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Could not load threat-intelligence runtime config: {e}")
        return {}


def is_paid_key(config: dict, setting_name: str) -> bool:
    """Return True only when a provider has explicitly been marked as a paid key."""
    return config.get(setting_name) is True


def load_api_keys(csv_path: str) -> dict:
    keys = {}
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            service = row.get("service")
            key = row.get("api_key")
            if service and key:
                keys[service] = key
    return keys


# ======================================
# VIRUSTOTAL ENRICHMENT
# ======================================

def query_virustotal(VT_API_KEY, sha256_hash, detailed=False):
    """Query VirusTotal for a file hash.
    
    Args:
        sha256_hash: The SHA256 hash to query
        detailed: If True, returns comprehensive data. If False, returns simplified format.
    """
    if not VT_API_KEY:
        return {"error": "No API key provided"}

    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL.format(sha256_hash)
    
    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            
            if not detailed:
                # Simple format (original working version)
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "status": stats,
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
            else:
                # Detailed format with comprehensive data
                attrs = data["data"]["attributes"]
                return {
                    "analysis_stats": attrs.get("last_analysis_stats"),
                    "meaningful_name": attrs.get("meaningful_name"),
                    "type_description": attrs.get("type_description"),
                    "md5": attrs.get("md5"),
                    "sha1": attrs.get("sha1"),
                    "sha256": attrs.get("sha256"),
                    "ssdeep": attrs.get("ssdeep"),
                    "magic": attrs.get("magic"),
                    "size": attrs.get("size"),
                    "creation_date": attrs.get("creation_date"),
                    "tags": attrs.get("tags"),
                    "trid": attrs.get("trid"),
                    "popular_threat_classification": attrs.get("popular_threat_classification"),
                    "sandbox_verdicts": attrs.get("sandbox_verdicts"),
                    "contacted_urls": attrs.get("contacted_urls"),
                    "contacted_domains": attrs.get("contacted_domains"),
                    "contacted_ips": attrs.get("contacted_ips"),
                    "crowdsourced_yara_results": attrs.get("crowdsourced_yara_results"),
                    "exiftool": attrs.get("exiftool"),
                    "names": attrs.get("names"),
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
        else:
            return {"error": f"VT query failed: {resp.status_code}"}
            
    except KeyError as e:
        return {"error": f"Missing expected field in VT response: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}

# ======================================
# ABUSEIPDB ENRICHMENT
# ======================================

def query_abuseipdb(ABUSEIPDB_KEY, ip_list, paid_key=False):
    """Query AbuseIPDB for IP reputation information."""
    if not ABUSEIPDB_KEY:
        return {ip: {"error": "ABUSEIPDB_KEY not configured"} for ip in ip_list}
    
    # Initialize the AbuseIPDB object once with API key
    try:
        abuse = AbuseIPDB(api_key=ABUSEIPDB_KEY)
    except Exception as e:
        return {ip: {"error": f"Failed to initialize AbuseIPDB: {str(e)}"} for ip in ip_list}
    
    results = {}

    for ip in ip_list:
        try:
            # Use check_ip_orig() to get full response with reports
            response = abuse.check_ip_orig(ip)
            
            # The response structure from the API
            data = response.get("data", {})

            results[ip] = {
                "ipAddress": data.get("ipAddress"),
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "countryCode": data.get("countryCode"),
                "domain": data.get("domain"),
                "isp": data.get("isp"),
                "usageType": data.get("usageType"),
                "totalReports": data.get("totalReports"),
                "numDistinctUsers": data.get("numDistinctUsers"),
                "lastReportedAt": data.get("lastReportedAt"),
                "isWhitelisted": data.get("isWhitelisted"),
                "reports": [
                    {
                        "reportedAt": r.get("reportedAt"),
                        "comment": r.get("comment"),
                        "categories": r.get("categories"),
                        "reporterCountryCode": r.get("reporterCountryCode")
                    }
                    for r in data.get("reports", [])
                ] if data.get("reports") else []
            }

        except Exception as e:
            results[ip] = {"error": str(e)}

        if not paid_key:
            time.sleep(2)  # Free-tier API rate-limit safety

    return results


# ======================================
# ABUSE.CH / MALWAREBAZAAR ENRICHMENT
# ======================================

# TODO: May want to have a loop search for other files with the found tags from a diffrent abusech query
def query_abusech(sha256_hash, auth_key: str = None, retries: int = 2, backoff: int = 2):
    """Query the Abuse.ch / MalwareBazaar API for a given SHA256 hash.

    Improvements:
    - Adds a `User-Agent` and `Accept` header (some services require a UA).
    - Returns `resp.text` on non-200 responses to surface server messages (helps debug 401).
    - Retries on transient network/server errors (5xx) with simple backoff.
    - Handles invalid-JSON responses gracefully.
    """
    payload = {"query": "get_info", "hash": sha256_hash}
    headers = {"User-Agent": "INFLEX-ThreatIntel/1.0", "Accept": "application/json"}

    # MalwareBazaar requires an Auth-Key header for most API actions
    if not auth_key:
        return {"error": "no_api_key", "message": "No Auth-Key provided. Obtain one at https://auth.abuse.ch/ and add it to threat_intelligence/keys.csv with service name MALWAREBAZAAR_KEY."}
    headers["Auth-Key"] = auth_key

    for attempt in range(retries + 1):
        try:
            resp = requests.post(ABUSECH_URL, data=payload, headers=headers, timeout=10)

            # Surface non-200 responses with the response text to help debugging
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    return {"error": "Invalid JSON response from Abuse.ch", "raw": resp.text}

                if "data" not in data or not data["data"]:
                    # Return any query_status or raw payload to help diagnose
                    return {
                        "error": data.get("query_status", "No data returned"),
                        "raw": data
                    }

                info = data["data"][0]

                return {
                    "sha256_hash": info.get("sha256_hash"),
                    "file_name": info.get("file_name"),
                    "file_type": info.get("file_type"),
                    "file_type_mime": info.get("file_type_mime"),
                    "file_size": info.get("file_size"),
                    "signature": info.get("signature"),
                    "first_seen": info.get("first_seen"),
                    "last_seen": info.get("last_seen"),
                    "tags": info.get("tags"),
                    "imphash": info.get("imphash"),
                    "ssdeep": info.get("ssdeep"),
                    "clamav": info.get("clamav"),
                    "delivery_method": info.get("delivery_method"),
                    "intelligence": info.get("intelligence"),
                    "vendor_intel": info.get("vendor_intel")
                }

            # If unauthorized, return full response text so the caller sees the message
            if resp.status_code == 401:
                return {"error": "Unauthorized (401)", "status_code": 401, "response": resp.text}

            # Retry on server errors (5xx)
            if 500 <= resp.status_code < 600 and attempt < retries:
                time.sleep(backoff * (attempt + 1))
                continue

            # For other non-200 codes return the code and raw text to assist debugging
            return {"error": f"Abuse.ch query failed: {resp.status_code}", "response": resp.text}

        except requests.RequestException as e:
            # Network errors — retry a few times before failing
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
                continue
            return {"error": str(e)}

    return {"error": "Max retries exceeded"}


# ======================================
# MALWAREBAZAAR / YARAIFY (FULL RULES)
# ======================================

def query_malwarebazaar_yaraify(MALWAREBAZAAR_KEY):
    if not MALWAREBAZAAR_KEY:
        return {"error": "MALWAREBAZAAR_KEY not configured"}
    
    try:
        b = Bazaar(api_key=MALWAREBAZAAR_KEY)
        y = Yaraify(api_key=MALWAREBAZAAR_KEY)
    except Exception as e:
        return {"error": f"Failed to initialize MalwareBazaar/Yaraify: {str(e)}"}

    results = {"recent_samples": [], "yara_rules": []}

    try:
        # ---- RECENT SAMPLES ----
        # Some versions of the `malwarebazaar` package expose a `recent()` helper;
        # if it's missing, fall back to a direct HTTP POST to the API endpoint.
        recent_data = None
        headers = {"Auth-Key": MALWAREBAZAAR_KEY, "User-Agent": "INFLEX-ThreatIntel/1.0", "Accept": "application/json"}

        if hasattr(b, "recent"):
            try:
                recent = b.recent()
                recent_data = recent.get("data", []) if isinstance(recent, dict) else recent
            except Exception:
                recent_data = None

        if recent_data is None:
            try:
                resp = requests.post(ABUSECH_URL, data={"query": "get_recent", "selector": 100}, headers=headers, timeout=15)
                if resp.status_code == 200:
                    j = resp.json()
                    recent_data = j.get("data", [])
                else:
                    results["error"] = f"MalwareBazaar recent query failed: {resp.status_code}"
                    recent_data = []
            except Exception as e:
                results["error"] = f"MalwareBazaar recent request error: {str(e)}"
                recent_data = []

        for s in recent_data:
            results["recent_samples"].append({
                "sha256": s.get("sha256_hash"),
                "file_name": s.get("file_name"),
                "signature": s.get("signature"),
                "first_seen": s.get("first_seen"),
                "tags": s.get("tags")
            })

        # ---- RECENT YARA RULES ----
        yara_resp = None
        if hasattr(y, "recent_yara"):
            try:
                yara_resp = y.recent_yara()
            except Exception:
                yara_resp = None

        # If the client doesn't provide a `recent_yara` endpoint, we can't
        # reliably emulate it here without the upstream API docs for Yaraify.
        if yara_resp is None:
            # Return empty yara_rules but include a helpful message.
            results.setdefault("warnings", []).append("Yaraify client does not expose recent_yara(); yara rules not fetched.")
            yara_data = []
        else:
            yara_data = yara_resp.get("data", [])

        for rule_data in yara_data:
            try:
                yara = YaraRule(**rule_data)
                
                rule_text = y.download_yara(yara.yarahub_uuid)

                # Convert bytes → text if necessary
                if isinstance(rule_text, bytes):
                    rule_text = rule_text.decode("utf-8", errors="replace")

                results["yara_rules"].append({
                    "rule_name": getattr(yara, "rule_name", None),
                    "description": getattr(yara, "description", None),
                    "tags": getattr(yara, "tags", None),
                    "author": getattr(yara, "author", None),
                    "yarahub_uuid": yara.yarahub_uuid,
                    "rule_text": rule_text
                })
            except Exception as e:
                # Continue processing other rules if one fails
                results["yara_rules"].append({"error": f"Failed to process rule: {str(e)}"})

    except Exception as e:
        results["error"] = str(e)

    return results


# ======================================
# GOOGLE SEARCH (HASH INTELLIGENCE)
# ======================================

def query_google_search(SERP_API_KEY, sha256_hash, pages=2, verify_content: bool = True, max_fetch: int = 10):
    """Search Google (via SerpApi) for pages/URLs that reference a hash.

    Behavior:
    - Queries SerpApi for the exact hash and `inurl:` matches to find candidate pages.
    - Collects candidate links from SerpApi results and (optionally) fetches each
      candidate to verify the hash appears either in the final URL or in the page
      HTML text. This reduces false positives and supplies links that actually
      contain the hash.

    Args:
        SERP_API_KEY: SerpApi API key.
        sha256_hash: The hash to search for.
        pages: Number of result pages to fetch (SerpApi returns 10 results per page).
        verify_content: If True, fetch candidate URLs and verify the hash exists in URL or page text.
        max_fetch: Max number of candidate URLs to fetch/verify to avoid too many external requests.
    """
    if not SERP_API_KEY:
        return [{"error": "SERP_API_KEY not configured"}]

    results = []
    base_url = "https://serpapi.com/search.json"
    headers = {"User-Agent": "INFLEX-ThreatIntel/1.0", "Accept": "application/json"}

    # Build a query that matches the exact hash or in the URL
    query_str = f'"{sha256_hash}" OR inurl:{sha256_hash}'

    candidates = []
    for start in range(0, pages * 10, 10):
        params = {"engine": "google", "q": query_str, "start": start, "api_key": SERP_API_KEY}
        try:
            resp = requests.get(base_url, params=params, headers=headers, timeout=15)

            if resp.status_code != 200:
                results.append({"error": f"Search API returned status {resp.status_code}", "response": resp.text})
                time.sleep(1)
                continue

            try:
                data = resp.json()
            except ValueError:
                results.append({"error": "Invalid JSON from search API", "raw": resp.text})
                time.sleep(1)
                continue

            # Collect from common result sections
            sections = []
            sections.extend(data.get("organic_results") or [])
            # Some SerpApi responses include `top_results` or `related_pages`
            if isinstance(data.get("top_results"), list):
                sections.extend(data.get("top_results"))
            if isinstance(data.get("related_pages"), list):
                sections.extend(data.get("related_pages"))

            if not sections:
                results.append({"warning": "No candidate results from SerpApi", "raw": data})

            for r in sections:
                link = r.get("link") or r.get("url") or r.get("displayed_link")
                title = r.get("title")
                snippet = r.get("snippet") or r.get("description")
                if link:
                    candidates.append({"link": link, "title": title, "snippet": snippet, "source_raw": r})

            time.sleep(1)
        except requests.RequestException as e:
            results.append({"error": str(e)})

    # Deduplicate candidates by link while preserving order
    seen = set()
    deduped = []
    for c in candidates:
        if c["link"] not in seen:
            seen.add(c["link"])
            deduped.append(c)

    # Optionally verify content by fetching each candidate (limited)
    verified = []
    fetch_count = 0
    for c in deduped:
        if verify_content and fetch_count < max_fetch:
            try:
                r = requests.get(c["link"], headers={"User-Agent": "INFLEX-ThreatIntel/1.0"}, timeout=10, allow_redirects=True)
                final_url = r.url
                text = r.text or ""
                contains = (sha256_hash in final_url) or (sha256_hash in text)
                fetch_count += 1
                if contains:
                    verified.append({"title": c.get("title"), "link": final_url, "snippet": c.get("snippet"), "verified_in": "url_or_page"})
                else:
                    # Not verified, but still record as candidate with note
                    results.append({"candidate_not_verified": c})
            except requests.RequestException as e:
                results.append({"fetch_error": str(e), "candidate": c})
        else:
            # If not verifying content (or exceeded max_fetch) include candidate as-is
            verified.append({"title": c.get("title"), "link": c.get("link"), "snippet": c.get("snippet"), "verified_in": "not_checked"})

    # If we have verified matches return them; otherwise include any candidates and debug info
    if verified:
        return verified
    if results:
        return results
    return [{"warning": "No results found"}]

# ======================================
# MAIN ENRICHMENT CONTROLLER
# ======================================

def enrich_threat_data(sample_data=None, sample_path=None):
    """
    Enrich threat intelligence data and return it.
    Does not modify files directly - returns enriched data for multiprocessing pipeline.
    
    Args:
        sample_data: The JSON data dictionary to enrich (should contain hashes, IPs, etc.)
    
    Returns:
        Dictionary with threat intelligence results, or None on error
    """
    print("DID WE EVEN MAKE IT IN")
    # Use provided data or defaults
    if sample_data is None:
        sample_data = {}
    
    api_keys = load_api_keys("threat_intelligence\\keys.csv")
    runtime_config = load_runtime_config()
    vt_paid_key = is_paid_key(runtime_config, "vt_paid_key")
    abuseipdb_paid_key = is_paid_key(runtime_config, "abuseipdb_paid_key")
    abusech_paid_key = is_paid_key(runtime_config, "abusech_paid_key")

    print("KEYS LOADED?", api_keys )
    print(f"[*] Paid API tiers - VT: {vt_paid_key}, AbuseIPDB: {abuseipdb_paid_key}, AbuseCH: {abusech_paid_key}")

    # Extract hashes and IPs from the provided data.
    # Build a deduplicated list: sha256 first, then md5/sha1 from static_analysis.
    # Use an ordered set pattern so VT is queried with sha256 once, then
    # falls back to md5/sha1 only if sha256 is missing.
    _seen_hashes = set()
    hashes = []
    ips = []

    file_path = "MITRE/mitre_store1.json"

    try:
        if not os.path.isfile(file_path):
            with open(file_path, "w") as f:
                pass
        print("Made it past MITRE file")
    except Exception as e:
        import traceback
        traceback.print_exc()

    def _add_hash(h):
        if h and isinstance(h, str) and h not in _seen_hashes:
            _seen_hashes.add(h)
            hashes.append(h)

    # Primary: sha256 from ingest_analysis (most authoritative)
    _add_hash(sample_data.get("ingest_analysis", {}).get("sha256"))

    print("HOW ABOUT HASHES:", hashes)

    # Secondary: hashes block from static_analysis (may include md5, sha1, imphash)
    static_hashes = sample_data.get("static_analysis", {}).get("hashes", {})
    if isinstance(static_hashes, dict):
        # Add sha256 first so it wins the VT query, then others
        _add_hash(static_hashes.get("sha256"))
        for _hval in static_hashes.values():
            _add_hash(_hval)
    
    # Try to extract IPs from strings
    if "static_analysis" in sample_data and "strings" in sample_data["static_analysis"]:
        if "interesting" in sample_data["static_analysis"]["strings"]:
            ips.extend(sample_data["static_analysis"]["strings"]["interesting"].get("ips", []))
    
    # Use defaults if nothing was extracted
    # if not hashes:
    #     hashes = [
    #         "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR test file
    #         "11b16ba733f2f4f10ac58021eecaf5668551a73e2a1acfae99745c50bfccbb44"
    #     ]
    # if not ips:
    #     ips = ["123.145.167.89"]

    # Where to look on the actual static analysis JSON structure
    # hashes = static_data["ingest_analysis"]["sha256"]
    # ips = static_data["static_analysis"]["strings"]["interesting"]["ips"]

    print("HASHES:", hashes)
    print("IPS:", ips)

    results = {
        "VirusTotal": {},
        "AbuseIPDB": {},
        "AbuseCH": {},
        # "MalwareBazaar_Yaraify": {},
        "GoogleSearch": {}
    }

    # May need to add in a timer to fall out if they are taking too long possibly like 30 sec? (Would need to use threading and timers for this)

    # === VIRUSTOTAL ===
    print("[*] Querying VirusTotal...")
    for sha in hashes:
        results["VirusTotal"][sha] = query_virustotal(api_keys["VT_API_KEY"], sha, detailed=True)  # Use simple format
        if not vt_paid_key:
            time.sleep(15)  # Free-tier VT rate-limit safety

    # === ABUSEIPDB ===
    print("[*] Querying AbuseIPDB...")
    results["AbuseIPDB"] = query_abuseipdb(
        api_keys["ABUSEIPDB_KEY"], ips, paid_key=abuseipdb_paid_key
    )

    # === ABUSE.CH ===
    print("[*] Querying Abuse.ch (MalwareBazaar)...")
    for sha in hashes:
        results["AbuseCH"][sha] = query_abusech(sha, auth_key=api_keys.get("MALWAREBAZAAR_KEY"))
        if not abusech_paid_key:
            time.sleep(3)  # Free-tier AbuseCH/MalwareBazaar rate-limit safety

    # NOT SURE IF WE EVEN WANT THIS ENRICHMENT AT ALL
    # # === MALWAREBAZAAR / YARAIFY ===
    # print("[*] Querying MalwareBazaar/Yaraify...")
    # results["MalwareBazaar_Yaraify"] = query_malwarebazaar_yaraify(api_keys["MALWAREBAZAAR_KEY"])

    # THIS ONLY HAS 250 CALLS PER MONTH FREE SO MAYBE DONT RUN IT ALL THE TIME
    # # === GOOGLE SEARCH ===
    # print("[*] Querying Google Search...")
    # for sha in hashes:
    #     results["GoogleSearch"][sha] = query_google_search(api_keys["SERP_API_KEY"], sha, pages=2)
    #     time.sleep(2)

    # === PREPARE THREAT DATA FOR MITRE/FINAL VERDICT ===
    # Extract threat scores from collected intelligence for final verdict
    vt_result = None
    abuse_result = 0.0
    
    # Get VirusTotal data by checking all hashes
    # Iterate through all hashes to find one with valid VT results

    print("VIRUSTOTAL RESULTS:", results["VirusTotal"])  # Debug print to see the VT results structure
    print("ABUSECH RESULTS:", results["AbuseCH"])  # Debug print to see the AbuseCH results structure

    for sha in hashes:
        if sha in results["VirusTotal"]:
            vt_data = results["VirusTotal"][sha]
            
            # Check for errors first
            if isinstance(vt_data, dict) and "error" in vt_data:
                print(f"[!] VirusTotal error for {sha[:16]}...: {vt_data['error']}")
                continue
            
            # Handle new VT API format with analysis_stats
            if isinstance(vt_data, dict) and "analysis_stats" in vt_data:
                stats = vt_data["analysis_stats"]
                malicious = stats.get("malicious", 0)
                # Total = main detection categories (exclude timeout, failure, type-unsupported)
                total = (stats.get("malicious", 0) + 
                        stats.get("suspicious", 0) + 
                        stats.get("undetected", 0) + 
                        stats.get("harmless", 0))
                
                if total > 0:
                    # Convert to format expected by final_verdict
                    vt_result = {"positives": malicious, "total": total}
                    print(f"[+] VirusTotal score for {sha[:16]}...: {malicious}/{total}")
                    break
            
            # Handle old VT API format (if it exists)
            elif isinstance(vt_data, dict) and "positives" in vt_data and "total" in vt_data:
                vt_result = vt_data
                print(f"[+] VirusTotal score for {sha[:16]}...: {vt_data['positives']}/{vt_data['total']}")
                break
    
    if not vt_result:
        print(f"[!] No valid VirusTotal results found for any hash - file likely not in VT database")
    
    # Aggregate AbuseIPDB and AbuseCH results for abuse_result score
    # If any IPs are flagged highly or hashes are known malware, increase abuse_result
    if results["AbuseIPDB"]:
        # If we have abuse scores from IPs, aggregate them
        abuse_scores = []
        for ip, ip_data in results["AbuseIPDB"].items():
            if isinstance(ip_data, dict) and "abuseConfidenceScore" in ip_data:
                # Normalize to 0-1 range (VirusTotal uses 0-100)
                abuse_scores.append(ip_data["abuseConfidenceScore"] / 100.0)
        if abuse_scores:
            abuse_result = min(sum(abuse_scores) / len(abuse_scores), 1.0)
            print(f"[+] AbuseIPDB average confidence: {abuse_result:.3f}")
    
    # Check AbuseCH for known malware hashes by checking all hashes
    abuse_ch_found = False
    for sha in hashes:
        if sha in results["AbuseCH"]:
            abuse_ch_data = results["AbuseCH"][sha]
            if isinstance(abuse_ch_data, dict):
                # If hash is found in abuse.ch (not hash_not_found), it's likely malware
                if "error" not in abuse_ch_data or abuse_ch_data.get("error") != "hash_not_found":
                    # Set abuse_result higher if known in abuse.ch
                    abuse_result = max(abuse_result, 0.5)
                    print(f"[+] Hash {sha[:16]}... found in Abuse.ch database")
                    abuse_ch_found = True
                    break  # Found known malware hash
    
    if not abuse_ch_found and hashes:
        print(f"[!] No hashes found in Abuse.ch database")

    # === MITRE ATT&CK ENRICHMENT ===
    # Run MITRE ATT&CK analysis with all collected threat intelligence
    print("[*] Querying MITRE ATT&CK with threat intelligence data...")
    try:
        mitre_results = run_mitre(
            sample=sample_path,
            vt_result=vt_result,
            abuse_result=abuse_result,
            osint_result=None  # OSINT not fully implemented yet
        )
        results["MITRE_ATTACK"] = mitre_results
    except RuntimeError as e:
        print(f"[!] MITRE ATT&CK analysis failed: {e}")
        print("[!] Skipping MITRE enrichment for this sample")
        results["MITRE_ATTACK"] = {"error": "MITRE analysis not supported for this file type"}

    print(f"[+] Threat intelligence enrichment complete")
    return results

# ======================================
# ENTRY POINT
# ======================================

if __name__ == "__main__":
    enrich_threat_data()
