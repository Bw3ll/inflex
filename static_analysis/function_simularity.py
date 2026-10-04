import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict


#  Shared helpers 

def load_report(json_path: Path) -> dict | None:
    """
    Load and validate a single report JSON from disk.

    Returns the parsed dict, or None if the file cannot be parsed or is missing
    the required disassembly.functions key.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  [!] Could not load {json_path.name}: {e}")
        return None

    if "disassembly" not in data or "functions" not in data["disassembly"]:
        print(f"  [!] Skipping {json_path.name}: no disassembly.functions key")
        return None

    return data


def extract_binary_id(data: dict, json_path: Path) -> str:
    """
    Return a human-readable identifier for the binary.
    Prefers sha256 from ingest_analysis, falls back to the JSON filename stem.
    """
    sha = (
        data.get("ingest_analysis", {}).get("sha256")
        or data.get("static_analysis", {}).get("hashes", {}).get("sha256")
    )
    filename = data.get("ingest_analysis", {}).get("filename") or json_path.stem
    if sha:
        return f"{filename} [{sha[:12]}]"
    return filename


def _extract_binary_id_from_report(report: dict) -> str:
    """
    Extract a binary_id string from an in-memory report dict
    (no json_path available, so we fall back to sha256 or filename only).
    """
    ia = report.get("ingest_analysis", {})
    sha = ia.get("sha256") or report.get("static_analysis", {}).get("hashes", {}).get("sha256")
    filename = ia.get("filename") or "unknown"
    if sha:
        return f"{filename} [{sha[:12]}]"
    return filename


def build_hash_index(reports: list[dict]) -> dict[str, list[dict]]:
    """
    Build an inverted index:  func_hash → [{ binary_id, name, offset, size }, ...]

    Allows O(1) lookup of every binary that contains a given function hash.

    Args:
        reports: List of report dicts, each with 'binary_id' and 'functions' keys.

    Returns:
        defaultdict mapping func_hash → list of occurrence dicts.
    """
    index = defaultdict(list)
    for report in reports:
        binary_id = report["binary_id"]
        for func in report["functions"]:
            h = func.get("func_hash")
            if not h:
                continue
            index[h].append({
                "binary_id": binary_id,
                "name":      func.get("name", "unknown"),
                "offset":    func.get("offset", "?"),
                "size":      func.get("size", 0),
            })
    return index


def find_overlaps(hash_index: dict[str, list[dict]]) -> dict[tuple, list[dict]]:
    """
    Identify all (binary_A, binary_B) pairs that share at least one function hash.

    Args:
        hash_index: Inverted index from build_hash_index().

    Returns:
        dict mapping sorted (binary_id_A, binary_id_B) tuple →
        list of shared function dicts:
            { func_hash, name_in_A, offset_in_A, name_in_B, offset_in_B, size }
    """
    overlaps = defaultdict(list)

    for func_hash, occurrences in hash_index.items():
        if len(occurrences) < 2:
            continue

        seen_pairs = set()
        for i in range(len(occurrences)):
            for j in range(i + 1, len(occurrences)):
                a = occurrences[i]
                b = occurrences[j]

                if a["binary_id"] == b["binary_id"]:
                    continue

                pair = tuple(sorted([a["binary_id"], b["binary_id"]]))
                dedupe_key = (pair, func_hash)
                if dedupe_key in seen_pairs:
                    continue
                seen_pairs.add(dedupe_key)

                first, second = (a, b) if pair[0] == a["binary_id"] else (b, a)

                overlaps[pair].append({
                    "func_hash":   func_hash,
                    "name_in_A":   first["name"],
                    "offset_in_A": first["offset"],
                    "name_in_B":   second["name"],
                    "offset_in_B": second["offset"],
                    "size":        first["size"],
                })

    return overlaps


def compute_similarity_score(shared: int, total_a: int, total_b: int) -> float:
    """
    Jaccard-style similarity: shared / union.  Returns a value in [0.0, 1.0].

    Note: this score is sensitive to size difference between binaries. A large
    binary sharing 74 functions with a small binary will score low even if that
    represents 18% of the smaller binary's functions. Use
    overlap_pct_of_smaller alongside this for a clearer picture.
    """
    union = total_a + total_b - shared
    return 0.0 if union == 0 else shared / union


def compute_overlap_pct_of_smaller(shared: int, total_a: int, total_b: int) -> float:
    """
    Overlap as a percentage of the smaller binary's function count.

    More intuitive than Jaccard when comparing binaries of very different sizes.
    e.g. 74 shared / 400 functions = 18.5%, which is far more meaningful than
    the Jaccard score when the other binary has 1635 functions.

    Returns a value in [0.0, 1.0].
    """
    smaller = min(total_a, total_b)
    return 0.0 if smaller == 0 else shared / smaller


#  Shared-functions report writer 

def write_shared_functions_report(
    new_id: str,
    matches: list[dict],
    output_path: str | Path,
) -> None:
    from datetime import datetime, timezone
    from collections import Counter

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build per-match records and collect all shared hashes for cross-match summary
    hash_appearance_count = Counter()
    match_records = []

    for m in matches:
        shared_funcs = m.get("shared_functions", [])
        hashes = [sf["func_hash"] for sf in shared_funcs]

        for h in hashes:
            hash_appearance_count[h] += 1

        match_records.append({
            "binary_id":               m["binary_id"],
            "shared_count":            m["shared_count"],
            "total_in_source":         m.get("total_in_new", 0),
            "total_in_match":          m.get("total_in_match", 0),
            "similarity_jaccard":      m.get("similarity_score", 0.0),
            "overlap_pct_of_smaller":  m.get("overlap_pct_of_smaller", 0.0),
            "shared_hashes":           hashes,
            "shared_functions":        shared_funcs,
        })

    # Cross-match summary: group hashes by how many matched binaries they appear in
    by_count: dict[int, list[str]] = {}
    for h, count in hash_appearance_count.items():
        by_count.setdefault(count, []).append(h)

    # Sort each bucket by hash string for deterministic output
    for bucket in by_count.values():
        bucket.sort()

    all_match_count = len(matches)
    hashes_in_all = by_count.get(all_match_count, []) if all_match_count > 1 else []

    report = {
        "source_binary":  new_id,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "match_count":    len(matches),
        "matches":        match_records,
        "cross_match_summary": {
            "hashes_shared_by_all_matches": hashes_in_all,
            "hashes_shared_by_N_matches":   {str(k): v for k, v in sorted(by_count.items(), reverse=True)},
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Shared-functions report written to: {output_path}")
    if hashes_in_all:
        print(f"    {len(hashes_in_all)} hash(es) shared across ALL {all_match_count} matched binaries (cluster fingerprint candidates)")


#  Single-report API (called from disassembly.py) 

def compare_single_report(
    new_report: dict,
    reports_dir: str | Path,
    min_overlap: int = 1,
    shared_functions_report_dir: str | Path | None = None,
) -> list[dict]:
    reports_dir = Path(reports_dir)

    new_id = _extract_binary_id_from_report(new_report)
    new_funcs = [
        f for f in new_report.get("disassembly", {}).get("functions", [])
        if f.get("func_hash")
    ]

    if not new_funcs:
        print(f"  [!] compare_single_report: new report has no hashed functions, skipping.")
        return []

    # Build hash → func lookup for the new binary
    new_index = defaultdict(list)
    for func in new_funcs:
        new_index[func["func_hash"]].append(func)

    json_files = sorted(reports_dir.glob("*.json")) if reports_dir.is_dir() else []
    matches = []
    seen_shas: set[str] = set()   # deduplicate: sha256.json and sha256_normalized.json contain the same data

    for jp in json_files:
        # Skip normalised duplicates — they contain identical disassembly data
        # to the raw report and would produce duplicate matches for every binary.
        if jp.name.endswith("_normalized.json"):
            continue

        existing = load_report(jp)
        if existing is None:
            continue

        # Secondary deduplication by sha256 in case the glob ever picks up
        # other copies (e.g. backups) of the same binary.
        existing_sha = (
            existing.get("ingest_analysis", {}).get("sha256")
            or existing.get("static_analysis", {}).get("hashes", {}).get("sha256")
            or ""
        )
        if existing_sha and existing_sha in seen_shas:
            continue
        if existing_sha:
            seen_shas.add(existing_sha)

        existing_id = extract_binary_id(existing, jp)

        # Never compare the binary against itself
        new_sha = (
            new_report.get("ingest_analysis", {}).get("sha256")
            or new_report.get("static_analysis", {}).get("hashes", {}).get("sha256")
            or ""
        )

        existing_sha = (
            existing.get("ingest_analysis", {}).get("sha256")
            or existing.get("static_analysis", {}).get("hashes", {}).get("sha256")
            or ""
        )

        # Skip self by sha256 (strongest check)
        if new_sha and existing_sha and existing_sha == new_sha:
            continue

        existing_funcs = [
            f for f in existing["disassembly"]["functions"]
            if f.get("func_hash")
        ]
        if not existing_funcs:
            continue

        # Find shared hashes
        shared_funcs = []
        seen_hashes = set()
        for func in existing_funcs:
            h = func.get("func_hash")
            if not h or h not in new_index or h in seen_hashes:
                continue
            seen_hashes.add(h)
            new_func = new_index[h][0]
            shared_funcs.append({
                "func_hash":       h,
                "name_in_new":     new_func.get("name", "unknown"),
                "offset_in_new":   new_func.get("offset", "?"),
                "name_in_match":   func.get("name", "unknown"),
                "offset_in_match": func.get("offset", "?"),
                "size":            new_func.get("size", 0),
            })

        if len(shared_funcs) < min_overlap:
            continue

        shared_count = len(shared_funcs)
        total_new    = len(new_funcs)
        total_match  = len(existing_funcs)
        score        = compute_similarity_score(shared_count, total_new, total_match)
        pct_smaller  = compute_overlap_pct_of_smaller(shared_count, total_new, total_match)

        matches.append({
            "binary_id":               existing_id,
            "shared_count":            shared_count,
            "total_in_new":            total_new,
            "total_in_match":          total_match,
            "similarity_score":        round(score, 6),
            "overlap_pct_of_smaller":  round(pct_smaller, 6),
            "shared_functions":        sorted(shared_funcs, key=lambda x: x["size"], reverse=True),
        })

    matches.sort(key=lambda x: x["similarity_score"], reverse=True)

    if matches:
        print(f"[+] Similarity check: {len(matches)} match(es) found for {new_id}")
        for m in matches:
            print(
                f"    → {m['binary_id']}  |  shared: {m['shared_count']}  "
                f"|  jaccard: {m['similarity_score']:.1%}  "
                f"|  pct_of_smaller: {m['overlap_pct_of_smaller']:.1%}"
            )

        # Write shared-functions report if a directory was provided
        if shared_functions_report_dir is not None:
            sha = (
                new_report.get("ingest_analysis", {}).get("sha256")
                or new_report.get("static_analysis", {}).get("hashes", {}).get("sha256")
                or "unknown"
            )
            report_filename = f"{sha}_shared_functions.json"
            report_path = Path(shared_functions_report_dir) / report_filename
            write_shared_functions_report(new_id, matches, report_path)
    else:
        print(f"[+] Similarity check: no matches found for {new_id}")

    return matches


def update_similarity_across_reports_folder(
    reports_dir: str | Path,
    min_overlap: int = 1,
    overwrite: bool = True,
) -> None:
    reports_dir = Path(reports_dir)

    if not reports_dir.is_dir():
        print(f"[-] Not a directory: {reports_dir}")
        return

    json_files = sorted(reports_dir.glob("*.json"))
    if not json_files:
        print(f"[-] No JSON files found in: {reports_dir}")
        return

    # Load all reports (NORMALIZED ONLY)
    reports_by_sha = {}
    report_paths_by_sha = {}
    func_counts = {}
    funcs_by_sha = {}

    print("[*] Loading NORMALIZED reports for post-processing...")

    for jp in json_files:
        # Only process normalized reports
        if not jp.name.endswith("_normalized.json"):
            continue

        data = load_report(jp)
        if data is None:
            continue

        sha = (
            data.get("ingest_analysis", {}).get("sha256")
            or data.get("static_analysis", {}).get("hashes", {}).get("sha256")
        )

        if not sha:
            print(f"  [!] Skipping {jp.name}: missing sha256")
            continue

        hashed_funcs = [
            f for f in data.get("disassembly", {}).get("functions", [])
            if f.get("func_hash")
        ]

        reports_by_sha[sha] = data
        report_paths_by_sha[sha] = jp
        func_counts[sha] = len(hashed_funcs)
        funcs_by_sha[sha] = hashed_funcs

        bid = extract_binary_id(data, jp)
        print(f"  [+] Loaded {bid} ({len(hashed_funcs)} hashed functions)")

    shas = sorted(reports_by_sha.keys())
    if len(shas) < 2:
        print("[-] Need at least 2 normalized reports to compute similarity.")
        return

    # Build inverted index: func_hash -> list of (sha, func metadata)
    print("[*] Building global hash index...")
    hash_index = defaultdict(list)

    for sha in shas:
        for func in funcs_by_sha[sha]:
            h = func.get("func_hash")
            if not h:
                continue

            hash_index[h].append({
                "sha": sha,
                "name": func.get("name", "unknown"),
                "offset": func.get("offset", "?"),
                "size": func.get("size", 0),
            })

    print(f"[+] Indexed {len(hash_index)} unique function hashes.")

    # Prepare similarity records per SHA-pair
    similarity_map = defaultdict(list)

    print("[*] Computing overlaps across all normalized binaries...")

    for func_hash, occurrences in hash_index.items():
        if len(occurrences) < 2:
            continue

        # for every pair that shares this hash
        for i in range(len(occurrences)):
            for j in range(i + 1, len(occurrences)):
                a = occurrences[i]
                b = occurrences[j]

                sha_a = a["sha"]
                sha_b = b["sha"]

                if sha_a == sha_b:
                    continue

                # store shared function record in both directions
                similarity_map[(sha_a, sha_b)].append({
                    "func_hash":       func_hash,
                    "name_in_new":     a["name"],
                    "offset_in_new":   a["offset"],
                    "name_in_match":   b["name"],
                    "offset_in_match": b["offset"],
                    "size":            a["size"],
                })

                similarity_map[(sha_b, sha_a)].append({
                    "func_hash":       func_hash,
                    "name_in_new":     b["name"],
                    "offset_in_new":   b["offset"],
                    "name_in_match":   a["name"],
                    "offset_in_match": a["offset"],
                    "size":            b["size"],
                })

    # Build final match lists for each SHA
    print("[*] Building per-report similarity lists...")

    per_report_matches = defaultdict(list)

    for (sha_a, sha_b), shared_funcs in similarity_map.items():
        # Deduplicate hashes per pair
        seen = set()
        unique_shared = []
        for sf in shared_funcs:
            if sf["func_hash"] in seen:
                continue
            seen.add(sf["func_hash"])
            unique_shared.append(sf)

        if len(unique_shared) < min_overlap:
            continue

        total_a = func_counts.get(sha_a, 0)
        total_b = func_counts.get(sha_b, 0)
        shared_count = len(unique_shared)

        score = compute_similarity_score(shared_count, total_a, total_b)
        pct_smaller = compute_overlap_pct_of_smaller(shared_count, total_a, total_b)

        report_b = reports_by_sha[sha_b]
        binary_id_b = extract_binary_id(report_b, report_paths_by_sha[sha_b])

        per_report_matches[sha_a].append({
            "binary_id":               binary_id_b,
            "shared_count":            shared_count,
            "total_in_new":            total_a,
            "total_in_match":          total_b,
            "similarity_score":        round(score, 6),
            "overlap_pct_of_smaller":  round(pct_smaller, 6),
            "shared_functions":        sorted(unique_shared, key=lambda x: x["size"], reverse=True),
        })

    # Write back into normalized JSON files
    print("[*] Writing similarity results back into NORMALIZED reports...")

    updated = 0

    for sha in shas:
        report = reports_by_sha[sha]
        jp = report_paths_by_sha[sha]

        matches = per_report_matches.get(sha, [])
        matches.sort(key=lambda x: x["similarity_score"], reverse=True)

        if "disassembly" not in report:
            report["disassembly"] = {}

        if overwrite or "similar_binaries" not in report["disassembly"]:
            report["disassembly"]["similar_binaries"] = matches
        else:
            # merge mode (dedupe by binary_id)
            existing = report["disassembly"].get("similar_binaries", [])
            existing_ids = {m.get("binary_id") for m in existing if m.get("binary_id")}
            for m in matches:
                if m["binary_id"] not in existing_ids:
                    existing.append(m)
            report["disassembly"]["similar_binaries"] = existing

        with open(jp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        updated += 1

    print(f"[+] Similarity post-processing complete. Updated {updated} normalized report(s).")


#  Full-folder scan (standalone mode) 

def run(reports_dir: str, min_overlap: int, output_path: str | None):
    """
    Scan an entire directory of report JSONs and print all overlapping pairs.
    Called when similarity_check.py is run directly from the command line.
    """
    reports_dir = Path(reports_dir)

    if not reports_dir.is_dir():
        print(f"[-] Not a directory: {reports_dir}")
        sys.exit(1)

    json_files = sorted(reports_dir.glob("*.json"))
    if not json_files:
        print(f"[-] No JSON files found in {reports_dir}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Binary Similarity Check")
    print(f"{'='*60}")
    print(f"[+] Reports directory : {reports_dir}")
    print(f"[+] JSON files found  : {len(json_files)}")
    print(f"[+] Min shared funcs  : {min_overlap}")
    print()

    print("[*] Loading reports...")
    reports = []
    func_counts = {}

    for jp in json_files:
        data = load_report(jp)
        if data is None:
            continue

        binary_id = extract_binary_id(data, jp)
        hashed_funcs = [f for f in data["disassembly"]["functions"] if f.get("func_hash")]

        reports.append({
            "binary_id": binary_id,
            "functions": hashed_funcs,
            "json_path": str(jp),
        })
        func_counts[binary_id] = len(hashed_funcs)
        print(f"  [+] {binary_id}  ({len(hashed_funcs)} hashed functions)")

    if len(reports) < 2:
        print("\n[-] Need at least 2 valid reports to compare. Exiting.")
        sys.exit(1)

    print(f"\n[+] Loaded {len(reports)} reports successfully.")

    print("[*] Building function hash index...")
    hash_index = build_hash_index(reports)
    print(f"[+] Indexed {len(hash_index)} unique function hashes.")

    print("[*] Comparing binaries...")
    all_overlaps = find_overlaps(hash_index)

    filtered = {
        pair: shared
        for pair, shared in all_overlaps.items()
        if len(shared) >= min_overlap
    }

    sorted_pairs = sorted(filtered.items(), key=lambda x: len(x[1]), reverse=True)

    print(f"\n{'='*60}")
    print(f"  Results: {len(sorted_pairs)} overlapping pair(s) found")
    print(f"{'='*60}\n")

    output_records = []

    if not sorted_pairs:
        print("  No overlapping functions found between any binary pair.")
    else:
        for (binary_a, binary_b), shared_funcs in sorted_pairs:
            total_a = func_counts.get(binary_a, 0)
            total_b = func_counts.get(binary_b, 0)
            shared_count = len(shared_funcs)
            score = compute_similarity_score(shared_count, total_a, total_b)

            print(f"  ┌ Pair ")
            print(f"  │  A : {binary_a}")
            print(f"  │  B : {binary_b}")
            print(f"  │  Shared functions : {shared_count}")
            print(f"  │  Total in A       : {total_a}")
            print(f"  │  Total in B       : {total_b}")
            print(f"  │  Similarity score : {score:.1%}  (Jaccard)")
            print(f"  │")
            print(f"  │  Shared function details:")

            for sf in sorted(shared_funcs, key=lambda x: x["size"], reverse=True):
                print(f"  │    hash    : {sf['func_hash'][:16]}...")
                print(f"  │    in A    : {sf['name_in_A']} @ {sf['offset_in_A']}  (size {sf['size']})")
                print(f"  │    in B    : {sf['name_in_B']} @ {sf['offset_in_B']}")
                print(f"  │    ·")

            print(f"  └\n")

            output_records.append({
                "binary_a":         binary_a,
                "binary_b":         binary_b,
                "shared_count":     shared_count,
                "total_in_a":       total_a,
                "total_in_b":       total_b,
                "similarity_score": round(score, 6),
                "shared_functions": shared_funcs,
            })

    if output_path:
        out = Path(output_path)
        with open(out, "w", encoding="utf-8") as f:
            json.dump({
                "reports_directory": str(reports_dir),
                "reports_scanned":   len(reports),
                "min_overlap":       min_overlap,
                "pairs_found":       len(output_records),
                "results":           output_records,
            }, f, indent=2)
        print(f"[+] Full results written to: {out}")

    print(f"[+] Done.")


#  Entry point 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compare binary analysis JSON reports by normalised function hashes."
    )
    parser.add_argument(
        "reports_dir",
        help="Directory containing the binary analysis JSON reports"
    )
    parser.add_argument(
        "--min-overlap",
        type=int,
        default=1,
        metavar="N",
        help="Minimum number of shared functions to report a pair (default: 1)"
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Optional path to write full results as JSON"
    )

    args = parser.parse_args()
    run(args.reports_dir, args.min_overlap, args.output)
