"""
Fetches recent CVEs from the NVD API v2.0 for the RAG corpus.

Supports:
- Paginated fetching with rate limiting (respects NVD's no-key limit)
- Local JSON caching to data/cve_cache/
- Configurable date range
- Offline mode using cached data
"""

import json
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from backend.config import (
    NVD_API_BASE,
    NVD_RATE_LIMIT_DELAY,
    CVE_CACHE_DIR,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# NVD API v2.0 returns max 2000 results per page
NVD_PAGE_SIZE = 200  # Keep small to stay under rate limits


def _build_params(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    keyword: Optional[str] = None,
    start_index: int = 0,
) -> dict:
    """Build NVD API query parameters."""
    params = {
        "resultsPerPage": NVD_PAGE_SIZE,
        "startIndex": start_index,
    }

    if start_date:
        params["pubStartDate"] = start_date
    if end_date:
        params["pubEndDate"] = end_date
    if keyword:
        params["keywordSearch"] = keyword

    return params


def _parse_cve(vuln: dict) -> dict:
    """Extract relevant fields from a single NVD vulnerability entry."""
    cve_data = vuln.get("cve", {})
    cve_id = cve_data.get("id", "UNKNOWN")

    # Get English description
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Get CVSS metrics (try v3.1 first, then v3.0, then v2.0)
    metrics = cve_data.get("metrics", {})
    severity = "UNKNOWN"
    base_score = 0.0

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version, [])
        if metric_list:
            cvss = metric_list[0].get("cvssData", {})
            base_score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", metric_list[0].get("baseSeverity", "UNKNOWN"))
            break

    # Get references
    references = [
        ref.get("url", "")
        for ref in cve_data.get("references", [])[:5]  # Cap at 5 refs
    ]

    # Get weaknesses (CWE IDs)
    weaknesses = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value", ""))

    # Published / modified dates
    published = cve_data.get("published", "")
    last_modified = cve_data.get("lastModified", "")

    # Affected configurations (CPE matches)
    affected_products = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    # Extract product name from CPE string
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        version_start = match.get("versionStartIncluding", "")
                        version_end = match.get("versionEndIncluding", match.get("versionEndExcluding", ""))
                        affected_products.append({
                            "vendor": vendor,
                            "product": product,
                            "version_start": version_start,
                            "version_end": version_end,
                            "criteria": criteria,
                        })

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity.upper(),
        "base_score": base_score,
        "published": published,
        "last_modified": last_modified,
        "references": references,
        "weaknesses": weaknesses,
        "affected_products": affected_products[:10],  # Cap
    }


def fetch_cves(
    days_back: int = 30,
    keyword: Optional[str] = None,
    max_results: int = 1000,
) -> list[dict]:
    """
    Fetch recent CVEs from the NVD API.

    Args:
        days_back: How many days back to fetch from today.
        keyword: Optional keyword filter for the search.
        max_results: Maximum number of CVEs to fetch.

    Returns:
        List of parsed CVE dictionaries.
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    # NVD requires ISO 8601 format with timezone
    start_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
    end_str = end_date.strftime("%Y-%m-%dT23:59:59.999")

    all_cves = []
    start_index = 0

    logger.info(f"Fetching CVEs from {start_str} to {end_str} (max {max_results})")

    with httpx.Client(timeout=30.0) as client:
        while len(all_cves) < max_results:
            params = _build_params(start_str, end_str, keyword, start_index)

            try:
                logger.info(f"  Requesting page at index {start_index}...")
                response = client.get(NVD_API_BASE, params=params)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"  NVD API error: {e}")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            if not vulnerabilities:
                logger.info(f"  No more results. Total available: {total_results}")
                break

            for vuln in vulnerabilities:
                parsed = _parse_cve(vuln)
                all_cves.append(parsed)
                if len(all_cves) >= max_results:
                    break

            logger.info(f"  Fetched {len(all_cves)}/{min(total_results, max_results)} CVEs")

            start_index += NVD_PAGE_SIZE

            if start_index >= total_results:
                break

            # Rate limiting — NVD allows ~5 requests per 30s without API key
            logger.info(f"  Rate-limiting: waiting {NVD_RATE_LIMIT_DELAY}s...")
            time.sleep(NVD_RATE_LIMIT_DELAY)

    logger.info(f"Fetched {len(all_cves)} CVEs total")
    return all_cves


def save_to_cache(cves: list[dict], filename: Optional[str] = None) -> Path:
    """Save fetched CVEs to local JSON cache."""
    if filename is None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"cves_{timestamp}.json"

    cache_path = CVE_CACHE_DIR / filename
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)

    logger.info(f"Saved {len(cves)} CVEs to {cache_path}")
    return cache_path


def load_from_cache(filename: Optional[str] = None) -> list[dict]:
    """
    Load CVEs from local cache.

    If no filename given, loads the most recent cache file.
    """
    if filename:
        cache_path = CVE_CACHE_DIR / filename
    else:
        # Find most recent cache file
        cache_files = sorted(CVE_CACHE_DIR.glob("cves_*.json"), reverse=True)
        if not cache_files:
            logger.warning("No cached CVE data found")
            return []
        cache_path = cache_files[0]

    with open(cache_path, "r", encoding="utf-8") as f:
        cves = json.load(f)

    logger.info(f"Loaded {len(cves)} CVEs from {cache_path}")
    return cves


def load_all_cached() -> list[dict]:
    """Load and merge all cached CVE files, deduplicating by CVE ID."""
    all_cves = {}
    cache_files = sorted(CVE_CACHE_DIR.glob("cves_*.json"))

    for cache_path in cache_files:
        with open(cache_path, "r", encoding="utf-8") as f:
            cves = json.load(f)
            for cve in cves:
                all_cves[cve["cve_id"]] = cve  # Later files overwrite older entries

    logger.info(f"Loaded {len(all_cves)} unique CVEs from {len(cache_files)} cache files")
    return list(all_cves.values())


# ── CLI Entry Point ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fetch CVEs from NVD API")
    parser.add_argument("--days", type=int, default=30, help="Days back to fetch (default: 30)")
    parser.add_argument("--keyword", type=str, default=None, help="Keyword filter")
    parser.add_argument("--max", type=int, default=500, help="Max results (default: 500)")
    parser.add_argument("--output", type=str, default=None, help="Output filename")
    args = parser.parse_args()

    cves = fetch_cves(days_back=args.days, keyword=args.keyword, max_results=args.max)

    if cves:
        save_to_cache(cves, filename=args.output)
        print(f"\nSample CVE: {cves[0]['cve_id']} — {cves[0]['severity']} ({cves[0]['base_score']})")
        print(f"  {cves[0]['description'][:120]}...")
    else:
        print("No CVEs fetched. Check network connection or try different parameters.")
