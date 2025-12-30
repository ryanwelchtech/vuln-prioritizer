"""
NIST NVD API client for fetching CVE data.
"""
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime
import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential
from cachetools import TTLCache

from app.core.config import settings

logger = structlog.get_logger()

# Cache CVE data for 24 hours
cve_cache: TTLCache = TTLCache(maxsize=10000, ttl=settings.CVE_CACHE_TTL)


class NVDClient:
    """Client for NIST National Vulnerability Database API."""

    def __init__(self):
        self.base_url = settings.NVD_API_URL
        self.api_key = settings.NVD_API_KEY
        self.headers = {}
        if self.api_key:
            self.headers["apiKey"] = self.api_key

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE details from NVD API.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            CVE data dictionary or None if not found
        """
        # Check cache first
        if cve_id in cve_cache:
            logger.debug("CVE cache hit", cve_id=cve_id)
            return cve_cache[cve_id]

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.base_url,
                    params={"cveId": cve_id},
                    headers=self.headers,
                )
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    logger.warning("CVE not found in NVD", cve_id=cve_id)
                    return None

                cve_data = self._parse_cve_response(vulnerabilities[0])
                cve_cache[cve_id] = cve_data

                logger.info("CVE fetched from NVD", cve_id=cve_id)
                return cve_data

        except httpx.HTTPStatusError as e:
            logger.error("NVD API error", cve_id=cve_id, status=e.response.status_code)
            raise
        except Exception as e:
            logger.error("Failed to fetch CVE", cve_id=cve_id, error=str(e))
            raise

    def _parse_cve_response(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NVD API response into standardized format."""
        cve = vuln_data.get("cve", {})

        # Extract CVSS v3 metrics
        cvss_v3 = None
        cvss_v3_vector = None
        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_v3 = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_v3 = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")

        # Extract CVSS v2
        cvss_v2 = None
        if "cvssMetricV2" in metrics:
            cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")

        # Extract CWE IDs
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        # Extract references
        references = [
            ref.get("url") for ref in cve.get("references", [])
            if ref.get("url")
        ]

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else None
        )

        return {
            "cve_id": cve.get("id"),
            "description": description,
            "published_date": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "cvss_v3_score": cvss_v3,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v2_score": cvss_v2,
            "cwe_ids": cwe_ids,
            "references": references[:10],  # Limit references
        }

    async def search_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        results_per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs with various filters.

        Returns:
            List of CVE data dictionaries
        """
        params = {"resultsPerPage": results_per_page}

        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.isoformat()
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.isoformat()

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers=self.headers,
                )
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                return [
                    self._parse_cve_response(vuln)
                    for vuln in vulnerabilities
                ]

        except Exception as e:
            logger.error("CVE search failed", error=str(e))
            raise


nvd_client = NVDClient()
