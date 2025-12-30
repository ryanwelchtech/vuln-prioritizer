"""
FIRST EPSS API client for exploit probability scores.
"""
from typing import Optional, Dict, Any, List
import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential
from cachetools import TTLCache

from app.core.config import settings

logger = structlog.get_logger()

# Cache EPSS scores for 24 hours
epss_cache: TTLCache = TTLCache(maxsize=50000, ttl=86400)


class EPSSClient:
    """Client for FIRST EPSS (Exploit Prediction Scoring System) API."""

    def __init__(self):
        self.base_url = settings.EPSS_API_URL

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def get_epss_score(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get EPSS score for a single CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary with epss score and percentile
        """
        # Check cache first
        if cve_id in epss_cache:
            logger.debug("EPSS cache hit", cve_id=cve_id)
            return epss_cache[cve_id]

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.base_url,
                    params={"cve": cve_id},
                )
                response.raise_for_status()

                data = response.json()
                epss_data = data.get("data", [])

                if not epss_data:
                    logger.debug("No EPSS data for CVE", cve_id=cve_id)
                    return None

                result = {
                    "cve_id": cve_id,
                    "epss_score": float(epss_data[0].get("epss", 0)),
                    "percentile": float(epss_data[0].get("percentile", 0)),
                    "date": epss_data[0].get("date"),
                }

                epss_cache[cve_id] = result
                logger.info("EPSS score fetched", cve_id=cve_id, score=result["epss_score"])

                return result

        except Exception as e:
            logger.error("Failed to fetch EPSS score", cve_id=cve_id, error=str(e))
            return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def get_epss_scores_bulk(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Get EPSS scores for multiple CVEs.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE IDs to their EPSS data
        """
        # Check which CVEs are already cached
        results = {}
        uncached_cves = []

        for cve_id in cve_ids:
            if cve_id in epss_cache:
                results[cve_id] = epss_cache[cve_id]
            else:
                uncached_cves.append(cve_id)

        if not uncached_cves:
            return results

        # Fetch uncached CVEs in batches (API limit)
        batch_size = 100
        for i in range(0, len(uncached_cves), batch_size):
            batch = uncached_cves[i:i + batch_size]
            cve_param = ",".join(batch)

            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.get(
                        self.base_url,
                        params={"cve": cve_param},
                    )
                    response.raise_for_status()

                    data = response.json()

                    for item in data.get("data", []):
                        cve_id = item.get("cve")
                        epss_data = {
                            "cve_id": cve_id,
                            "epss_score": float(item.get("epss", 0)),
                            "percentile": float(item.get("percentile", 0)),
                            "date": item.get("date"),
                        }
                        epss_cache[cve_id] = epss_data
                        results[cve_id] = epss_data

            except Exception as e:
                logger.error("Bulk EPSS fetch failed", error=str(e), batch_start=i)

        logger.info("Bulk EPSS fetch complete", total=len(cve_ids), fetched=len(results))
        return results


epss_client = EPSSClient()
