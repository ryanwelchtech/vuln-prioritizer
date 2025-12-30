"""
CISA KEV (Known Exploited Vulnerabilities) feed client.
"""
from typing import Optional, Dict, Set
from datetime import datetime
import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings

logger = structlog.get_logger()

# In-memory KEV catalog
kev_catalog: Dict[str, Dict] = {}
kev_cve_set: Set[str] = set()
kev_last_updated: Optional[datetime] = None


class KEVClient:
    """Client for CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self):
        self.feed_url = settings.KEV_FEED_URL

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def refresh_catalog(self) -> int:
        """
        Refresh the KEV catalog from CISA feed.

        Returns:
            Number of CVEs in the catalog
        """
        global kev_catalog, kev_cve_set, kev_last_updated

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(self.feed_url)
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                kev_catalog.clear()
                kev_cve_set.clear()

                for vuln in vulnerabilities:
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        kev_catalog[cve_id] = {
                            "cve_id": cve_id,
                            "vendor": vuln.get("vendorProject"),
                            "product": vuln.get("product"),
                            "vulnerability_name": vuln.get("vulnerabilityName"),
                            "date_added": vuln.get("dateAdded"),
                            "due_date": vuln.get("dueDate"),
                            "short_description": vuln.get("shortDescription"),
                            "required_action": vuln.get("requiredAction"),
                            "known_ransomware_use": vuln.get("knownRansomwareCampaignUse") == "Known",
                        }
                        kev_cve_set.add(cve_id)

                kev_last_updated = datetime.utcnow()

                logger.info("KEV catalog refreshed", count=len(kev_catalog))
                return len(kev_catalog)

        except Exception as e:
            logger.error("Failed to refresh KEV catalog", error=str(e))
            raise

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        return cve_id in kev_cve_set

    def get_kev_details(self, cve_id: str) -> Optional[Dict]:
        """Get KEV details for a CVE."""
        return kev_catalog.get(cve_id)

    def get_catalog_stats(self) -> Dict:
        """Get statistics about the KEV catalog."""
        ransomware_count = sum(
            1 for v in kev_catalog.values() if v.get("known_ransomware_use")
        )

        return {
            "total_cves": len(kev_catalog),
            "ransomware_related": ransomware_count,
            "last_updated": kev_last_updated.isoformat() if kev_last_updated else None,
        }


kev_client = KEVClient()
