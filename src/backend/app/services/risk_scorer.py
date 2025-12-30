"""
Risk scoring engine for vulnerability prioritization.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
import structlog

from app.models.vulnerability import Vulnerability
from app.services.nvd_client import nvd_client
from app.services.epss_client import epss_client
from app.services.kev_client import kev_client

logger = structlog.get_logger()


class RiskScorer:
    """
    Risk-based vulnerability scoring engine.

    Combines multiple data sources to calculate a unified risk score:
    - CVSS base score (severity)
    - EPSS score (exploit probability)
    - CISA KEV (known exploitation)
    - Asset context (criticality, reachability)
    """

    # Weight factors
    CVSS_WEIGHT = 0.3
    EPSS_WEIGHT = 0.35
    KEV_WEIGHT = 0.25
    CONTEXT_WEIGHT = 0.1

    # KEV multiplier
    KEV_MULTIPLIER = 2.0

    # Severity thresholds
    CRITICAL_THRESHOLD = 70
    HIGH_THRESHOLD = 40
    MEDIUM_THRESHOLD = 20

    async def enrich_vulnerability(self, cve_id: str) -> Dict[str, Any]:
        """
        Enrich a CVE with data from all sources.

        Args:
            cve_id: CVE identifier

        Returns:
            Enriched vulnerability data
        """
        result = {
            "cve_id": cve_id,
            "enriched_at": datetime.utcnow().isoformat(),
        }

        # Fetch NVD data
        nvd_data = await nvd_client.get_cve(cve_id)
        if nvd_data:
            result.update({
                "description": nvd_data.get("description"),
                "published_date": nvd_data.get("published_date"),
                "cvss_v3_score": nvd_data.get("cvss_v3_score"),
                "cvss_v3_vector": nvd_data.get("cvss_v3_vector"),
                "cvss_v2_score": nvd_data.get("cvss_v2_score"),
                "cwe_ids": nvd_data.get("cwe_ids", []),
                "references": nvd_data.get("references", []),
            })

        # Fetch EPSS data
        epss_data = await epss_client.get_epss_score(cve_id)
        if epss_data:
            result.update({
                "epss_score": epss_data.get("epss_score"),
                "epss_percentile": epss_data.get("percentile"),
            })

        # Check KEV
        result["in_kev"] = kev_client.is_in_kev(cve_id)
        if result["in_kev"]:
            kev_details = kev_client.get_kev_details(cve_id)
            if kev_details:
                result["kev_details"] = kev_details

        logger.info("Vulnerability enriched", cve_id=cve_id, in_kev=result["in_kev"])
        return result

    def calculate_risk_score(
        self,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        in_kev: bool = False,
        asset_criticality: float = 1.0,
        network_reachability: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Calculate unified risk score.

        Args:
            cvss_score: CVSS v3 base score (0-10)
            epss_score: EPSS probability (0-1)
            in_kev: Whether CVE is in CISA KEV
            asset_criticality: Asset importance (0.5-1.5)
            network_reachability: Network exposure (0.5-1.5)

        Returns:
            Risk score details
        """
        # Normalize inputs
        cvss_normalized = (cvss_score or 5.0) / 10.0
        epss_normalized = epss_score or 0.1
        context_factor = (asset_criticality + network_reachability) / 2

        # Calculate component scores
        cvss_component = cvss_normalized * self.CVSS_WEIGHT * 100
        epss_component = epss_normalized * self.EPSS_WEIGHT * 100

        # KEV bonus
        kev_component = 0
        if in_kev:
            kev_component = self.KEV_WEIGHT * 100

        # Context adjustment
        context_component = context_factor * self.CONTEXT_WEIGHT * 100

        # Total score
        raw_score = cvss_component + epss_component + kev_component + context_component

        # Apply KEV multiplier for urgency
        if in_kev:
            raw_score = min(raw_score * 1.5, 100)

        # Determine severity
        if raw_score >= self.CRITICAL_THRESHOLD:
            severity = "critical"
        elif raw_score >= self.HIGH_THRESHOLD:
            severity = "high"
        elif raw_score >= self.MEDIUM_THRESHOLD:
            severity = "medium"
        else:
            severity = "low"

        return {
            "risk_score": round(raw_score, 2),
            "severity": severity,
            "components": {
                "cvss_component": round(cvss_component, 2),
                "epss_component": round(epss_component, 2),
                "kev_component": round(kev_component, 2),
                "context_component": round(context_component, 2),
            },
            "factors": {
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "in_kev": in_kev,
                "asset_criticality": asset_criticality,
                "network_reachability": network_reachability,
            },
        }

    async def score_vulnerabilities(
        self,
        cve_ids: List[str],
        asset_criticality: float = 1.0,
        network_reachability: float = 1.0,
    ) -> List[Dict[str, Any]]:
        """
        Score multiple vulnerabilities.

        Args:
            cve_ids: List of CVE identifiers
            asset_criticality: Asset importance factor
            network_reachability: Network exposure factor

        Returns:
            List of scored vulnerabilities, sorted by risk score
        """
        # Bulk fetch EPSS scores
        epss_scores = await epss_client.get_epss_scores_bulk(cve_ids)

        results = []
        for cve_id in cve_ids:
            # Enrich vulnerability
            enriched = await self.enrich_vulnerability(cve_id)

            # Get EPSS score
            epss_data = epss_scores.get(cve_id, {})
            epss_score = epss_data.get("epss_score")

            # Calculate risk score
            score_result = self.calculate_risk_score(
                cvss_score=enriched.get("cvss_v3_score"),
                epss_score=epss_score,
                in_kev=enriched.get("in_kev", False),
                asset_criticality=asset_criticality,
                network_reachability=network_reachability,
            )

            results.append({
                **enriched,
                **score_result,
            })

        # Sort by risk score descending
        results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        logger.info("Vulnerabilities scored", count=len(results))
        return results


risk_scorer = RiskScorer()
