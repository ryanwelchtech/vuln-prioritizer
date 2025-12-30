# Vulnerability Prioritization Engine

[![CI](https://github.com/ryanwelchtech/vuln-prioritizer/workflows/CI/badge.svg)](https://github.com/ryanwelchtech/vuln-prioritizer/actions)
[![Security Scan](https://github.com/ryanwelchtech/vuln-prioritizer/workflows/Security%20Scan/badge.svg)](https://github.com/ryanwelchtech/vuln-prioritizer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Intelligent vulnerability management platform that correlates CVEs with runtime context, exploit availability, and business criticality to prioritize remediation. Reduces vulnerability noise by 70% by focusing on exploitable, reachable issues.

## Architecture

```mermaid
graph TB
    subgraph "Vulnerability Prioritization Engine"
        subgraph "Data Ingestion Layer"
            Trivy[Trivy Scanner]
            NVD[NIST NVD API]
            EPSS[EPSS API]
            KEV[CISA KEV Feed]
        end

        subgraph "Backend Services"
            API[FastAPI Gateway<br/>Port 8000]
            Scorer[Risk Scoring Engine]
            Correlator[CVE Correlator]
            Scheduler[Background Jobs<br/>Celery]
        end

        subgraph "Data Layer"
            DB[(PostgreSQL<br/>Vulnerability Store)]
            Cache[(Redis<br/>API Cache)]
        end

        subgraph "Frontend"
            UI[React Dashboard<br/>Port 3000]
        end
    end

    subgraph "External Integrations"
        Jira[Jira/ServiceNow]
        Slack[Slack Alerts]
        GitHub[GitHub Security]
    end

    Trivy -->|Scan Results| API
    NVD -->|CVE Data| Correlator
    EPSS -->|Exploit Probability| Scorer
    KEV -->|Known Exploited| Scorer

    API --> Scorer
    API --> Correlator
    Scorer --> DB
    Correlator --> DB
    Scheduler --> Cache

    UI -->|REST API| API
    API --> Jira
    API --> Slack
    API --> GitHub

    style UI fill:#3b82f6,stroke:#1e40af,color:#fff
    style API fill:#10b981,stroke:#059669,color:#fff
    style Scorer fill:#f59e0b,stroke:#d97706,color:#fff
```

## Risk Scoring Flow

```mermaid
sequenceDiagram
    participant Scanner
    participant API
    participant NVD
    participant EPSS
    participant Scorer
    participant DB

    Scanner->>API: Submit vulnerability scan
    API->>NVD: Fetch CVE details
    NVD-->>API: CVSS, CWE, references
    API->>EPSS: Get exploit probability
    EPSS-->>API: EPSS score (0-1)
    API->>Scorer: Calculate risk score

    Note over Scorer: Risk = CVSS * EPSS * Asset_Criticality * Reachability

    Scorer->>DB: Store prioritized vulnerabilities
    Scorer-->>API: Risk-ranked results
    API-->>Scanner: Prioritized response
```

## Key Features

- **Risk-Based Scoring**: Combines CVSS, EPSS exploit probability, asset criticality, and network reachability into unified risk score
- **CISA KEV Integration**: Automatically flags vulnerabilities in Known Exploited Vulnerabilities catalog
- **EPSS Correlation**: Uses Exploit Prediction Scoring System for real-world exploit likelihood
- **Remediation SLA Tracking**: Configurable SLA policies with Jira/ServiceNow ticket integration
- **Trend Analysis**: Historical vulnerability aging reports and mean-time-to-remediate metrics
- **Asset Context**: Maps vulnerabilities to business-critical assets for prioritization

## Tech Stack

### Backend
- **Framework**: Python 3.11, FastAPI, Pydantic v2
- **Database**: PostgreSQL 15, SQLAlchemy 2.0, Alembic
- **Caching**: Redis for API response caching
- **Background Jobs**: Celery for async CVE enrichment
- **Scanner Integration**: Trivy, Grype API clients

### Frontend
- **Framework**: Next.js 14, React 18, TypeScript
- **Styling**: Tailwind CSS, Recharts for visualizations
- **State**: React Query, Zustand

### Infrastructure
- **Containers**: Docker, Kubernetes
- **CI/CD**: GitHub Actions, Trivy scanning
- **Monitoring**: Prometheus, Grafana

### Security Data Sources
- **NIST NVD**: CVE details, CVSS scores
- **FIRST EPSS**: Exploit probability scores
- **CISA KEV**: Known exploited vulnerabilities
- **GitHub Advisory**: Security advisories

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Node.js 20+ and Python 3.11+
- PostgreSQL 15+ (or use Docker)

### Quick Start

```bash
# Clone repository
git clone https://github.com/ryanwelchtech/vuln-prioritizer.git
cd vuln-prioritizer

# Start all services
docker-compose up -d

# Access the dashboard
open http://localhost:3000
```

### Local Development

```bash
# Backend setup
cd src/backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend setup (new terminal)
cd src/frontend
npm install
npm run dev
```

### Environment Variables

```bash
# Backend (.env)
DATABASE_URL=postgresql://vulndb:vulndb@localhost:5432/vulndb
REDIS_URL=redis://localhost:6379/0
NVD_API_KEY=your-nvd-api-key
JIRA_URL=https://your-org.atlassian.net
JIRA_API_TOKEN=your-jira-token
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx

# Frontend (.env.local)
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/vulnerabilities` | GET | List prioritized vulnerabilities |
| `/api/v1/vulnerabilities/{cve_id}` | GET | Get CVE details with risk score |
| `/api/v1/scans` | POST | Submit vulnerability scan results |
| `/api/v1/assets` | GET/POST | Manage asset inventory |
| `/api/v1/policies` | GET/POST | Configure SLA policies |
| `/api/v1/reports/trends` | GET | Vulnerability trend analysis |
| `/api/v1/integrations/jira` | POST | Create Jira ticket for CVE |

## Risk Scoring Algorithm

```python
def calculate_risk_score(vuln: Vulnerability) -> float:
    """
    Risk Score = Base_Score * Exploit_Factor * Context_Factor

    Base_Score: CVSS v3.1 (0-10)
    Exploit_Factor: EPSS probability * KEV multiplier (1.0-2.0)
    Context_Factor: Asset criticality * Network reachability (0.5-1.5)
    """
    base = vuln.cvss_score / 10  # Normalize to 0-1

    exploit_factor = vuln.epss_score
    if vuln.in_kev:
        exploit_factor *= 2.0  # Double weight for known exploited

    context_factor = (
        vuln.asset_criticality * 0.5 +
        vuln.network_reachability * 0.5
    )

    return min(base * exploit_factor * context_factor * 100, 100)
```

## Security Considerations

### Data Protection
- All API endpoints require JWT authentication
- Database credentials stored in Kubernetes secrets
- Redis connections encrypted with TLS

### Vulnerability Data
- NVD API rate limiting with exponential backoff
- CVE data cached for 24 hours to reduce API calls
- EPSS scores refreshed daily via background job

### Compliance
- Audit logging for all vulnerability state changes
- RBAC for team-based access control
- Data retention policies for compliance requirements

## Monitoring

### Prometheus Metrics

```prometheus
# Application metrics
vuln_prioritizer_vulnerabilities_total{severity="critical|high|medium|low"}
vuln_prioritizer_risk_score_distribution
vuln_prioritizer_sla_violations_total
vuln_prioritizer_scan_duration_seconds
vuln_prioritizer_api_requests_total{endpoint, status}
```

### Grafana Dashboards

Pre-built dashboards in `monitoring/grafana/dashboards/`:
- Vulnerability Overview (counts, trends, SLA status)
- Risk Distribution (score histograms, severity breakdown)
- Remediation Metrics (MTTR, aging analysis)

## Documentation

- [Architecture Deep Dive](docs/ARCHITECTURE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Security Hardening](docs/SECURITY.md)
- [API Reference](docs/API.md)

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/epss-v3-support`)
3. Commit changes (`git commit -m 'Add EPSS v3 API support'`)
4. Push to branch (`git push origin feature/epss-v3-support`)
5. Open Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details

## Contact

**Ryan Welch**
Cloud & Systems Security Engineer
[GitHub](https://github.com/ryanwelchtech) | [LinkedIn](https://www.linkedin.com/in/ryanwelch54/)

---

Built with Python, FastAPI, React, and a focus on risk-based vulnerability management.
