# ShieldFlow AppSec Pipeline — Threat Model

**Document:** Pipeline Threat Model
**Project:** ShieldFlow AppSec Pipeline & SOAR Automation Platform
**Scope:** CI/CD pipeline, scanner toolchain, SOAR ingestion layer, artifact storage, and notification channels
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

## Threat Model Table

| ID   | Threat                 | Attack Scenario                                                      | Impact                                       | Mitigation                                                           | Component Affected                | STRIDE Category                   |
| ---- | ---------------------- | -------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------- | --------------------------------- | --------------------------------- |
| T-01 | Scanner bypass         | Attacker modifies workflow to disable scanners or reduce thresholds. | Vulnerabilities reach production.            | Branch protection, CODEOWNERS, required status checks.               | GitHub Actions workflow, Gate job | Tampering, Elevation of Privilege |
| T-02 | Workflow tampering     | Malicious PR injects compromised actions or steals secrets.          | Secret exposure and supply-chain compromise. | Pin actions to commit SHA, code review, least privilege permissions. | GitHub Actions runner, secrets    | Tampering, Information Disclosure |
| T-03 | Secret leakage         | API keys appear in logs or artifacts.                                | TheHive and Slack compromise.                | Secret masking, rotation, environment protection rules.              | GitHub Secrets, logs              | Information Disclosure            |
| T-04 | SARIF manipulation     | Findings removed from SARIF before gate evaluation.                  | False clean security state.                  | Hash verification, immutable artifacts, SARIF upload auditing.       | SARIF artifacts, Gate job         | Tampering, Repudiation            |
| T-05 | Slack webhook exposure | Webhook leaked through logs or source code.                          | Fake security alerts and phishing.           | Store as GitHub Secret, rotate if exposed.                           | Slack integration                 | Information Disclosure, Spoofing  |
| T-06 | Dependency poisoning   | Malicious package enters dependency tree.                            | Runtime compromise.                          | Lock files, Dependabot, Trivy scanning.                              | SCA pipeline                      | Tampering, Elevation of Privilege |
| T-07 | False negative scans   | Vulnerability bypasses scanner detection.                            | Vulnerability ships undetected.              | Layered security tools, manual review, custom rules.                 | SAST, DAST, Secrets scanning      | Repudiation                       |
| T-08 | Container compromise   | Malicious Docker image used in pipeline.                             | Runner compromise and secret theft.          | Pin image digest, image scanning, signature verification.            | Docker image, DAST job            | Tampering, Elevation of Privilege |

---

## Pipeline Attack Surface Summary

```text
Developer Workstation
        │
        ▼
GitHub Repository
        │
        ▼
GitHub Actions Runner
 ├── SAST (Semgrep)
 ├── SCA (Trivy)
 ├── Secrets (Gitleaks)
 └── DAST (OWASP ZAP)
        │
        ▼
Severity Gate
        │
   Deploy / Block
        │
        ▼
SOAR Connector
        │
   TheHive / Cortex
        │
        ▼
   Slack / Email
```

### Key Risks

* Highest Risk: GitHub Actions workflow files, repository secrets, SARIF artifacts.
* Lowest Residual Risk: Slack webhook exposure, SARIF manipulation.
* Accepted Residual Risk: False negatives from automated scanners.

## References

* OWASP CI/CD Security Top 10
* GitHub Actions Security Hardening Guide
* STRIDE Threat Modeling Methodology
* NIST SP 800-204C (DevSecOps)
