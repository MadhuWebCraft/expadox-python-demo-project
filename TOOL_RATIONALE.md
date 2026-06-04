# ShieldFlow AppSec Pipeline – Tool Selection & Rationale

## Tool Selection Rationale

| Security Function | Selected Tool | Purpose | Why Chosen | Alternatives Considered | Why Rejected |
|------------------|--------------|---------|------------|--------------------------|--------------|
| SAST | Semgrep | Source code security analysis | Fast, open-source, GitHub Actions integration, SARIF output, custom rules support | SonarQube, CodeQL, Bandit | Higher setup complexity, slower scans, language limitations |
| SCA | Trivy | Dependency and container vulnerability scanning | Free, scans filesystem and containers, CVSS-based severity scoring, SARIF support | Snyk, OWASP Dependency-Check, Grype | Paid tiers, slower scans, weaker integrations |
| Secrets Detection | Gitleaks | Detects exposed credentials and secrets | Scans full Git history, low false positives, GitHub Actions support | TruffleHog, git-secrets, detect-secrets | Less stable integrations or limited coverage |
| DAST | OWASP ZAP | Dynamic web application security testing | OWASP standard, free, Juice Shop compatible, GitHub Actions support | Burp Suite, Nikto, Nuclei | Commercial licensing or limited automation |
| CI/CD | GitHub Actions | Pipeline orchestration and automation | Native GitHub integration, free for public repositories, Security tab support | Jenkins, GitLab CI, CircleCI | Additional infrastructure and maintenance |
| SOAR | Mock TheHive Simulator | Automated alert ingestion and playbook simulation | Demonstrates SOAR concepts without heavy infrastructure | TheHive + Cortex, Shuffle SOAR | Time-consuming setup and resource requirements |
| Notifications | Slack Incoming Webhooks | Security alert notifications | Free, simple setup, webhook-based integration | Teams, Email, PagerDuty | Additional configuration or costs |

---

# Tool Integration Architecture

| Stage | Tool | Output Format | Consumed By |
|---------|---------|---------|---------|
| SAST | Semgrep | SARIF 2.1.0 | Gate, SOAR, GitHub Security |
| SCA | Trivy | SARIF 2.1.0 | Gate, SOAR, GitHub Security |
| Secrets | Gitleaks | JSON / SARIF | Gate, SOAR, GitHub Security |
| DAST | OWASP ZAP | JSON / SARIF | Gate, SOAR, GitHub Security |
| Gate | Python Severity Script | Exit Code 0/1 | Deployment Control |
| SOAR | Mock TheHive Simulator | Alert Objects | Slack Notifications |
| Notification | Slack Webhook | Block Kit Message | Security Team |

---

# Key Design Principles

## 1. Open Source First
All selected tools are free and open-source, reducing project cost while maintaining enterprise-grade capabilities.

## 2. SARIF Standardization
All scanner outputs are converted to SARIF 2.1.0 to ensure consistent processing and GitHub Security integration.

## 3. Parallel Security Scanning
SAST, SCA, Secrets Detection, and DAST execute independently to reduce pipeline execution time.

## 4. Automated Response
Security findings are automatically ingested by the SOAR simulator and mapped to predefined playbooks.

## 5. Security Gate Enforcement
Critical findings automatically block deployment, ensuring vulnerable code cannot progress through the pipeline.

---

# References

- Semgrep: https://semgrep.dev/docs/
- Trivy: https://trivy.dev/
- Gitleaks: https://gitleaks.io/
- OWASP ZAP: https://www.zaproxy.org/
- GitHub Actions Security: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- TheHive Project: https://thehive-project.org/
- Slack Block Kit: https://api.slack.com/block-kit
