# Security & Legal Considerations

## Ethical Framework

This honeypot infrastructure is designed for **defensive cybersecurity research** and **threat intelligence generation**. All activities must comply with:

- Your cloud provider's Acceptable Use Policy
- Local jurisdiction computer crime laws
- Responsible disclosure norms for novel vulnerabilities

## Critical Safety Requirements

### 1. Outbound Containment (MANDATORY)

Compromised honeypot containers **will** attempt to:
- Scan random IP ranges
- Participate in DDoS attacks
- Send spam/phishing
- Host malware distribution

**iptables rules MUST be applied before exposing honeypots to internet.**

Verification:
```bash
# From inside Cowrie container
docker exec -it cowrie bash
curl https://google.com
# Expected: Connection timeout or explicit DROP
```

### 2. No Production Account Usage

- Create dedicated cloud account for honeypots
- Never use company/university production accounts
- Isolate from personal projects with sensitive data

### 3. Data Retention Policy

- Attack logs: 90 days automatic deletion (ILM policy)
- Captured malware binaries: 30 days, then hash-only retention
- No PII collection beyond what attackers voluntarily submit
- GeoIP resolution: City-level only

### 4. Legal Compliance

**You are responsible for:**
- Ensuring honeypot deployment is legal in your jurisdiction
- Not entrapping or inducing criminal activity
- Reporting serious vulnerabilities through responsible disclosure
- Maintaining audit logs of your own infrastructure access

**This project does NOT:**
- Attack third-party systems
- Collect data from non-attacker sources
- Distribute malware (binaries are quarantined in isolated storage)
- Participate in offensive operations

### 5. AWS-Specific Risks

If using AWS (not recommended for zero-budget):
- AWS may suspend account if outbound abuse detected
- Data transfer charges apply after 15GB/month free tier
- EC2 instance costs apply after 750 hrs/month free tier
- Set billing alerts and use AWS Budgets

### 6. Incident Response

If honeypot containment fails:
1. Immediately run `make down` to stop all containers
2. Apply emergency iptables: `iptables -P OUTPUT DROP`
3. Review `/var/log/kern.log` for `[HONEYPOT-ABUSE-BLOCK]` entries
4. Contact cloud provider abuse team if needed
5. Document incident for research records

## Responsible Disclosure

If you discover:
- Novel exploit technique: 90-day disclosure to vendor
- Active botnet C2 infrastructure: Report to CERT/CC or national CSIRT
- Critical infrastructure targeting: Immediate notification to affected party

## References

- [AWS Acceptable Use Policy](https://aws.amazon.com/aup/)
- [Oracle Cloud Use Policy](https://www.oracle.com/legal/privacy/services-privacy-policy.html)
- [RFC 3028 - Internet Honeypots](https://tools.ietf.org/html/rfc3028)
- [The Honeynet Project Legal Issues](https://www.honeynet.org/legal/)
