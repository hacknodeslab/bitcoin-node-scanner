# Methodology

## Table of Contents

- [Overview](#overview)
- [Research Objectives](#research-objectives)
- [Data Collection](#data-collection)
- [Analysis Framework](#analysis-framework)
- [Risk Assessment](#risk-assessment)
- [Ethical Considerations](#ethical-considerations)
- [Limitations](#limitations)
- [Scientific Basis](#scientific-basis)

---

## Overview

This document describes the methodology behind the Bitcoin Node Security Scanner, including data collection techniques, analysis frameworks, risk assessment criteria, and ethical considerations.

### Purpose

The scanner identifies security vulnerabilities in publicly exposed Bitcoin nodes to:
- Improve overall Bitcoin network security posture
- Help node operators identify misconfigurations
- Provide aggregate security metrics for the Bitcoin ecosystem
- Enable responsible disclosure of critical issues

---

## Research Objectives

### Primary Objectives

1. **Vulnerability Identification**
   - Identify nodes running known vulnerable Bitcoin Core/Knots versions
   - Detect exposed RPC interfaces (critical security risk)
   - Find development versions running in production environments

2. **Infrastructure Analysis**
   - Map geographic distribution of Bitcoin nodes
   - Analyze hosting provider concentrations
   - Identify infrastructure security patterns

3. **Temporal Analysis**
   - Track patch adoption rates
   - Measure time-to-update after security releases
   - Monitor version distribution evolution

4. **Risk Quantification**
   - Categorize nodes by risk level
   - Quantify exposure severity
   - Identify high-value targets

### Secondary Objectives

- Provide actionable intelligence for node operators
- Contribute to Bitcoin security research
- Develop automated security assessment tools
- Create baseline metrics for future comparison

---

## Data Collection

### Data Sources

#### Primary Source: Shodan

**Why Shodan?**
- Comprehensive internet-wide scanning
- Regular updates (continuous scanning)
- Historical data availability
- API access for automation
- Structured data output

**What Shodan Provides:**
- IP addresses and ports
- Service banners and version strings
- SSL/TLS certificate information
- Geographic location data
- Autonomous System (AS) information
- Associated hostnames and domains

#### Secondary Source: Bitnodes (Cross-Reference)

**Purpose:**
- Validate Shodan findings
- Compare exposed vs. reachable node populations
- Verify version distributions
- Cross-reference network topology

### Collection Process

#### Phase 1: Multi-Query Search

Execute comprehensive Shodan queries:

```
Query Set:
1. product:Bitcoin
2. port:8333 (P2P mainnet)
3. "Satoshi" port:8333
4. port:8332 (RPC - CRITICAL)
5. "Bitcoin Core"
6. "Bitcoin Knots"
7. bitcoin (general)
8. "btcd" (alternative implementation)
9. "bcoin" (alternative implementation)
```

**Rationale:**
- **Redundancy**: Multiple queries ensure comprehensive coverage
- **Specificity**: Different query types catch different node configurations
- **Completeness**: Captures both standard and non-standard deployments

#### Phase 2: Data Parsing

Extract standardized fields from Shodan results:

**Network Information:**
- IP address
- Port number
- Transport protocol
- Geographic location (country, city, coordinates)
- ISP and organization
- ASN (Autonomous System Number)

**Service Information:**
- Product name and version
- Banner content
- SSL/TLS configuration
- Associated hostnames

**Security Information:**
- Known vulnerabilities (CVE references)
- CPE identifiers
- Service tags

#### Phase 3: Host Enrichment (Selective)

For high-risk nodes, perform deep host scans:

**Enrichment Criteria:**
- RPC port (8332) exposed
- Known vulnerable version detected
- Multiple high-risk services on same host

**Enrichment Data:**
- Complete port inventory
- All running services
- Operating system fingerprinting
- Additional vulnerability information

### Data Quality Assurance

**Deduplication:**
- Remove duplicate IP addresses
- Merge data from multiple queries
- Preserve all query sources for traceability

**Validation:**
- Verify version string formats
- Cross-check geographic data
- Validate port/service correlations

**Completeness:**
- Track missing fields
- Document data gaps
- Note unavailable information

---

## Analysis Framework

### Vulnerability Detection

#### Version Analysis

**Method:**
1. Extract version from banner/product fields
2. Parse version number components
3. Match against vulnerability database
4. Classify severity level

**Vulnerability Database:**
```yaml
# Known Vulnerable Versions
0.13.x: Multiple CVEs (including consensus bugs)
0.14.x: CVE-2017-12842 (remote crash)
0.15.x - 0.16.x: CVE-2018-17144 (inflation bug)
0.17.x - 0.19.x: Multiple DoS vectors
0.20.x - 0.21.x: Various CVEs
< 0.21.0: Generally considered outdated
```

**Version Classification:**
- **Critical**: Active exploit available
- **High**: Known vulnerability, no public exploit
- **Medium**: Outdated but no known active vulnerabilities
- **Low**: Recent version with good security posture

#### Configuration Analysis

**RPC Exposure Detection:**
```
IF port == 8332 AND publicly accessible THEN
    risk_level = CRITICAL
    reason = "RPC_EXPOSED"
```

**Rationale:**
- RPC interface provides full node control
- Should NEVER be exposed to internet
- Immediate security incident if detected

**Development Version Detection:**
```
IF version contains ".99." THEN
    risk_level = MEDIUM/HIGH
    reason = "DEV_VERSION_IN_PRODUCTION"
```

**Rationale:**
- Development versions are unstable
- Not intended for production use
- May contain unpatched vulnerabilities

### Infrastructure Analysis

#### Geographic Distribution

**Metrics:**
- Node count per country
- Node density per capita
- Regulatory environment correlation
- Timezone-based activity patterns

**Analysis Questions:**
- Are nodes concentrated in privacy-friendly jurisdictions?
- Do geographic patterns suggest institutional vs. retail operators?
- Are there unexpected concentrations?

#### Hosting Provider Analysis

**ASN Distribution:**
- Top hosting providers
- Cloud vs. residential distribution
- Single-provider concentration risk

**Implications:**
- **High cloud concentration**: Centralization risk
- **Residential diversity**: Better decentralization
- **Major provider dominance**: Infrastructure attack surface

#### Multi-Service Analysis

**Co-located Services:**
```
IF same_ip hosts:
    - Bitcoin node
    - SSH (port 22)
    - Web server (80/443)
    - Database (3306, 5432)
THEN
    risk_level = HIGH
    reason = "MULTIPLE_SERVICES"
```

**Rationale:**
- Increases attack surface
- Suggests shared infrastructure
- Higher compromise risk

### Temporal Analysis

#### Patch Adoption Metrics

**Measurement:**
1. Note release date of new version
2. Track version distribution over time
3. Calculate adoption percentages
4. Measure time-to-50% adoption
5. Identify slow-updating populations

**Key Metrics:**
- Days to 10% adoption
- Days to 50% adoption
- Days to 90% adoption
- Percentage still on vulnerable versions

**Example Timeline:**
```
Bitcoin Core 30.0.0 Release: Dec 2024
+30 days: 16% adoption
+60 days: 35% adoption
+90 days: 52% adoption
```

#### Version Lifecycle

**Categories:**
- **Current**: Latest stable release
- **Maintained**: Recent, still supported
- **Outdated**: Old but functional
- **Vulnerable**: Known security issues
- **Critical**: Active exploitation risk

---

## Risk Assessment

### Risk Level Framework

#### CRITICAL

**Criteria:**
- RPC interface (port 8332) publicly exposed

**Impact:**
- Complete node compromise possible
- Fund theft if wallet enabled
- Network disruption potential

**Prevalence:** ~0.1-0.2% of exposed nodes

**Recommended Action:**
- Immediate remediation required
- Firewall RPC port immediately
- Check for compromise indicators

---

#### HIGH

**Criteria:**
- Known vulnerable version + exposed services
- Multiple high-risk factors (2+)
- Development version + internet exposure

**Impact:**
- Remote code execution possible
- Denial of service likely
- Data exfiltration risk

**Prevalence:** ~15-20% of exposed nodes

**Recommended Action:**
- Urgent update required
- Review firewall configuration
- Monitor for unusual activity

---

#### MEDIUM

**Criteria:**
- Single risk factor
- Outdated version (no known active exploits)
- Development version only

**Impact:**
- Potential DoS vulnerability
- Information disclosure
- Reduced reliability

**Prevalence:** ~35-40% of exposed nodes

**Recommended Action:**
- Schedule update within 30 days
- Review security configuration
- Enable monitoring

---

#### LOW

**Criteria:**
- Recent version (< 6 months old)
- Secure configuration
- Only P2P port exposed

**Impact:**
- Minimal security risk
- Normal operational exposure

**Prevalence:** ~40-45% of exposed nodes

**Recommended Action:**
- Maintain regular update schedule
- Continue monitoring
- Follow best practices

---

### Risk Scoring Algorithm

```python
def calculate_risk_score(node):
    score = 0
    
    # Critical factors
    if node.port == 8332:
        return 100  # Immediate CRITICAL
    
    # High-risk factors
    if is_vulnerable_version(node.version):
        score += 40
    
    if is_dev_version(node.version):
        score += 30
    
    # Medium-risk factors
    if count_high_risk_services(node) > 2:
        score += 20
    
    if version_age(node.version) > 365:  # days
        score += 15
    
    # Risk levels
    if score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"
```

---

## Ethical Considerations

### Passive Reconnaissance Only

**Principles:**
- **No Active Exploitation**: Never attempt to exploit vulnerabilities
- **No Unauthorized Access**: Never attempt authentication
- **No Service Disruption**: Never send malformed packets or DoS
- **Public Data Only**: Only use publicly available information

### Responsible Disclosure

**Process:**
1. **Discovery**: Identify vulnerability pattern
2. **Validation**: Confirm finding with multiple sources
3. **Documentation**: Thoroughly document methodology
4. **Private Disclosure**: Report to Bitcoin Core security team first
5. **Embargo Period**: Allow 90 days for patching
6. **Public Disclosure**: Publish anonymized findings

**Contact:**
- Bitcoin Core Security: security@bitcoincore.org
- Encrypted communication preferred (PGP)

### Data Privacy

**Anonymization:**
- **Never publish**: Individual IP addresses
- **Never publish**: Specific organizational identities
- **Always aggregate**: Present statistics only
- **Always anonymize**: Remove identifying information

**GDPR Compliance:**
- Data from public sources (Shodan)
- Legitimate security research interest
- No personal data collection
- Anonymized reporting

### Research Ethics

**Principles:**
1. **Benefit > Harm**: Research must benefit Bitcoin security
2. **Transparency**: Methodology must be publicly documented
3. **Reproducibility**: Results must be verifiable
4. **Accountability**: Researchers must be identifiable

---

## Limitations

### Coverage Limitations

**Not Captured:**
- Nodes behind NAT without port forwarding
- Nodes on Tor or I2P only
- Nodes with non-standard configurations
- Private/internal nodes
- Nodes blocking Shodan scanners

**Estimated Coverage:**
- ~50% of total Bitcoin nodes
- ~90% of publicly-exposed nodes
- ~100% of internet-facing nodes

### Temporal Limitations

**Data Freshness:**
- Shodan data may be hours to days old
- Network changes occur continuously
- Scan represents point-in-time snapshot

**Recommendation:**
- Regular re-scanning (weekly/monthly)
- Trend analysis over time
- Compare with historical data

### Technical Limitations

**Version Detection:**
- Relies on banner accuracy
- Custom builds may misreport
- Version strings can be modified
- Some nodes hide version information

**False Positives:**
- Honeypots may appear vulnerable
- Intentionally misconfigured test nodes
- Version strings may not reflect actual version

**False Negatives:**
- Custom patches not reflected in version
- Hidden vulnerabilities (0-days)
- Configuration issues not detectable remotely

### Methodological Limitations

**No Internal Assessment:**
- Cannot assess internal security
- Cannot verify patch application
- Cannot test actual vulnerability

**Banner-Based Only:**
- Relies on service self-reporting
- No active probing
- No exploitation attempts

---

## Scientific Basis

### Threat Modeling

**Attacker Model:**
- **Capability**: Internet-wide scanning (like Shodan)
- **Goal**: Identify vulnerable Bitcoin nodes
- **Constraints**: No inside knowledge, remote only

**Attack Vectors:**
1. **Remote Code Execution**: Via known CVEs
2. **Denial of Service**: Protocol-level attacks
3. **Information Disclosure**: Banner grabbing
4. **Unauthorized RPC Access**: Exposed interfaces

### Validation Methods

**Cross-Validation:**
- Compare Shodan results with Bitnodes
- Verify version distributions
- Cross-check geographic data

**Statistical Validation:**
- Chi-square tests for distribution anomalies
- Time-series analysis for trend validation
- Correlation analysis for relationship verification

**Expert Review:**
- Peer review by Bitcoin Core developers
- Security researcher validation
- Community feedback incorporation

### Reproducibility

**Open Methodology:**
- Complete documentation of process
- Open-source scanner code
- Published query strings
- Transparent analysis methods

**Reproducible Results:**
- Same queries should yield similar results
- Methodology can be independently verified
- Results can be cross-validated

---

## Statistical Methods

### Descriptive Statistics

**Measures:**
- **Central Tendency**: Mean, median, mode
- **Dispersion**: Standard deviation, variance
- **Distribution**: Histograms, frequency tables

**Applications:**
- Version distribution analysis
- Geographic concentration metrics
- Risk level distributions

### Comparative Analysis

**Methods:**
- Time-series comparison
- Cross-sectional analysis
- Before/after studies

**Examples:**
- Version adoption over time
- Pre/post security release changes
- Regional comparison

### Sampling Considerations

**Population:**
- All internet-exposed Bitcoin nodes
- Estimated ~50,000 - 100,000 nodes

**Sample:**
- Shodan-indexed nodes (~12,000 - 25,000)
- ~50% coverage estimate

**Bias Considerations:**
- Selection bias (Shodan-indexed only)
- Temporal bias (point-in-time)
- Geographic bias (internet connectivity)

---

## Continuous Improvement

### Feedback Integration

**Sources:**
- Bitcoin Core developer input
- Security researcher feedback
- Community contributions
- False positive reports

### Methodology Updates

**Triggers for Updates:**
- New vulnerability types discovered
- Changes in Bitcoin protocol
- Improved detection methods
- Community best practices evolution

### Version Control

**Documentation:**
- Track methodology changes
- Version methodology documents
- Maintain change log
- Archive historical methods

---

## Future Work

### Planned Enhancements

1. **Automated Monitoring**: Continuous scanning
2. **Trend Analysis**: Long-term pattern detection
3. **Predictive Modeling**: Adoption rate prediction
4. **Network Graph Analysis**: Node relationship mapping

### Research Questions

- What factors predict rapid patch adoption?
- Are there geographic security patterns?
- How do hosting choices affect security?
- What is the relationship between node age and vulnerability?

---

## References

### Academic Research

- Nakamoto, S. (2008). "Bitcoin: A Peer-to-Peer Electronic Cash System"
- Heilman, E., et al. (2015). "Eclipse Attacks on Bitcoin's Peer-to-Peer Network"
- OSTIF/Quarkslab (2025). "Bitcoin Core Technical Security Audit Report"

### Technical Documentation

- Bitcoin Core Security Advisories: https://bitcoincore.org/en/security-advisories/
- CVE Database: https://cve.mitre.org/
- Shodan Documentation: https://developer.shodan.io/

### Standards and Guidelines

- NIST Cybersecurity Framework
- OWASP Security Testing Guide
- Responsible Disclosure Guidelines (ISO 29147)

---

## Conclusion

This methodology provides a systematic, ethical, and scientifically rigorous approach to Bitcoin node security assessment. By combining passive reconnaissance, statistical analysis, and responsible disclosure practices, we aim to contribute positively to Bitcoin network security while respecting privacy and ethical boundaries.

The methodology is continuously evolving based on community feedback, new threats, and improved detection capabilities. All updates are documented and versioned to ensure reproducibility and transparency.

---

## Contact

For methodology questions or suggestions:
- Email: security@hacknodes.com
- GitHub Issues: https://github.com/hacknodes-lab/bitcoin-node-scanner/issues

---

**Document Version:** 1.0.0  
**Last Updated:** 2026-01-03  
**Authors:** HackNodes Lab Research Team
