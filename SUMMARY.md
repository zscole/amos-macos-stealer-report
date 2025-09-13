# Fake StreamYard Campaign - Quick Reference

## Attack Summary
- **Campaign**: Amos InfoStealer disguised as StreamYard
- **Vector**: Twitter DM then email with malicious link
- **Target**: macOS users, content creators
- **Status**: Attack blocked, domains burned

## Key Files
- [Full Incident Report](INCIDENT_REPORT.md) - Comprehensive analysis
- [Indicators of Compromise](INDICATORS.md) - IOCs for detection
- [README](README.md) - Repository overview

## Critical IOCs
```
Domains: streamyard.org, lefenari.com
DMG SHA256: 97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c
Payload SHA256: bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2
```

## Detection
- YARA rules: `detection/yara/`
- Suricata rules: `detection/suricata/`
- Behavioral indicators in [INDICATORS.md](INDICATORS.md)

## Key Findings
1. Threat actor renting phishing kit (~$3k/month)
2. Multiple victims confirmed
3. Amos InfoStealer variant targeting credentials/wallets
4. Social engineering combined with technical exploitation

## Response Recommendations
1. Block domains immediately
2. Hunt for file hashes
3. Monitor for `/tmp/.Streamyard` execution
4. Alert on `osascript` with `xattr -c` commands

## Repository Contents
```
├── INCIDENT_REPORT.md      # Full analysis
├── INDICATORS.md           # Complete IOCs
├── analysis/               # Technical artifacts
├── detection/              # YARA/Suricata rules
├── docs/                   # Supporting documentation
├── evidence/               # Forensic evidence (redacted)
└── scripts/                # Analysis tools
```

## Sharing
- **Classification**: TLP:CLEAR
- **License**: MIT (for analysis/rules)
- **Status**: Public release ready

---
*Incident Date: September 12, 2025*  
*Published: September 13, 2025*  
*Author: Zak Cole (@0xzak)*