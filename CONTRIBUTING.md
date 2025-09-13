# Contributing to StreamYard Incident Analysis

## Responsible Disclosure

How we handle malware safely:

1. **No Active Malware**: Everything was analyzed in a safe environment
2. **Privacy Protected**: Personal info has been removed
3. **Defense Only**: This is for protecting systems, not attacking
4. **Helping Others**: Shared so others can defend themselves

## How to Contribute

### Reporting Similar Incidents
If you've encountered similar attacks:
1. Open an issue with redacted details
2. Include IOCs in standardized format (STIX 2.1 preferred)
3. Provide timeline and TTPs observed
4. Do NOT include active malware samples in issues

### Adding Detection Rules
1. Fork the repository
2. Add rules to appropriate directories:
   - `detection/yara/` for YARA rules
   - `detection/suricata/` for network rules
   - `detection/sigma/` for Sigma rules
3. Include metadata: author, date, description, references
4. Test rules before submission
5. Submit pull request with testing evidence

### Improving Documentation
- Follow existing formatting conventions
- Cite sources for threat intelligence
- Use clear, technical language
- Include MITRE ATT&CK references where applicable

## Code of Conduct

- Respect privacy of all parties
- No malicious use of shared information
- Collaborative and professional communication
- Focus on improving collective defense

## Security Considerations

- Never execute malware samples outside isolated environments
- Verify all IOCs before deployment
- Test detection rules in non-production first
- Report any accidentally included PII immediately

## Contact

For sensitive security matters or questions:
- GitHub Issues (public discussion)
- Email: zcole@linux.com (sensitive matters)
- Twitter: [@0xzak](https://x.com/0xzak)

## Legal

By contributing, you agree that your contributions will be licensed under the MIT License.