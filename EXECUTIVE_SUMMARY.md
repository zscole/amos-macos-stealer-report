# Executive Summary: Amos InfoStealer Campaign Analysis

**Incident Date**: September 12, 2025  
**Published**: September 13, 2025  
**Author**: Zak Cole (@0xzak)  
**Classification**: TLP:CLEAR  
**Distribution**: Public Release

## The Threat

I was targeted by a phishing attack using fake podcast invitations to spread Amos InfoStealer malware. This malware steals passwords, crypto wallets, and personal messages from Mac users.

## Key Statistics

- **Attack Duration**: 1 day (September 10-12, 2025)
- **Malware Family**: Amos InfoStealer (macOS)
- **C2 Connections**: 130+ encrypted HTTPS sessions (sandbox)
- **Detection Rate**: Multiple AV engines confirmed malicious
- **Financial Impact**: $0 (attack prevented)
- **Data Exfiltrated**: None 

## Attack Chain

1. **Initial Contact**: Twitter DM from fake Empire Podcast representative
2. **Lure**: Meeting invite link (streamyard.org disguised as .com)
3. **Fake Error**: "Cannot join meeting" page
4. **Malware Push**: "Download desktop client" (StreamYard has none)
5. **Prevention**: macOS Gatekeeper blocked execution

## Technical Analysis

### What the Malware Does
- Uses multiple layers of encoding to hide
- Tries to bypass Gatekeeper with xattr commands
- All communications are encrypted (HTTPS)
- Scans your system for valuable data
- Targets Mail and Messages apps

### Threat Actor Profile
- **Type**: Criminal (financially motivated)
- **Resources**: Rented infrastructure (~$3,000/month per admission)
- **Victims**: Multiple confirmed by threat actor
- **Sophistication**: Moderate (using commodity malware)

## Impact Assessment

### What Was Prevented
- Credential theft across all browsers
- Cryptocurrency wallet compromise
- Email and message theft
- System backdoor installation
- Identity theft and account takeover

### Risk to Others
- **Severity**: High
- **Active Campaign**: Yes
- **Target Profile**: Content creators, media professionals

## Key Findings

1. **Social Engineering**: Highly targeted approach using industry-specific lures
2. **Technical Evasion**: Professional-grade obfuscation and anti-analysis
3. **Infrastructure**: Threat actors using MaaS (Malware-as-a-Service)
4. **Prevention**: Native macOS security remains effective when enabled

## Recommendations for the Community

### Immediate Actions
1. Deploy provided IOCs to security tools
2. Block domains: streamyard.org, lefenari.com
3. Alert users about fake StreamYard desktop app (none exists)
4. Verify Gatekeeper is enabled on all macOS systems

### Detection Opportunities
- Monitor for osascript executing with xattr -c
- Alert on execution from /tmp/ directory
- Watch for high-volume HTTPS on ports 57xxx
- Track Mail/Messages app extension access

## Lessons Learned

This incident demonstrates that:
- Being careful can stop these attacks
- Threat actors are actively targeting individuals, not just enterprises
- Commodity malware is increasingly accessible to low-skill actors
- Sharing threat intelligence benefits the entire community

## Resources

- **Full Analysis**: [INCIDENT_REPORT.md](INCIDENT_REPORT.md)
- **IOCs**: [INDICATORS.md](INDICATORS.md)
- **Detection Rules**: `detection/` directory
- **MITRE ATT&CK**: 12+ techniques mapped

---

*This analysis is shared with the security community to help defend against similar attacks. For questions or to report similar incidents, please open an issue on GitHub.*