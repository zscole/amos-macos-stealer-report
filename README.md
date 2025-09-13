# Fake StreamYard macOS Malware Analysis

## [CRITICAL SAFETY WARNING - READ FIRST](SAFETY_WARNING.md)

**This repository contains analysis of ACTIVE MALWARE. All analysis was conducted on a quarantined laptop with NO sensitive data. DO NOT run this malware on any system with credentials or personal data.**

## Executive Summary

On September 12, 2025, I was targeted by a phishing attack. Twitter user @0xMauriceWang claimed to be from The Empire Podcast and invited me via DM, then sent a StreamYard meeting link. The fake site showed an error and prompted me to download a "desktop client." StreamYard doesn't have a desktop client. The download was malware.

### Key Findings
- **Attack Vector**: Phishing via Twitter DM and email impersonation
- **Malware Family**: Amos macOS InfoStealer
- **Distribution**: Fake domains (streamyard.org, lefenari.com)
- **Payload**: Multi-stage loader leading to credential/wallet theft malware
- **Status**: Attack prevented by macOS Gatekeeper

## Repository Structure

```
.
├── README.md                 # This file
├── INCIDENT_REPORT.md        # Full incident response report
├── INDICATORS.md             # Indicators of Compromise (IOCs)
├── docs/                     # Documentation
│   ├── timeline.md           # Attack timeline
│   ├── impact-analysis.md    # Impact assessment
│   ├── mitigations.md        # Recommended mitigations
│   └── threat-intel.md       # Threat intelligence correlation
├── analysis/                 # Technical analysis artifacts
│   ├── stage2.applescript    # Decoded Stage2 payload
│   ├── decode_stage2.sh      # Decoding script
│   └── forensics/            # Forensic artifacts
├── detection/                # Detection rules
│   ├── yara/                 # YARA rules
│   └── suricata/             # Network detection rules
└── screenshots/              # Evidence screenshots
```

## Quick Start

### For Security Teams

1. Review [INDICATORS.md](INDICATORS.md) for IOCs to add to your security stack
2. Deploy detection rules from the `detection/` directory
3. Review [mitigations.md](docs/mitigations.md) for hardening recommendations

### For Researchers

1. Read the full [INCIDENT_REPORT.md](INCIDENT_REPORT.md) for detailed analysis
2. Examine decoded payloads in `analysis/` directory
3. Review threat intelligence correlation in `docs/threat-intel.md`

## Attack Overview

### Initial Contact
- Attacker impersonated The Empire Podcast via Twitter DM
- Invitation to join fake podcast recording
- Email with malicious StreamYard link (streamyard.org instead of streamyard.com)

### Payload Delivery
- Fake error page pushing DMG download
- Social engineering to bypass security warnings
- Persistence through "installation help" call

### Technical Details
- **Stage 1**: Bash loader with multi-layer obfuscation
- **Stage 2**: AppleScript to bypass Gatekeeper
- **Final Payload**: Amos InfoStealer (Mach-O universal binary)

## Indicators of Compromise

### Domains
- `streamyard.org` (phishing site)
- `lefenari.com` (payload delivery)

### File Hashes (SHA256)
- **DMG**: `97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c`
- **Mach-O Payload**: `bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2`
- **Bash Loader**: `0b96c2efd47fe7801a4300c21f4ee8dd864aa499b2e68cd82649919445368edf`

See [INDICATORS.md](INDICATORS.md) for complete IOC list.

## Detection Rules

### YARA
```yara
rule Fake_Streamyard_Loader {
    meta:
        description = "Detects fake StreamYard macOS loader"
    strings:
        $key = "97bccf63605c587186ef47c30b101d78"
        $eval = "eval \"$oVGpzC\""
    condition:
        all of them
}
```

### Behavioral Detection
- Monitor for `osascript` executing with `xattr -c` commands
- Alert on execution attempts from `/tmp/` directory
- Track Terminal drag-and-drop installation attempts

## Mitigations

### Immediate Actions
1. Block identified domains at network level
2. Hunt for IOCs in your environment
3. Review macOS Gatekeeper settings

### Long-term Recommendations
1. User awareness training on phishing tactics
2. Implement application allowlisting
3. Monitor for suspicious AppleScript execution

## About This Research

This analysis was conducted by an independent security researcher who was directly targeted in this campaign. The thorough documentation and public release aim to help others defend against similar attacks.

**Researcher**: Zak Cole  
**Contact**: zcole@linux.com  
**Twitter**: [@0xzak](https://x.com/0xzak)  
**Incident Date**: September 12, 2025  
**Published**: September 13, 2025

## Contributing

If you have additional information about this campaign or similar attacks, please:
1. Open an issue with details
2. Submit a pull request with new IOCs
3. Contact via email for sensitive information

## CRITICAL SAFETY WARNING

**This analysis was conducted on a quarantined laptop with no sensitive data, credentials, or secrets.**

**DO NOT attempt to run this malware on any system containing:**
- Personal or work credentials
- Cryptocurrency wallets
- Banking information
- Private keys or certificates
- Personal documents or photos
- Any data you care about

This malware steals everything on your system and sends it to criminals. Even mounting the DMG can be dangerous.

## Disclaimer

I analyzed this malware using:
- A quarantined laptop with nothing important on it
- No passwords or personal data stored
- Isolated network
- Malware analysis tools

**Never run malware outside a proper lab. It will steal everything on your computer.**

## License

This repository is provided for educational and defensive security purposes under the MIT License. See LICENSE file for details.

## Acknowledgments

- VirusTotal for sandbox analysis capabilities
- The security community for collaborative defense
- macOS security features that prevented compromise
- Fellow researchers tracking Amos InfoStealer campaigns

---

**Last Updated**: September 13, 2025
**Status**: Active Campaign
**Threat Level**: High