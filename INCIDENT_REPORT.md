# Incident Response Report: Fake StreamYard macOS Malware

**Incident ID**: INC-2025-0912-001  
**Report Version**: 1.1  
**Classification**: TLP:CLEAR  
**Incident Date**: September 12, 2025  
**Report Published**: September 13, 2025  
**Last Updated**: September 13, 2025  

## Incident Metadata

| Field | Value |
|-------|-------|
| **Incident Type** | Targeted Phishing / Malware Delivery |
| **Severity** | High |
| **Impact** | None (Prevented) |
| **Threat Actor** | Unknown (Criminal, Non-APT) |
| **Target Sector** | Media/Content Creation |
| **Initial Vector** | Social Engineering (Twitter/Email) |
| **Malware Family** | Amos InfoStealer |
| **MITRE ATT&CK** | [View Mappings](#mitre-attck) |
| **Kill Chain Phase** | Delivery (Blocked) |
| **Containment Status** | Complete |
| **Regulatory Requirements** | N/A |

## 1. Executive Summary

I was targeted by a phishing attack on September 12, 2025. The attacker impersonated someone associated with The Empire Podcast and tried to get me to install fake StreamYard software. The malware was Amos InfoStealer, which steals passwords, crypto wallets, and personal data. macOS Gatekeeper blocked it from running.

### Key Findings
- Attack used both social engineering and malware
- Attacker admitted paying $3,000/month for phishing kit
- Attacker confirmed he had other victims
- macOS Gatekeeper blocked the malware

## 2. Timeline of Events

All times in UTC-6 (Central Time)

### September 10, 2025
- **Initial Contact**: Twitter DM from @0xMauriceWang inviting me to join The Empire Podcast
- **Email Request**: Asked for my email to send invite
- **Phishing Email**: Sent meeting link from `studio@theempirepodcast.com` (streamyard.org disguised as streamyard.com)

### September 12, 2025
- **Morning**: Clicked link, got "error joining" message
- **10:57**: Downloaded fake "desktop client" DMG (StreamYard has no desktop client)
- **10:58:04**: macOS Gatekeeper initiates quarantine analysis
- **10:58:05-10**: DMG mounted as `/Volumes/Streamyard`
- **11:00-11:15**: Social engineering call with threat actor
- **11:15-11:45**: Static malware analysis conducted
- **11:45+**: Forensic artifacts collected and preserved

## 3. Attack Vector Analysis

### 3.1 Initial Compromise Attempt

**Social Engineering Chain**:
1. Twitter DM from someone claiming to be with The Empire Podcast
2. Email with meeting link (text showed streamyard.com but went to streamyard.org)
3. Fake meeting page showed "error joining"
4. Prompted to download "desktop client" (StreamYard has no desktop app)
5. Offered "help" via call when I said I had installation troubles

### 3.2 Technical Delivery

**Domain Infrastructure**:
- Primary lure: `streamyard.org`
- Payload delivery: `lefenari.com/.../load.*.php?call=stream`
- WhereFroms metadata preserved in quarantine

## 4. Malware Analysis

### 4.1 Package Structure

The DMG contained:
```
/Volumes/Streamyard/
├── .Streamyard          # Hidden Mach-O payload
├── Streamyard.KPi       # Bash loader script
├── Terminal             # Finder alias (social engineering)
├── .VolumeIcon.icns     # Volume icon
└── .background/         # Background image
```

### 4.2 Execution Chain

**Stage 1 - Bash Loader** (`Streamyard.KPi`)
- SHA256: `0b96c2efd47fe7801a4300c21f4ee8dd864aa499b2e68cd82649919445368edf`
- Obfuscation: Base64 → XOR (key: `97bccf63605c587186ef47c30b101d78`) → Base64 → eval

**Stage 2 - AppleScript**
- SHA256: `ffedeeceee860b9f6f37675f604fbf6754734e9402cfb1e786a928f826054167`
- Actions:
  1. Copy `.Streamyard` to `/tmp/.Streamyard`
  2. Remove quarantine attribute (`xattr -c`)
  3. Set executable permissions (`chmod +x`)
  4. Execute payload

**Stage 3 - Mach-O Payload**
- SHA256: `bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2`
- Type: Universal binary (x86_64 + arm64)
- Classification: Amos InfoStealer variant

### 4.3 Malware Capabilities

Based on Amos family analysis and VirusTotal sandbox execution:

**Observed Behaviors (VirusTotal Sandbox)**:
- **Network Activity**: Extensive HTTPS traffic observed on multiple ephemeral ports (57xxx range)
- **Encrypted Communications**: Uses TLS/HTTPS for C2 communication (MITRE T1573)
- **File System Activity**:
  - Drops payloads to `/Volumes/Streamyard/.Streamyard` and `/Volumes/Streamyard/Streamyard.KPi`
  - Writes to power management databases (`/private/var/db/powerlog/`)
  - Archives system logs with timestamps
- **System Reconnaissance**:
  - Accesses Mail.app extensions
  - Accesses Messages.app extensions
  - Enumerates system frameworks (`/usr/bin/`, `/Library/Frameworks/`)

**Known Amos Capabilities**:
- Browser credential theft (Chrome, Safari, Firefox)
- Cryptocurrency wallet extraction
- System information gathering
- Persistence via LaunchAgents
- C2 communication via HTTP/Telegram

## 5. Dynamic Analysis (VirusTotal Sandbox)

### 5.1 Execution Environment
- **Platform**: macOS sandbox environment
- **Analysis Date**: September 12, 2025
- **Sample**: Streamyard.dmg (SHA256: 97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c)

### 5.2 Network Behavior
The malware made a lot of network connections:
- **Protocol**: HTTPS only (port 443)
- **Ports**: Used high ports in the 57000-58000 range
- **Volume**: Over 130 connections
- **Encryption**: Everything was encrypted

### 5.3 File System Operations
**Files Created/Modified**:
- Power management databases (potential persistence or anti-analysis)
- System log archives with date-based naming convention

**Suspicious Access Patterns**:
- Mail.app extension enumeration (potential email harvesting)
- Messages.app extension access (iMessage data collection)
- Framework directory scanning (system profiling)

### 5.4 Evasion Techniques
- All C2 traffic was encrypted
- No readable domains found in sandbox
- Modified power management files (maybe to prevent sleep)

## 6. Threat Actor Intelligence

### Profile
- **Type**: Criminal, financially motivated
- **Sophistication**: Moderate (rented infrastructure)
- **Scale**: Multiple active victims
- **Investment**: ~$3,000/month for phishing kit
- **Control**: Limited (no access to C2 infrastructure)

### TTPs (MITRE ATT&CK)
- T1566.001 - Phishing: Spearphishing Attachment
- T1204.002 - User Execution: Malicious File
- T1553.001 - Subvert Trust Controls: Gatekeeper Bypass
- T1055 - Process Injection
- T1003 - OS Credential Dumping
- T1573 - Encrypted Channel (confirmed via sandbox)
- T1119 - Automated Collection
- T1005 - Data from Local System
- T1114 - Email Collection (Mail.app access observed)
- T1083 - File and Directory Discovery

## 7. Impact Assessment

### Prevented Impacts
- No malware execution achieved
- No persistence established
- No data was stolen
- No lateral movement possible

### What Would Have Happened If It Ran
- Steal all email and messages
- Steal browser passwords and cookies
- Steal crypto wallets
- Install backdoor for future access
- Send everything to criminals

## 8. Indicators of Compromise

### Network IOCs
```
Domain: streamyard.org
Domain: lefenari.com
URL Pattern: */load.*.php?call=stream
```

### File IOCs
```
DMG:        97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c
Payload:    bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2
Loader:     0b96c2efd47fe7801a4300c21f4ee8dd864aa499b2e68cd82649919445368edf
Stage2:     ffedeeceee860b9f6f37675f604fbf6754734e9402cfb1e786a928f826054167
```

### Behavioral Indicators
- Execution attempts from `/tmp/` directory
- `osascript` with `xattr -c` commands
- Unexpected Terminal drag-and-drop prompts
- StreamYard branded DMG (legitimate service has no desktop app)
- Power management database writes (`/private/var/db/powerlog/`)
- Mail.app and Messages.app extension enumeration
- High-volume HTTPS traffic on ephemeral ports (57xxx range)
- System framework directory scanning

## 9. Response Actions Taken

### Immediate Response
1. Downloaded DMG to quarantined analysis laptop (no secrets/credentials)
2. Prevented execution through security controls
3. Conducted static analysis in isolated environment
4. Extracted and decoded all stages safely

### Intelligence Gathering
1. Social engineering of threat actor
2. Infrastructure mapping
3. Victim scope assessment
4. TTPs documentation

### Containment
1. Samples submitted to VirusTotal
2. IOCs shared with security community
3. Detection rules created (YARA, Suricata)
4. Documentation published

## 10. Recommendations

### Short-term
1. Block identified domains at perimeter
2. Hunt for IOCs across environment
3. User awareness bulletin on campaign
4. Verify Gatekeeper enabled on all macOS systems

### Medium-term
1. Implement application allowlisting
2. Enhanced monitoring for AppleScript abuse
3. Regular phishing simulation training
4. Review third-party app installation policies

### Long-term
1. Zero-trust architecture implementation
2. Enhanced EDR deployment on macOS
3. Behavioral analytics for anomaly detection
4. Supply chain security program

## 11. Lessons Learned

### What Worked
- Security awareness training (domain verification)
- macOS native security controls (Gatekeeper)
- Incident response procedures
- Threat intelligence gathering

### Areas for Improvement
- Earlier detection of impersonation attempts
- Automated IOC extraction and sharing
- Cross-platform threat hunting capabilities

## 12. Detection Engineering

### YARA Rules
```yara
rule Amos_Streamyard_Campaign {
    meta:
        description = "Detects Amos InfoStealer StreamYard campaign"
        date = "2025-09-12"
        threat = "Amos InfoStealer"
        
    strings:
        $bash = "#!/bin/bash"
        $xor_key = "97bccf63605c587186ef47c30b101d78"
        $eval = "eval \"$oVGpzC\""
        $as1 = "set diskList to list disks"
        $as2 = "xattr -c"
        $as3 = "/tmp/.Streamyard"
        
    condition:
        ($bash and $xor_key and $eval) or
        (2 of ($as*))
}
```

### Suricata Rule
```
alert http any any -> any any (
  msg:"Amos StreamYard Campaign C2";
  flow:to_client,established;
  http.host; content:"lefenari.com";
  http.uri; content:"/load.";
  http.uri; content:"call=stream";
  classtype:trojan-activity;
  sid:2025091201; rev:1;
)
```

## 13. Appendices

### A. Technical Artifacts
- Full malware samples (quarantined)
- Decoded Stage2 AppleScript
- Network packet captures
- System logs

### B. References
- Amos InfoStealer analysis reports
- macOS security documentation
- MITRE ATT&CK framework mappings

### C. Contact Information
- Security Operations Center: [REDACTED]
- Incident Response Team: [REDACTED]
- Threat Intelligence: [REDACTED]

---

**Classification**: TLP:CLEAR  
**Distribution**: Public  
**Version**: 1.1  
**Last Updated**: September 13, 2025