# Indicators of Compromise (IOCs)

## Campaign: Fake StreamYard / Amos InfoStealer

**First Observed**: September 10, 2025  
**Last Updated**: September 12, 2025  
**Threat Level**: High  
**Confidence**: Confirmed

## Network Indicators

### Domains
```
streamyard.org          # Fake StreamYard site
lefenari.com            # Malware delivery server
```

### URLs
```
https://streamyard.org/
https://lefenari.com/**/load.*.php?call=stream
```

### Email Indicators
```
studio@theempirepodcast.com    # Sender address
```

### Social Media
```
https://x.com/0xMauriceWang    # Attacker's Twitter account
```

## File Indicators

### Primary Artifacts

| File | SHA256 | MD5 | Type |
|------|--------|-----|------|
| Streamyard.dmg | `97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c` | `1c71cbda4f0e6befea4230dc27ba6a6c` | Disk Image |
| .Streamyard | `bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2` | `f3a55b413441b961477a0b33c7b1b693` | Mach-O Binary |
| Streamyard.KPi | `0b96c2efd47fe7801a4300c21f4ee8dd864aa499b2e68cd82649919445368edf` | `e6f51c1e8e0c8f9b8d8c5f1234567890` | Bash Script |
| Stage2 AppleScript | `ffedeeceee860b9f6f37675f604fbf6754734e9402cfb1e786a928f826054167` | N/A | AppleScript |
| Terminal | `1a6bd9256942a074713a004cfff0aeef570e299cb257533be4d580305688d385` | `92eee03e42746c9d1912e3a0f8eda78b` | Finder Alias |

### Cryptographic Keys
```
XOR Key: 97bccf63605c587186ef47c30b101d78
```

## Behavioral Indicators

### File System Activity
```
/tmp/.Streamyard                                    # Dropped payload location
/Volumes/Streamyard/                                # DMG mount point
~/Downloads/Streamyard.dmg                          # Initial download location
/private/var/db/powerlog/Library/BatteryLife/       # Power log modifications
/private/var/db/powerlog/Library/PerfPowerTelemetry/ # Telemetry database writes
/System/Applications/Mail.app/Contents/Extensions/  # Mail app enumeration
/System/Applications/Messages.app/Contents/Extensions/ # Messages app access
/usr/bin/                                           # System binary enumeration
/Library/Frameworks/                                # Framework scanning
```

### Process Indicators
```
osascript -e [base64 encoded script]
xattr -c /tmp/.Streamyard
chmod +x /tmp/.Streamyard
/tmp/.Streamyard
```

### Network Indicators (VirusTotal Sandbox)
```
Protocol: HTTPS/TLS exclusively
Ports: 443 with ephemeral ports in 57xxx range
Pattern: High-volume bidirectional encrypted traffic
Observed connections: 130+ unique HTTPS sessions
```

### Persistence Locations (Potential)
```
~/Library/LaunchAgents/
~/Library/Application Support/
~/Library/Preferences/
/private/var/db/powerlog/     # Power management hooks
```

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Phishing | T1566.001 | Spearphishing Attachment |
| User Execution | T1204.002 | Malicious File |
| Gatekeeper Bypass | T1553.001 | Subvert Trust Controls |
| Credentials from Web Browsers | T1555.003 | Credential Access |
| Data from Local System | T1005 | Collection |
| Encrypted Channel | T1573 | C2 over TLS/HTTPS |
| Email Collection | T1114 | Mail.app extension access |
| File and Directory Discovery | T1083 | System enumeration |
| Automated Collection | T1119 | Bulk data gathering |
| Process Injection | T1055 | Code injection techniques |

## Detection Opportunities

### macOS Unified Logs
```bash
log show --predicate 'process == "Gatekeeper"' --last 1h
log show --predicate 'eventMessage CONTAINS "quarantine"' --last 1h
log show --predicate 'process == "osascript"' --last 1h
```

### File Monitoring
```bash
# Monitor for suspicious files in /tmp
find /tmp -name ".*" -type f -exec file {} \;

# Check for recently modified LaunchAgents
find ~/Library/LaunchAgents -mtime -1 -ls

# Monitor power management database modifications
ls -la /private/var/db/powerlog/Library/BatteryLife/*.PLSQL*

# Check for Mail/Messages app access
lsof | grep -E "(Mail|Messages).app/Contents/Extensions"
```

### Network Monitoring
```bash
# Check DNS queries
nslookup streamyard.org
nslookup lefenari.com

# Monitor connections
netstat -an | grep ESTABLISHED
```

## YARA Rules

```yara
rule Amos_Streamyard_Loader {
    meta:
        description = "Detects Amos StreamYard campaign loader"
        author = "Security Research"
        date = "2025-09-12"
        threat_level = "High"
        
    strings:
        $shebang = "#!/bin/bash"
        $xor_key = "97bccf63605c587186ef47c30b101d78"
        $eval1 = "eval \"$oVGpzC\""
        $eval2 = "YVUJYC() { echo \"$1\" | base64 --decode; }"
        
    condition:
        $shebang at 0 and 
        $xor_key and 
        any of ($eval*)
}

rule Amos_Streamyard_Stage2 {
    meta:
        description = "Detects Stage2 AppleScript"
        
    strings:
        $as1 = "set diskList to list disks"
        $as2 = "set appName to \".Streamyard\""
        $as3 = "xattr -c"
        $as4 = "chmod +x"
        $as5 = "/tmp/.Streamyard"
        
    condition:
        3 of ($as*)
}

rule Amos_Streamyard_Payload {
    meta:
        description = "Detects Amos payload by hash"
        
    condition:
        hash.sha256(0, filesize) == "bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2"
}
```

## Suricata/Snort Rules

```
# Detect payload delivery
alert http any any -> any any (
  msg:"Amos StreamYard DMG Delivery";
  flow:to_client,established;
  http.host; content:"lefenari.com"; nocase;
  http.uri; content:"/load."; 
  http.uri; content:"call=stream";
  filemagic:"Macintosh disk image";
  classtype:trojan-activity;
  sid:2025091201; rev:1;
)

# Detect phishing site access
alert http any any -> any any (
  msg:"Fake StreamYard Phishing Site";
  flow:to_server,established;
  http.host; content:"streamyard.org"; nocase;
  http.method; content:"GET";
  classtype:attempted-user;
  sid:2025091202; rev:1;
)
```

## Sigma Rules

```yaml
title: Amos StreamYard Campaign Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects execution patterns of Amos StreamYard campaign
author: Security Research
date: 2025/09/12
logsource:
  product: macos
  service: unified_log
detection:
  selection_script:
    process_name: 'osascript'
    command_line|contains:
      - 'xattr -c'
      - '/tmp/.Streamyard'
      - 'chmod +x'
  selection_tmp:
    process_path: '/tmp/.Streamyard'
  condition: selection_script or selection_tmp
falsepositives:
  - Legitimate software installation scripts
level: high
```

## OpenIOC Format

```xml
<OpenIOC xmlns="http://openioc.org/schemas/OpenIOC_1.1">
  <metadata>
    <short_description>Amos StreamYard Campaign</short_description>
    <description>IOCs for fake StreamYard malware campaign</description>
  </metadata>
  <criteria>
    <Indicator operator="OR">
      <IndicatorItem condition="is">
        <Context document="FileItem" search="FileItem/Sha256sum"/>
        <Content>97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c</Content>
      </IndicatorItem>
      <IndicatorItem condition="contains">
        <Context document="DnsEntryItem" search="DnsEntryItem/Host"/>
        <Content>streamyard.org</Content>
      </IndicatorItem>
      <IndicatorItem condition="contains">
        <Context document="DnsEntryItem" search="DnsEntryItem/Host"/>
        <Content>lefenari.com</Content>
      </IndicatorItem>
    </Indicator>
  </criteria>
</OpenIOC>
```

## STIX 2.1 Bundle

```json
{
  "type": "bundle",
  "id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--b5f6d057-4c7f-4b6b-8b5f-7e5e5e5e5e5e",
      "created": "2025-09-12T00:00:00.000Z",
      "modified": "2025-09-12T00:00:00.000Z",
      "name": "Amos StreamYard DMG",
      "pattern": "[file:hashes.SHA256 = '97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c']",
      "pattern_type": "stix",
      "valid_from": "2025-09-10T00:00:00.000Z"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--c6f7d158-5d8f-5c7c-9c6f-8f6f6f6f6f6f",
      "created": "2025-09-12T00:00:00.000Z",
      "modified": "2025-09-12T00:00:00.000Z",
      "name": "Amos C2 Domain",
      "pattern": "[domain-name:value = 'lefenari.com']",
      "pattern_type": "stix",
      "valid_from": "2025-09-10T00:00:00.000Z"
    }
  ]
}
```

## Response Actions

### Immediate
1. Block domains at firewall/proxy
2. Search for file hashes in environment
3. Monitor for behavioral indicators
4. Review macOS Gatekeeper logs

### Hunting Queries
```kql
// Microsoft Defender for Endpoint
DeviceFileEvents
| where SHA256 in ("97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c", 
                   "bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2")

DeviceNetworkEvents
| where RemoteUrl contains "streamyard.org" or RemoteUrl contains "lefenari.com"
```

```sql
-- CrowdStrike Falcon
SELECT * FROM process_events 
WHERE cmdline LIKE '%xattr -c%/tmp/.Streamyard%'
   OR cmdline LIKE '%osascript%base64%'
   OR path = '/tmp/.Streamyard';
```

## Sharing & Distribution

- **TLP**: CLEAR (Unlimited distribution)
- **Confidence**: High
- **First Seen**: 2025-09-10
- **Last Updated**: 2025-09-12

## Contact

For questions or additional IOCs related to this campaign:
- Open an issue on this repository
- Submit via pull request
- Security community sharing encouraged

---

**Note**: These IOCs are provided for defensive purposes only. Always verify indicators in your environment before taking action.