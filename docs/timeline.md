## Timeline of Events (All times September 12, 2025, CST)

- **10:20–10:52**  
  - macOS Gatekeeper quarantine events logged.  
  - `parsec-fbf` sandbox denials when the downloaded file attempted lookups against `com.apple.coreservices.quarantine-resolver`.

- **10:46–10:58**  
  - Disk image operations recorded.  
  - `DiskImageMounter` attaches `Streamyard.dmg` in quarantine.  
  - Mounted volume created under `/Volumes/Streamyard`.  
  - Quarantine flag applied to the mounted image.  
  - CoreServices UI prompts displayed.

- **10:57–11:00**  
  - User interaction with the mounted volume.  
  - Files present: `.Streamyard`, `Streamyard.KPi`, `Terminal`, `.VolumeIcon.icns`, `.background/H7sZmmAcYO.png`.  
  - Attempt made to drag into Terminal; macOS prevented execution.

- **11:02**  
  - User ran log review (`log show --last 1h | grep quarantine`).  
  - Confirmed that Gatekeeper blocked execution and sandbox denied the binary.

- **11:06–11:13**  
  - Forensic analysis initiated.  
  - Mount path confirmed.  
  - `.Streamyard` identified as Mach-O universal binary.  
  - `Streamyard.KPi` identified as a Bash loader script.  
  - XOR key discovered: `97bccf63605c587186ef47c30b101d78`.

- **11:14–11:20**  
  - Stage2 payload extracted from `Streamyard.KPi`.  
  - Base64 decoded and XOR decrypted into `Streamyard.stage2.decoded`.  
  - File classified as ASCII text script with long encoded lines.  
  - Stage2 SHA256: `ffedeeceee860b9f6f37675f604fbf6754734e9402cfb1e786a928f826054167`.

- **11:20–11:45**  
  - IOC extraction performed on Stage2.  
  - No cleartext URLs or IPs surfaced in first pass (still obfuscated).  
  - Execution flow: Stage1 (KPi script) → decode Stage2 → eval.  
  - YARA rules authored for Stage1 and Stage2.

- **11:45 onward**  
  - Comprehensive triage script (`streamyard_autotriage.sh`) built and executed.  
  - Case folder generated: `~/Desktop/streamyard_forensics_<timestamp>`.  
  - IOC_SUMMARY.txt and encrypted `streamyard_forensics.zip` created.  
  - All artifacts preserved for submission to VirusTotal and sharing with DFIR teams.
