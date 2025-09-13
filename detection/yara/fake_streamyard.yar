rule Fake_Streamyard_KPi_Loader {
  meta:
    description = "Fake StreamYard macOS loader (Bash, XOR key, base64 eval)"
    date = "2025-09-12"
    dmg_sha256 = "97cdf485b242daf345d9bf55a3cf38ce025de9eef40d26a29c829ae769d5919c"
    kpi_sha256 = "0b96c2efd47fe7801a4300c21f4ee8dd864aa499b2e68cd82649919445368edf"
  strings:
    $sh = "#!/bin/bash" ascii
    $s1 = "eval \"$oVGpzC\"" ascii
    $s2 = "YVUJYC() { echo \"$1\" | base64 --decode; }" ascii
    $key = "97bccf63605c587186ef47c30b101d78" ascii
  condition:
    $sh and all of ($s*) and $key
}

rule Fake_Streamyard_Stage2_AppleScript {
  meta:
    description = "Stage2 AppleScript copies .Streamyard, clears quarantine, executes"
    date = "2025-09-12"
    stage2_sha256 = "ffedeeceee860b9f6f37675f604fbf6754734e9402cfb1e786a928f826054167"
  strings:
    $a1 = "set diskList to list disks" ascii
    $a2 = "set appName to \".Streamyard\"" ascii
    $a3 = "xattr -c " ascii
    $a4 = "chmod +x " ascii
    $a5 = "do shell script quoted form of tempAppPath" ascii
  condition:
    all of ($a*)
}

rule Fake_Streamyard_Payload_MachO {
  meta:
    description = "Hidden .Streamyard Mach-O fat payload (hash-specific)"
    date = "2025-09-12"
    payload_sha256 = "bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2"
  condition:
    sha256(0, filesize) == "bb364083b01ce851b33fa2ba121603322d6a700e984f947a349f010502ef79f2"
}
