#!/usr/bin/env bash
set -euo pipefail

# Usage: bash streamyard_autotriage.sh /path/to/Streamyard.dmg
DMG="${1:-$HOME/Downloads/Streamyard.dmg}"
if [[ ! -f "$DMG" ]]; then
  echo "DMG not found: $DMG" >&2; exit 1
fi

# Output structure
TS="$(date +%Y%m%d_%H%M%S)"
CASE_ROOT="$HOME/Desktop/streamyard_forensics_$TS"
ART="$CASE_ROOT/artifacts"; ORIG="$ART/originals"; VOLCOPY="$ART/mounted_copy"
ANAL="$CASE_ROOT/analysis"; LOGS="$CASE_ROOT/logs"; RULES="$CASE_ROOT/yara"
mkdir -p "$ORIG" "$VOLCOPY" "$ANAL" "$LOGS" "$RULES"

# Helper
_has() { command -v "$1" >/dev/null 2>&1; }

echo "[*] Copy DMG and metadata"
cp -p "$DMG" "$ORIG/"
shasum -a 256 "$DMG" | tee "$ANAL/dmg.sha256.txt"
md5 "$DMG" | tee "$ANAL/dmg.md5.txt" >/dev/null
hdiutil imageinfo "$DMG" | tee "$ANAL/dmg.imageinfo.txt"
mdls -name kMDItemWhereFroms "$DMG" | tee "$ANAL/dmg.wherefroms.txt"
xattr -l "$DMG" | tee "$ANAL/dmg.xattr.txt"

echo "[*] Attach DMG read-only, noverify, noautoopen"
ATTACH_OUT="$(hdiutil attach -readonly -noverify -noautoopen "$DMG")"
echo "$ATTACH_OUT" | tee "$ANAL/hdiutil.attach.txt"
MNT="$(echo "$ATTACH_OUT" | awk '/\/Volumes\//{print $3}' | head -n1)"
if [[ -z "$MNT" || ! -d "$MNT" ]]; then echo "Mount failed" >&2; exit 1; fi
echo "Mounted at: $MNT" | tee "$ANAL/mountpoint.txt"

echo "[*] List and copy mounted contents (no execution)"
ls -la "$MNT" | tee "$ANAL/volume.ls.txt"
# Use ditto to preserve metadata; works on macOS base
ditto "$MNT" "$VOLCOPY"

echo "[*] Characterize copied files"
find "$VOLCOPY" -type f -print0 | while IFS= read -r -d '' f; do
  rel="${f#$VOLCOPY/}"
  {
    echo "### $rel"
    shasum -a 256 "$f"
    md5 "$f"
    file "$f"
    xattr -l "$f" 2>/dev/null || true
    echo
  } | tee -a "$ANAL/files.characterization.txt" >/dev/null
done

# Identify expected payloads
BIN="$VOLCOPY/.Streamyard"
KPI="$VOLCOPY/Streamyard.KPi"
TERMFILE="$VOLCOPY/Terminal"

# Static on payloads if present
for f in "$BIN" "$KPI"; do
  [[ -f "$f" ]] || continue
  base="$(basename "$f")"
  echo "[*] Static: $base"
  file "$f" | tee "$ANAL/${base}.file.txt"
  /usr/bin/otool -L "$f" 2>/dev/null | tee "$ANAL/${base}.otool_L.txt" >/dev/null || true
  /usr/bin/otool -l "$f" 2>/dev/null | sed -n '1,200p' | tee "$ANAL/${base}.otool_l.head.txt" >/dev/null || true
  strings -a "$f" | tee "$ANAL/${base}.strings.txt" >/dev/null
  egrep -i 'https?://|[0-9]{1,3}(\.[0-9]{1,3}){3}|curl|wget|osascript|launchd|/Library/Launch|~/Library/Launch|base64|eval|chmod|crontab|ssh|sudo|/tmp/|\.php|\.onion' \
    "$ANAL/${base}.strings.txt" | sort -u | tee "$ANAL/${base}.ioc_candidates.txt" >/dev/null || true
done

# Decode Stage 2 from Streamyard.KPi if present
STAGE2_OUT="$ANAL/Streamyard.stage2.decoded"
if [[ -f "$KPI" ]]; then
  echo "[*] Attempt Stage2 decode from Streamyard.KPi"
  PAYLOAD="$(awk '
    /^(wYCvQxcd|CJcrePhM|nqnffPBX|fxtuZitv|NCRIMPcG|OYIxNiTC|jwlxIEhU|WIuHAudX|NsQplFmA|DhPFwcls|RPpxYZNl|zRcRhaWq|JvlpiBVK|XzRuoTbv|HTFQhQpj|HtMoFlnt|iAqeolom|OESYDzSb|qYTDwqFA|MNRMHBTf)=/ {
      gsub(/^.*='\''?/, "", $0); gsub(/'\''?$/, "", $0); printf "%s", $0
    }' "$KPI")"
  if [[ -n "${PAYLOAD:-}" ]]; then
    printf "%s" "$PAYLOAD" | base64 --decode | \
    perl -we 'binmode(STDIN); binmode(STDOUT);
      my $key=pack("H*","97bccf63605c587186ef47c30b101d78");
      my $d=do{local $/; <STDIN>};
      my $o=""; for(my $i=0; $i<length($d); $i++){ $o.=chr(ord(substr($d,$i,1)) ^ ord(substr($key,$i%length($key),1))); }
      print $o;' > "$STAGE2_OUT" || true
    if [[ -s "$STAGE2_OUT" ]]; then
      echo "[*] Stage2 decoded -> $STAGE2_OUT"
      file "$STAGE2_OUT" | tee "$ANAL/Streamyard.stage2.file.txt"
      shasum -a 256 "$STAGE2_OUT" | tee "$ANAL/Streamyard.stage2.sha256.txt"
      strings -a "$STAGE2_OUT" | egrep -i 'https?://|/Library/Launch|~/Library/Launch|curl|wget|osascript|base64|eval|chmod|crontab|ssh|sudo|/tmp/|\.php|\.onion|[0-9]{1,3}(\.[0-9]{1,3}){3}' \
        | sort -u | tee "$ANAL/Streamyard.stage2.ioc_candidates.txt" >/dev/null || true
      egrep -ao 'https?://[^"'"'"' <>]+' "$STAGE2_OUT" | sort -u | tee "$ANAL/stage2.urls.txt" >/dev/null || true
      egrep -ao '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$STAGE2_OUT" | sort -u | tee "$ANAL/stage2.ips.txt" >/dev/null || true
      egrep -ao '/(Library|Users)/[^"'"'"' ]+' "$STAGE2_OUT" | sort -u | tee "$ANAL/stage2.paths.txt" >/dev/null || true
      egrep -ao '(curl|wget|osascript|launchctl|plutil|chmod|crontab|ssh|sudo)[^"'"'"' ]*' "$STAGE2_OUT" | sort -u | tee "$ANAL/stage2.execs.txt" >/dev/null || true
    else
      echo "[*] Stage2 decode produced no output"
    fi
  else
    echo "[*] No embedded base64 variables found in KPi"
  fi
fi

echo "[*] System logs around quarantine and DiskImageMounter (3h)"
log show --last 3h --style syslog --predicate 'eventMessage CONTAINS[c] "quarantine" OR process == "DiskImageMounter" OR process == "CoreServicesUIAgent"' \
  | tee "$LOGS/quarantine_and_dmg_3h.log" >/dev/null || true

echo "[*] Check for processes executing from the mount (should be empty)"
lsof +D "$MNT" 2>/dev/null | tee "$ANAL/lsof_volume.txt" >/dev/null || true

echo "[*] Snapshot persistence dirs and Login Items"
{ ls -lt ~/Library/LaunchAgents 2>/dev/null; ls -lt /Library/LaunchAgents 2>/dev/null; ls -lt /Library/LaunchDaemons 2>/dev/null; } \
  | tee "$ANAL/persistence_dirs.ls.txt" >/dev/null
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
  | tee "$ANAL/login_items.txt" >/dev/null
find "$HOME/Downloads" -maxdepth 1 -ctim
