#!/usr/bin/env bash
set -euo pipefail

# Safe, read-only triage to verify no execution/persistence occurred.
# Creates a small report folder and collects outputs.

TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="$HOME/Desktop/streamyard_hostcheck_${TS}"
mkdir -p "$OUTDIR/logs" "$OUTDIR/analysis"

echo "[+] Writing results to: $OUTDIR"

echo "[+] Check for payload at /tmp/.Streamyard"
{
  date
  if [[ -e /tmp/.Streamyard ]]; then
    echo "FOUND /tmp/.Streamyard"; ls -la /tmp/.Streamyard || true
    echo "Quarantine xattr:"; xattr -p com.apple.quarantine /tmp/.Streamyard 2>&1 || true
    echo "File info:"; file /tmp/.Streamyard || true
    echo "Hash:"; shasum -a 256 /tmp/.Streamyard || true
  else
    echo "NOT FOUND: /tmp/.Streamyard"
  fi
} | tee "$OUTDIR/analysis/tmp_dot_streamyard.txt"

echo "[+] Search common locations for stray '.Streamyard'"
{
  date
  find /tmp /private/tmp "$HOME" -maxdepth 3 -type f -name '.Streamyard' -ls 2>/dev/null || true
} | tee "$OUTDIR/analysis/search_dot_streamyard.txt"

echo "[+] List LaunchAgents/Daemons; grep for suspicious content"
{
  date
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    echo "## $d"; ls -lt "$d" 2>/dev/null || true
  done
} | tee "$OUTDIR/analysis/persistence_dirs.txt"

grep -HnEi '(/tmp/|xattr -c|chmod +x|osascript|curl|wget|base64|\.Streamyard)' \
  "$HOME/Library/LaunchAgents"/*.plist \
  /Library/LaunchAgents/*.plist \
  /Library/LaunchDaemons/*.plist 2>/dev/null \
  | tee "$OUTDIR/analysis/persistence_grep.txt" >/dev/null || true

echo "[+] Login Items (System Events)"
osascript -e 'tell application "System Events" to get the name of every login item' \
  | tee "$OUTDIR/analysis/login_items.txt" >/dev/null || true

echo "[+] lsof for processes under /Volumes/Streamyard or /tmp/.Streamyard"
{
  date
  lsof +D /Volumes/Streamyard 2>/dev/null || true
  lsof /tmp/.Streamyard 2>/dev/null || true
} | tee "$OUTDIR/analysis/lsof_checks.txt"

echo "[+] Unified logs (last 48h) for osascript/xattr/chmod/.Streamyard/spctl"
log show --last 48h --style syslog \
  --predicate 'process == "osascript" OR process == "spctl" OR eventMessage CONTAINS[c] ".Streamyard" OR eventMessage CONTAINS[c] "xattr -c" OR eventMessage CONTAINS[c] "chmod +x" OR eventMessage CONTAINS[c] "/tmp/.Streamyard"' \
  | tee "$OUTDIR/logs/host_validation_48h.log" >/dev/null || true

echo "[+] Gatekeeper/XProtect events (last 48h)"
log show --last 48h --style syslog \
  --predicate 'process == "CoreServicesUIAgent" OR process == "syspolicyd" OR process == "XProtect" OR processImagePath CONTAINS[c] "CoreServicesUIAgent"' \
  | tee "$OUTDIR/logs/gatekeeper_48h.log" >/dev/null || true

echo "[+] Done. Review $OUTDIR for results."
