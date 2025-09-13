#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and decode Stage2 AppleScript from Streamyard.KPi
# 1) Extract concatenated Base64 payload
# 2) Base64-decode, XOR with fixed key 0x97bccf63605c587186ef47c30b101d78
# 3) Base64-decode result to plain-text AppleScript

KPI_PATH="${1:-streamyard_forensics_20250912_114516/artifacts/mounted_copy/Streamyard.KPi}"
OUT_DIR="${2:-streamyard_forensics_20250912_114516/analysis}"

mkdir -p "$OUT_DIR"

AWK_SCRIPT="$(mktemp)"
cat > "$AWK_SCRIPT" << 'AWK'
BEGIN{RS="\n"}
/^[A-Za-z0-9_]+='[^']*'/ {
  split($0,a,"='"); name=a[1]; val=substr($0, index($0,"='")+2); sub(/'$/,"",val); vars[name]=val;
}
/^hJmyuI="/ {
  s=$0; sub(/^hJmyuI="/,"",s); sub(/"$/,"",s);
  out=s;
  while (match(out,/\$\{[A-Za-z0-9_]+\}/)) {
    pre=substr(out,1,RSTART-1);
    nm=substr(out,RSTART+2,RLENGTH-3);
    post=substr(out,RSTART+RLENGTH);
    out=pre vars[nm] post;
  }
  print out;
}
AWK

L1_B64="$OUT_DIR/Streamyard.stage2.layer1.b64"
FINAL_TXT="$OUT_DIR/Streamyard.Stage2.applescript"

awk -f "$AWK_SCRIPT" "$KPI_PATH" > "$L1_B64"

KEY_HEX=97bccf63605c587186ef47c30b101d78

base64 -d "$L1_B64" | \
perl -we '
  use strict; use warnings;
  binmode STDIN; binmode STDOUT;
  my $key = pack("H*", shift @ARGV);
  local $/; my $d = <STDIN>;
  my $kl = length($key);
  my $o = "";
  for (my $i=0; $i<length($d); $i++) {
    $o .= chr( ord(substr($d,$i,1)) ^ ord(substr($key,$i%$kl,1)) );
  }
  print $o;
' "$KEY_HEX" | base64 -d > "$FINAL_TXT"

echo "Recovered AppleScript: $FINAL_TXT"
echo "Intermediate Base64:   $L1_B64"

