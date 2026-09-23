#!/usr/bin/env bash
# SR-002 / SC-007: no PowerDNS or Recursor API key (nor any private key) in
# any captured output. The security suite drives every service path with the
# sentinel keys DNS-MARKER-KEY-* against hostile PowerDNS stubs that echo the
# key, and writes everything it observed (responses, errors, logs, audit rows,
# events) to $FREYA_CAPTURE_DIR; the tagged integration suite (real PowerDNS
# containers, when present) is captured as well.
set -euo pipefail
ART="${ARTIFACTS:-.artifacts}"; export FREYA_CAPTURE_DIR="$ART/capture"; mkdir -p "$FREYA_CAPTURE_DIR"
find "$FREYA_CAPTURE_DIR" -type f -name '*.log' -delete
go test -count=1 ./tests/security/... -v > "$ART/security.log" 2>&1 || { tail -50 "$ART/security.log"; exit 1; }
cp "$ART/security.log" "$FREYA_CAPTURE_DIR/security-suite.log"
if compgen -G "tests/integration/*_test.go" > /dev/null; then
  go test -count=1 -tags integration ./tests/integration/... -v > "$ART/integration.log" 2>&1 || { tail -50 "$ART/integration.log"; exit 1; }
  cp "$ART/integration.log" "$FREYA_CAPTURE_DIR/integration-suite.log"
fi
# The suite log itself names the sentinel prefix only in source identifiers,
# never a key value: scan for the full sentinel pattern.
n=0; for pat in 'DNS-MARKER-KEY-[a-z]' '-----BEGIN [A-Z ]*PRIVATE KEY-----'; do
  c=$({ grep -rcE -- "$pat" "$FREYA_CAPTURE_DIR" || true; } | awk -F: '{s+=$2} END {print s+0}'); echo "redaction-scan: '$pat': $c"; n=$((n+c)); done
[[ "$n" -eq 0 ]] || { echo "redaction-scan: FAIL ($n matches)" >&2; exit 1; }; echo "redaction-scan: 0 matches"
