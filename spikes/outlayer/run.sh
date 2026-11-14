#!/usr/bin/env bash
# One on-chain lookup through a caller contract. Usage: run.sh <payee> <logfile> [caller|caller2]
# Needs the throwaway account in ~/.near-credentials (legacy keychain). Prints no keys.
set -euo pipefail
O=$(cat /tmp/ol-acct); C=${3:-caller}.$O
bal() { near account view-account-summary "$O" network-config testnet now 2>&1 | grep -i 'native account balance' | head -1 | awk '{print $(NF-1)}'; }
B0=$(bal); T0=$(python3 -c 'import time;print(time.time())')
ARGS=$(jq -cn --arg payee "$1" '{payee: $payee}')
# no `|| true`: a CLI failure (bad args, tx not sent) fails this script. An
# on-chain REJECTED/null result is a successful tx and is logged below.
if ! near contract call-function as-transaction "$C" lookup json-args "$ARGS" \
  prepaid-gas '300 Tgas' attached-deposit '0.1 NEAR' sign-as "$O" network-config testnet \
  sign-with-legacy-keychain send > "$2.raw" 2>&1; then
  sed 's/\x1b\[[0-9;]*m//g' "$2.raw" | grep -vE '/(Users|home)/' >&2; rm -f "$2.raw"
  echo "run.sh: near CLI call failed for payee $ARGS" >&2; exit 1
fi
T1=$(python3 -c 'import time;print(time.time())'); sleep 3; B1=$(bal)
# keep only the tx id, logs and return value; no key material is in this output
sed 's/\x1b\[[0-9;]*m//g' "$2.raw" | grep -E 'Transaction ID|Logs \[|lookup|EVENT_JSON|yNEAR|Execution|return value|^null|^\{|succeeded|failed|Error' | grep -vE '/(Users|home)/' > "$2"; rm "$2.raw"
printf 'wall_seconds=%.1f balance_before=%s balance_after=%s\n' "$(python3 -c "print($T1-$T0)")" "$B0" "$B1" >> "$2"
cat "$2"
