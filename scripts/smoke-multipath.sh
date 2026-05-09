#!/usr/bin/env bash
# End-to-end smoke test for G1 fixes.
# Deploys dnstt-server to the test box, runs dnstt-client locally with
# -multipath, and verifies a full HTTP request through the SOCKS5 tunnel.
#
# Asserts the server saw exactly ONE KCP session (not N), proving the
# Task 9 single-ClientID fix works end-to-end.

set -euo pipefail

SERVER_HOST="${SERVER_HOST:-150.241.94.29}"
SERVER_USER="${SERVER_USER:-root}"
DOMAIN="${DOMAIN:-t.ivantopgaming.ru}"
LOCAL_ADDR="${LOCAL_ADDR:-127.0.0.1:7000}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

step()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
fatal() { printf "\033[1;31m!!!\033[0m %s\n" "$*"; exit 1; }

step "Building binaries"
go build -o /tmp/dnstt-server ./dnstt-server
go build -o /tmp/dnstt-client ./dnstt-client

step "Generating throwaway server keypair"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
/tmp/dnstt-server -gen-key -privkey-file "$TMPDIR/server.key" -pubkey-file "$TMPDIR/server.pub" >/dev/null

step "Deploying server binary and key to $SERVER_USER@$SERVER_HOST"
ssh "$SERVER_USER@$SERVER_HOST" "pkill -9 dnstt-server || true; mkdir -p /opt/dnstt"
scp -q /tmp/dnstt-server "$SERVER_USER@$SERVER_HOST:/opt/dnstt/dnstt-server"
scp -q "$TMPDIR/server.key" "$SERVER_USER@$SERVER_HOST:/opt/dnstt/server.key"
ssh "$SERVER_USER@$SERVER_HOST" "chmod 0700 /opt/dnstt/dnstt-server; chmod 0400 /opt/dnstt/server.key"

step "Starting server (background) on $SERVER_HOST in -socks5 mode"
ssh "$SERVER_USER@$SERVER_HOST" \
  "rm -f /opt/dnstt/server.log; nohup /opt/dnstt/dnstt-server -udp :53 -privkey-file /opt/dnstt/server.key -socks5 -log-level debug $DOMAIN >/opt/dnstt/server.log 2>&1 &"
sleep 2
ssh "$SERVER_USER@$SERVER_HOST" "pgrep -a dnstt-server" || fatal "server did not start (check /opt/dnstt/server.log)"

step "Starting client locally with -multipath"
PUBKEY_HEX="$(cat "$TMPDIR/server.pub")"
/tmp/dnstt-client \
  -multipath \
  -doh https://1.1.1.1/dns-query \
  -dot 1.1.1.1:853 \
  -udp 1.1.1.1:53 \
  -pubkey "$PUBKEY_HEX" \
  -log-level info \
  "$DOMAIN" "$LOCAL_ADDR" >/tmp/dnstt-client.log 2>&1 &
CLIENT_PID=$!
trap 'kill -9 $CLIENT_PID 2>/dev/null || true; ssh "$SERVER_USER@$SERVER_HOST" "pkill -9 dnstt-server || true" 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

# Wait for client to bind LOCAL_ADDR.
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if nc -z 127.0.0.1 7000 2>/dev/null; then
    break
  fi
  sleep 1
done
nc -z 127.0.0.1 7000 || fatal "client did not bind $LOCAL_ADDR (see /tmp/dnstt-client.log)"

step "Sending HTTP request through SOCKS5 tunnel"
GOT_IP="$(curl --max-time 60 --proxy "socks5h://$LOCAL_ADDR/" -s https://api.ipify.org || true)"
echo "  got: $GOT_IP"
echo "  expected: $SERVER_HOST"
if [[ "$GOT_IP" != "$SERVER_HOST" ]]; then
  printf -- "----- client log tail -----\n"
  tail -n 20 /tmp/dnstt-client.log || true
  printf -- "----- server log tail -----\n"
  ssh "$SERVER_USER@$SERVER_HOST" "tail -n 20 /opt/dnstt/server.log" || true
  fatal "tunnel produced wrong egress IP - multipath probably broken"
fi

step "Checking server only saw ONE session"
SESSIONS="$(ssh "$SERVER_USER@$SERVER_HOST" "grep -c 'begin session' /opt/dnstt/server.log || true")"
echo "  sessions: $SESSIONS"
if [[ "$SESSIONS" != "1" ]]; then
  printf -- "----- server log -----\n"
  ssh "$SERVER_USER@$SERVER_HOST" "cat /opt/dnstt/server.log"
  fatal "expected exactly one KCP session; got $SESSIONS - multipath ClientID still split"
fi

step "Stopping server"
ssh "$SERVER_USER@$SERVER_HOST" "pkill -9 dnstt-server || true"

step "OK - multipath uses a single ClientID end-to-end"
