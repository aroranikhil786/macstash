#!/usr/bin/env bash
# Enforce the invariant that macstash's own code never opens a socket.
#
# The check is by exact package name rather than by prefix. "Anything under net/"
# is the tempting rule and it is wrong in one direction: net/url is pure string
# parsing and opens nothing, so banning it buys no safety and invites the check to
# be weakened later, which is how these guarantees actually die. What matters is
# the packages that can actually reach the network.
set -euo pipefail

DENY='^(net|net/http|net/http/.*|net/smtp|net/rpc|crypto/tls|golang\.org/x/net(/.*)?)$'

found=$(go list -deps ./... | grep -E "$DENY" || true)

if [ -n "$found" ]; then
  echo "FAIL: macstash must not link socket-capable packages, but found:"
  echo "$found" | sed 's/^/  /'
  echo
  echo "macstash promises it never opens a socket. That promise is only worth"
  echo "anything while this check passes."
  exit 1
fi

echo "OK: no socket-capable packages in the import graph."
