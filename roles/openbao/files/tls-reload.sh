#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# openbao — tls-reloader sidecar: OpenBao reads tls_cert_file only at start and
# on SIGHUP. Every OB_TLS_INTERVAL seconds (min 5) hash $OB_TLS_DIR/tls.crt;
# once after start and whenever the hash changed, SIGHUP every `bao server`
# process (shared process namespace) older than the interval, then confirm the
# local listener serves the mounted leaf. Retried next interval until it does.
# POSIX sh, busybox and the bao CLI (unauthenticated seal-status) only.

set -u
DIR=${OB_TLS_DIR:-/openbao/userconfig/openbao-server-tls}
INTERVAL=${OB_TLS_INTERVAL:-60}
log() { printf 'openbao-tls-reload: %s\n' "$*" >&2; }
case $INTERVAL in '' | *[!0-9]*) log "OB_TLS_INTERVAL '$INTERVAL' is not a number; using 60"; INTERVAL=60 ;; esac
[ "$INTERVAL" -ge 5 ] || INTERVAL=5
unset BAO_TOKEN
export HOME=/tmp BAO_CLIENT_TIMEOUT=5s
LEAF=/tmp/tls-reload-leaf.pem

# The listener presents the mounted leaf (the only trust anchor); 2 = sealed.
served() {
	bao status -address=https://127.0.0.1:8200 -ca-cert="$LEAF" >/dev/null 2>&1
	case $? in 0 | 2) return 0 ;; *) return 1 ;; esac
}

log "watching $DIR/tls.crt every ${INTERVAL}s"
done_hash=
unread=
while :; do
	sleep "$INTERVAL"
	if ! h=$(sha256sum "$DIR/tls.crt" 2>/dev/null); then
		[ -n "$unread" ] || log "cannot read $DIR/tls.crt"
		unread=1
		continue
	fi
	unread=
	[ "$h" = "$done_hash" ] && continue
	# The first PEM block is the leaf (the chain follows it).
	awk '/BEGIN CERTIFICATE/{n++} n==1' "$DIR/tls.crt" >"$LEAF" 2>/dev/null
	grep -q 'END CERTIFICATE' "$LEAF" || { log "no certificate in $DIR/tls.crt; not signalling"; continue; }
	up=$(cut -d. -f1 /proc/uptime)
	sent=
	for p in $(pidof bao 2>/dev/null); do
		# `bao status` probes are bao processes too: match the command line.
		tr '\000' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -Eq '(^|/)bao server' || continue
		# Started less than an interval ago: its SIGHUP handler may not exist yet.
		st=$(awk '{sub(/.*\) /, ""); print int($20 / 100)}' "/proc/$p/stat" 2>/dev/null) || continue
		[ $((up - st)) -ge "$INTERVAL" ] || continue
		kill -HUP "$p" 2>/dev/null && sent="$sent $p"
	done
	[ -n "$sent" ] || { log "no 'bao server' process older than ${INTERVAL}s signalled; retrying"; continue; }
	i=0
	until served || [ "$i" -ge 5 ]; do sleep 1; i=$((i + 1)); done
	if served; then
		done_hash=$h
		log "sent SIGHUP to$sent; the mounted certificate is served"
	else
		log "sent SIGHUP to$sent but the mounted certificate is not served; retrying"
	fi
done
