#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# openbao — reload the listener certificate after cert-manager renewed it.
#
# OpenBao reads tls_cert_file only at start and on SIGHUP. cert-manager renews
# the server Secret, the kubelet updates the mounted files, and the running
# server keeps serving the old certificate until it expires. This script finds
# out which certificate is served and sends SIGHUP to the bao server process
# when it is not the mounted one. Shipped in the bootstrap ConfigMap; POSIX sh,
# busybox and the bao CLI only (all in the server image). No secret is read.
#
#   /bin/sh tls-reload.sh check            print current | stale | unreachable | nocert
#   /bin/sh tls-reload.sh reload-if-stale  check; SIGHUP if stale; print
#                                          current | reloaded | unreachable | nocert | failed
#   /bin/sh tls-reload.sh watch            reload-if-stale every OB_TLS_INTERVAL s
#                                          (the tls-reloader sidecar; logs changes)
#
# How "served" is found: `bao status -ca-cert=<leaf>` with only the mounted leaf
# certificate as trust anchor succeeds (exit 0 unsealed, 2 sealed) only when the
# server presents exactly that certificate. Otherwise a probe without
# verification tells "answers with another certificate" (stale: an older one,
# also an expired one or one from a rotated CA) from "nothing answers".
# nocert: the mounted tls.crt holds no certificate (a broken mount).
#
# Env: OB_TLS_DIR (tls.crt and ca.crt), OB_TLS_ADDR (default https://127.0.0.1:8200,
# a SAN of the server cert), OB_TLS_INTERVAL (watch period, seconds).
# Exit: 0 current/reloaded, 1 failed/unreachable (check: 1 stale/unreachable).

set -u
set -f
umask 077

MODE=${1:-check}
OB_TLS_DIR=${OB_TLS_DIR:-/openbao/userconfig/openbao-server-tls}
OB_TLS_ADDR=${OB_TLS_ADDR:-https://127.0.0.1:8200}
OB_TLS_INTERVAL=${OB_TLS_INTERVAL:-60}
BAO_CLIENT_TIMEOUT=${BAO_CLIENT_TIMEOUT:-5s}
export BAO_CLIENT_TIMEOUT
# Probes are unauthenticated: never send a token from the environment.
unset BAO_TOKEN

log() { printf 'openbao-tls-reload: %s\n' "$*" >&2; }

TMPD=$(mktemp -d 2>/dev/null) || { log "cannot create a temp dir"; exit 1; }
trap 'rm -rf "$TMPD"' EXIT
trap 'exit 1' HUP INT TERM
LEAF=$TMPD/leaf.pem

# probe <ca file>: the server answered a TLS handshake verified against it.
probe() {
	bao status -address="$OB_TLS_ADDR" -ca-cert="$1" >/dev/null 2>&1
	case $? in 0 | 2) return 0 ;; *) return 1 ;; esac
}

# probe_any: the server answers at all (no verification: an unauthenticated
# seal-status read, no credential is sent).
probe_any() {
	bao status -address="$OB_TLS_ADDR" -tls-skip-verify >/dev/null 2>&1
	case $? in 0 | 2) return 0 ;; *) return 1 ;; esac
}

# state: current | stale | unreachable | nocert (current = the mounted leaf is served).
state() {
	# The first PEM block of tls.crt is the leaf (any chain follows it).
	if ! awk '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if(n==1) exit}' \
		"$OB_TLS_DIR/tls.crt" >"$LEAF" 2>/dev/null || ! grep -q 'END CERTIFICATE' "$LEAF"; then
		echo nocert
		log "no certificate in $OB_TLS_DIR/tls.crt"
		return
	fi
	if probe "$LEAF"; then
		echo current
	elif probe_any; then
		echo stale
	else
		echo unreachable
	fi
}

# The bao server process(es): `bao status` probes (ours, the readiness probe)
# are bao processes too, so match the command line.
server_pids() {
	for p in $(pidof bao 2>/dev/null); do
		if tr '\000' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -Eq '(^|/)bao server'; then
			printf '%s\n' "$p"
		fi
	done
}

reload_if_stale() {
	s=$(state)
	[ "$s" = stale ] || { echo "$s"; [ "$s" = current ]; return; }
	pids=$(server_pids)
	if [ -z "$pids" ]; then
		echo failed
		log "served certificate is stale, but no 'bao server' process is visible"
		return 1
	fi
	for p in $pids; do kill -HUP "$p" 2>/dev/null || log "SIGHUP to $p failed"; done
	i=0
	while [ "$i" -lt 10 ]; do
		sleep 1
		i=$((i + 1))
		# The files may have changed again right after the signal (a renewal
		# racing the reload): signal once more halfway through.
		if [ "$i" -eq 5 ] && [ "$(state)" = stale ]; then
			for p in $pids; do kill -HUP "$p" 2>/dev/null; done
		fi
		if [ "$(state)" = current ]; then
			echo reloaded
			log "served certificate was stale; sent SIGHUP to $(printf '%s' "$pids" | tr '\n' ' ' | sed 's/ *$//') and it now serves the mounted one"
			return 0
		fi
	done
	echo failed
	log "sent SIGHUP but the server still does not serve the mounted certificate"
	return 1
}

case "$MODE" in
check)
	s=$(state)
	echo "$s"
	[ "$s" = current ]
	;;
reload-if-stale)
	reload_if_stale
	;;
watch)
	case "$OB_TLS_INTERVAL" in '' | *[!0-9]*) log "OB_TLS_INTERVAL must be a number of seconds"; exit 1 ;; esac
	[ "$OB_TLS_INTERVAL" -ge 5 ] || OB_TLS_INTERVAL=5
	log "watching $OB_TLS_DIR/tls.crt against $OB_TLS_ADDR every ${OB_TLS_INTERVAL}s"
	last=
	backoff=0
	while :; do
		if [ "$backoff" -gt 0 ]; then
			backoff=$((backoff - 1))
		else
			r=$(reload_if_stale)
			# A SIGHUP that did not help is retried after 3 periods, not every period.
			[ "$r" = failed ] && backoff=3
			[ "$r" != "$last" ] && [ "$r" != reloaded ] && log "state: $r"
			last=$r
		fi
		sleep "$OB_TLS_INTERVAL"
	done
	;;
*)
	log "unknown mode '$MODE' (check | reload-if-stale | watch)"
	exit 1
	;;
esac
