#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# openbao — Raft snapshot save / restore, run by the snapshot Job
# (templates/snapshot-job.yaml.j2) in openbao_backup_namespace.
#
#   /bin/sh snapshot.sh save      write $OB_SNAPSHOT_DIR/openbao-<sha256>.snap, then
#                                 point openbao.snap.sha256 at it (one atomic rename)
#   /bin/sh snapshot.sh restore   force-restore the file openbao.snap.sha256 names,
#                                 after checking its sha256
#
# The checksum file is the only pointer: "<sha256>  <file>". A save writes the
# new snapshot under its own name, renames the pointer over the old one and only
# then deletes the old snapshot, so a crash leaves a consistent old or new pair.
#
# Logs in with the Job's projected ServiceAccount token (OB_JWT_FILE, audience
# openbao_auth_audience) as Kubernetes-auth role OB_ROLE ('backup', AD-7: read on
# sys/storage/raft/snapshot, update on sys/storage/raft/snapshot-force). The
# OpenBao token lives only in the shell variable TOKEN and reaches each bao call
# as BAO_TOKEN in that child's environment; it is never printed, written or put
# in argv, and it is revoked on exit. The JWT is passed as jwt=@file.
# The snapshot itself is encrypted by OpenBao's barrier: restoring it needs the
# unseal keys of the cluster that took it.
#
# Env: BAO_ADDR, BAO_CACERT (set by the Job), OB_AUTH_MOUNT, OB_ROLE, OB_JWT_FILE,
# OB_SNAPSHOT_DIR.
# Output: one JSON line on stdout (last line of the Job log):
#   {"result":"saved|restored|failed","stage":"...","error":"...","bytes":N,"sha256":"...",
#    "file":"openbao-<sha256>.snap","sealed":true|false|null}
# Exit: 0 success, 1 failure.

set -u
set -f
umask 077

MODE=${1:-}
OB_AUTH_MOUNT=${OB_AUTH_MOUNT:-kubernetes}
OB_ROLE=${OB_ROLE:-backup}
OB_JWT_FILE=${OB_JWT_FILE:-/var/run/secrets/openbao/token}
OB_SNAPSHOT_DIR=${OB_SNAPSHOT_DIR:-/snapshots}
BAO_CLIENT_TIMEOUT=${BAO_CLIENT_TIMEOUT:-300s}
export BAO_CLIENT_TIMEOUT
unset BAO_TOKEN

SUM=$OB_SNAPSHOT_DIR/openbao.snap.sha256
TMP=$OB_SNAPSHOT_DIR/.openbao.snap.tmp

RESULT=failed
STAGE=start
ERR=
BYTES=0
SHA=
SEALED=null
TOKEN=
FILE=

log() { printf 'openbao-snapshot: %s\n' "$*" >&2; }
jstr() { printf '%s' "$1" | tr '\n\r\t' '   ' | tr -d '\000-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

finish() {
	if [ -n "$TOKEN" ]; then
		# After a restore the token store is the snapshot's: this token (issued
		# later) no longer exists, so a failed revoke is expected there.
		BAO_CLIENT_TIMEOUT=10s BAO_TOKEN="$TOKEN" bao token revoke -self >/dev/null 2>&1 ||
			[ "$MODE" = restore ] || log "revoke of the job token failed (it expires with its TTL)"
		TOKEN=
	fi
	rm -f "$TMP" "$SUM.tmp"
	printf '{"result":"%s","stage":"%s","error":"%s","bytes":%s,"sha256":"%s","file":"%s","sealed":%s}\n' \
		"$(jstr "$RESULT")" "$(jstr "$STAGE")" "$(jstr "$ERR")" "${BYTES:-0}" "$(jstr "$SHA")" "$(jstr "${FILE##*/}")" "$SEALED"
	[ "$RESULT" = failed ] && exit 1
	exit 0
}
trap finish EXIT
trap 'ERR="interrupted by signal"; exit 1' HUP INT TERM

fail() {
	ERR=$*
	RESULT=failed
	log "$ERR"
	exit 1
}

# with_token <bao args...>: one bao call with the job token in its environment;
# on failure keep the last lines of its error text (bao never echoes the token).
with_token() {
	if ! e=$(BAO_TOKEN="$TOKEN" bao "$@" 2>&1 >/dev/null); then
		ERR="$STAGE: $(printf '%s' "$e" | grep -v '^ *$' | tail -n 3)"
		log "$ERR"
		return 1
	fi
}

login() {
	STAGE=login
	[ -r "$OB_JWT_FILE" ] || fail "no ServiceAccount token at $OB_JWT_FILE"
	errf=$(mktemp) || fail "cannot create a temp file"
	if ! TOKEN=$(BAO_CLIENT_TIMEOUT=30s bao write -field=token "auth/$OB_AUTH_MOUNT/login" role="$OB_ROLE" jwt=@"$OB_JWT_FILE" 2>"$errf"); then
		TOKEN=
		e=$(grep -v '^ *$' "$errf" | tail -n 3)
		rm -f "$errf"
		fail "login as role $OB_ROLE on auth/$OB_AUTH_MOUNT failed: $e"
	fi
	rm -f "$errf"
	[ -n "$TOKEN" ] || fail "login as role $OB_ROLE returned no token"
}

seal_state() {
	flat=$(bao status -format=json 2>/dev/null | tr -d ' \n\r\t')
	case "$flat" in
	*'"sealed":false'*) SEALED=false ;;
	*'"sealed":true'*) SEALED=true ;;
	*) SEALED=null ;;
	esac
}

save() {
	STAGE=check
	[ -d "$OB_SNAPSHOT_DIR" ] && [ -w "$OB_SNAPSHOT_DIR" ] || fail "$OB_SNAPSHOT_DIR is not a writable directory"
	login
	STAGE=save
	rm -f "$TMP" "$SUM.tmp"
	with_token operator raft snapshot save "$TMP" || exit 1
	[ -s "$TMP" ] || fail "the snapshot is empty"
	STAGE=checksum
	SHA=$(sha256sum "$TMP" | cut -d' ' -f1)
	BYTES=$(wc -c <"$TMP" | tr -d ' ')
	new=openbao-$SHA.snap
	old=$(cut -s -d' ' -f3 "$SUM" 2>/dev/null)
	mv -f "$TMP" "$OB_SNAPSHOT_DIR/$new" || fail "could not move the snapshot into place"
	printf '%s  %s\n' "$SHA" "$new" >"$SUM.tmp"
	sync
	# The pointer switches in one rename; the old snapshot goes only after it.
	mv -f "$SUM.tmp" "$SUM" || fail "could not update $SUM"
	sync
	case "$old" in openbao-*.snap) [ "$old" != "$new" ] && rm -f "$OB_SNAPSHOT_DIR/$old" ;; esac
	FILE=$OB_SNAPSHOT_DIR/$new
	seal_state
	STAGE=done
	RESULT=saved
}

restore() {
	STAGE=check
	[ -s "$SUM" ] || fail "no checksum file $SUM (was the PVC restored from the backup?)"
	want=$(cut -d' ' -f1 "$SUM")
	name=$(cut -s -d' ' -f3 "$SUM")
	case "$name" in openbao-*.snap) ;; *) fail "$SUM names no snapshot file ('$name')" ;; esac
	FILE=$OB_SNAPSHOT_DIR/$name
	[ -s "$FILE" ] || fail "no snapshot at $FILE"
	SHA=$(sha256sum "$FILE" | cut -d' ' -f1)
	BYTES=$(wc -c <"$FILE" | tr -d ' ')
	[ "$SHA" = "$want" ] || fail "checksum mismatch: $FILE is $SHA, $SUM says $want; refusing to restore"
	login
	STAGE=restore
	# -force: the backup policy grants only sys/storage/raft/snapshot-force; it also
	# accepts a snapshot of another keyring (OpenBao then seals: unseal with the
	# shares of the cluster that took the snapshot).
	with_token operator raft snapshot restore -force "$FILE" || exit 1
	STAGE=status
	i=0
	while [ "$i" -lt 15 ]; do
		sleep 2
		i=$((i + 1))
		seal_state
		[ "$SEALED" != null ] && break
	done
	STAGE=done
	RESULT=restored
}

case "$MODE" in
save) save ;;
restore) restore ;;
*) STAGE=params; fail "unknown mode '$MODE' (save | restore)" ;;
esac
exit 0
