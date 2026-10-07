#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# openbao — in-pod init, unseal, bootstrap and root revoke.
#
# Shipped in a ConfigMap mounted read-only into every OpenBao server pod and run
# in pod 0 by tasks/bootstrap_exec.yaml (kubernetes.core.k8s_exec), and in
# tests/bootstrap_test.yaml (docker exec). POSIX sh + the bao CLI only.
#
#   /bin/sh bootstrap.sh <status|init|apply> <layer>:<namespace>:<worker_sa> ...
#
#   status  read-only: detect the state of every replica and, when initialized
#           and unsealed, check the bootstrap markers. Never writes anything.
#   init    as status; if (and only if) every replica is uninitialized:
#           1. bao operator init (Shamir, OB_KEY_SHARES / OB_KEY_THRESHOLD)
#           2. unseal pod 0, wait for it to be active, unseal every peer
#           3. bootstrap: KV v2 mount, auth/kubernetes, AD-7 policies and roles,
#              check the stdout file audit device (declared in the server config)
#           4. revoke the root token (EXIT trap, also on failure)
#   apply   re-runnable bootstrap for an initialized, unsealed OpenBao (adding a
#           layer, finishing a partial bootstrap, policy updates): reads a
#           temporary token (generate-root) as the first line of stdin, then
#           converges the KV mount, auth/kubernetes, its config, every AD-7
#           policy and role (creating what is missing, rewriting the rest),
#           checks the audit device, reads every role and policy back, and
#           revokes the token (EXIT trap). Run by the operator, never by the
#           installer: docs/deploy/openbao.md, "Change the bootstrap (generate-root)".
#
# Non-secret inputs only, through env (OB_*, plus the chart's BAO_ADDR and
# BAO_CACERT) and args:
#   OB_KEY_SHARES, OB_KEY_THRESHOLD   Shamir split
#   OB_KV_MOUNT                       KV v2 mount path
#   OB_CLUSTER_ID                     <cluster_id> path segment
#   OB_AUDIENCE                       audience of every Kubernetes-auth role
#   OB_ESO_SA, OB_ESO_NAMESPACE       ESO controller ServiceAccount (eso-<layer>)
#   OB_OPERATOR_SA, OB_OPERATOR_NAMESPACE, OB_OPERATOR_TOKEN_TTL
#   OB_BACKUP_SA, OB_BACKUP_NAMESPACE snapshot Job ServiceAccount
#   OB_PEER_ADDRS                     space-separated API addresses of pods 1..N-1
#   OB_TIMEOUT                        seconds to wait for peers / unseal / active
#   OB_K8S_HOST                       kubernetes_host of auth/kubernetes
#
# Secrets: the root token (init) or the temporary token (apply, read from
# stdin) lives only in the shell variable ROOT of this process.
# It is never printed, written to a file, exported, or put in argv; each bao call
# that needs it gets it as BAO_TOKEN in that one child's environment. The unseal
# shares are sent to sys/unseal on stdin (key=-) and leave the script only in the
# single JSON result line on stdout, which the caller registers with no_log.
#
# Output: exactly one JSON object on stdout (from the EXIT trap):
#   {"state", "stage", "error", "missing", "sealed_pods", "unreachable_pods",
#    "bootstrap_ok", "root_revoked", "root_accessor", "shares"}
#   state: uninitialized | initialized (this run) | ok | missing_bootstrap |
#          sealed | mixed | peer_unreachable | unreachable | init_failed |
#          concurrent_init | bad_params | applied | apply_failed |
#          token_missing | token_invalid (apply)
#   sealed_pods / unreachable_pods: pod ordinals (0 = this pod).
#   shares: JSON array of the base64 unseal shares (init run only), else null.
# Exit: 0 success, 1 failure (see state/stage/error), 3 root (init) or
# temporary (apply) token not revoked.
# Diagnostics go to stderr and never contain a secret.

set -u
set -f
umask 077
# Every probe here is meant to be unauthenticated; a token is passed explicitly
# (BAO_TOKEN="$ROOT" per call), never inherited from the caller's shell.
unset BAO_TOKEN

MODE=${1:-status}
[ $# -gt 0 ] && shift
LAYERS="$*"

OB_KEY_SHARES=${OB_KEY_SHARES:-5}
OB_KEY_THRESHOLD=${OB_KEY_THRESHOLD:-3}
OB_KV_MOUNT=${OB_KV_MOUNT:-}
OB_CLUSTER_ID=${OB_CLUSTER_ID:-}
OB_AUDIENCE=${OB_AUDIENCE:-vault}
OB_ESO_SA=${OB_ESO_SA:-external-secrets}
OB_ESO_NAMESPACE=${OB_ESO_NAMESPACE:-external-secrets}
OB_OPERATOR_SA=${OB_OPERATOR_SA:-openbao-operator}
OB_OPERATOR_NAMESPACE=${OB_OPERATOR_NAMESPACE:-openbao}
OB_OPERATOR_TOKEN_TTL=${OB_OPERATOR_TOKEN_TTL:-1h}
OB_BACKUP_SA=${OB_BACKUP_SA:-openbao-snapshot}
OB_BACKUP_NAMESPACE=${OB_BACKUP_NAMESPACE:-openbao}
OB_PEER_ADDRS=${OB_PEER_ADDRS:-}
OB_TIMEOUT=${OB_TIMEOUT:-120}
OB_K8S_HOST=${OB_K8S_HOST:-https://kubernetes.default.svc}

# No bao call may hang the exec (and with it the EXIT trap) indefinitely:
# 5s for status probes, longer for the calls that write (WRITE_TIMEOUT) and
# for init itself (INIT_TIMEOUT), which Raft can take a while to commit.
BAO_CLIENT_TIMEOUT=${BAO_CLIENT_TIMEOUT:-5s}
export BAO_CLIENT_TIMEOUT
WRITE_TIMEOUT=30s
INIT_TIMEOUT=60s

STATE=unknown
STAGE=detect
ERR=
MISSING=
SEALED=
UNREACH=
BOOT_OK=false
REVOKED=false
ROOT_ACC=
SHARES_JSON=
ROOT=
KEYS=
# false | pending (init call started) | true (init succeeded)
INIT_DONE=false
# true once ROOT holds a token this run must revoke (init or apply).
TOKEN_HELD=false

log() { printf 'openbao-bootstrap: %s\n' "$*" >&2; }

# JSON string escape: whitespace folded to spaces, other control characters
# dropped, then backslash and quote escaped.
jstr() {
	printf '%s' "$1" | tr '\n\r\t' '   ' | tr -d '\000-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

trim_list() { printf '%s' "$1" | sed -e 's/^ *//' -e 's/ *$//'; }

emit() {
	printf '{"state":"%s","stage":"%s","error":"%s","missing":"%s","sealed_pods":"%s","unreachable_pods":"%s","bootstrap_ok":%s,"root_revoked":%s,"root_accessor":"%s","shares":%s}\n' \
		"$(jstr "$STATE")" "$(jstr "$STAGE")" "$(jstr "$ERR")" "$(jstr "$(trim_list "$MISSING")")" \
		"$(jstr "$(trim_list "$SEALED")")" "$(jstr "$(trim_list "$UNREACH")")" "$BOOT_OK" "$REVOKED" \
		"$(jstr "$ROOT_ACC")" "${SHARES_JSON:-null}"
}

# EXIT trap: revoke the root token if one exists, then print the result (and the
# shares, if this run created them) whatever happened before.
finish() {
	code=0
	if [ "$INIT_DONE" = pending ]; then
		# Interrupted inside bao operator init: did the server initialize?
		pod_status ""
		if [ "$P_INIT" = false ]; then
			INIT_DONE=false
			STATE=init_failed
		else
			INIT_DONE=true
			STATE=initialized
			ERR="interrupted during bao operator init (${ERR:-no error}); OpenBao may be initialized: the shares and root token are lost"
		fi
	fi
	if [ -n "$ROOT" ]; then
		if BAO_CLIENT_TIMEOUT=$WRITE_TIMEOUT BAO_TOKEN="$ROOT" bao token revoke -self >/dev/null 2>&1; then
			REVOKED=true
		elif [ "$STATE" = token_invalid ]; then
			# apply: the token was refused before any use; nothing to revoke
			# unless the lookup below finds it working after all.
			REVOKED=true
		else
			log "token revoke failed"
		fi
		# A successful lookup means the token still works, whatever revoke said.
		if BAO_TOKEN="$ROOT" bao token lookup >/dev/null 2>&1; then
			REVOKED=false
		fi
		ROOT=
	elif [ "$INIT_DONE" = true ]; then
		# Init ran but its root token could not be read: it cannot be revoked here.
		REVOKED=false
	else
		REVOKED=true
	fi
	KEYS=
	# apply: never leave an interrupted hidden prompt with echo off.
	[ "$MODE" = apply ] && [ -t 0 ] && stty echo 2>/dev/null
	emit
	if { [ "$INIT_DONE" = true ] || [ "$TOKEN_HELD" = true ]; } && [ "$REVOKED" != true ]; then
		code=3
	else
		case "$STATE" in
		ok | uninitialized) [ -n "$ERR" ] && code=1 ;;
		initialized) { [ "$BOOT_OK" = true ] && [ -z "$SEALED" ] && [ -z "$ERR" ]; } || code=1 ;;
		applied) { [ "$BOOT_OK" = true ] && [ -z "$ERR" ]; } || code=1 ;;
		*) code=1 ;;
		esac
	fi
	exit "$code"
}
trap finish EXIT
trap 'ERR="interrupted by signal"; exit 1' HUP INT TERM

fail() {
	ERR=$*
	log "$ERR"
	exit 1
}

bad() {
	STATE=bad_params
	fail "$*"
}

is_uint() { case "$1" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# DNS-1123 label (namespaces): lower alnum and '-', alnum at both ends, <= 63.
is_label() {
	[ ${#1} -ge 1 ] && [ ${#1} -le 63 ] || return 1
	case "$1" in *[!a-z0-9-]* | -* | *-) return 1 ;; esac
}

# DNS-1123 subdomain (ServiceAccount names): dot-separated labels, <= 253.
is_subdomain() {
	[ ${#1} -ge 1 ] && [ ${#1} -le 253 ] || return 1
	case "$1" in .* | *. | *..*) return 1 ;; esac
	old_ifs=$IFS
	IFS=.
	for part in $1; do
		is_label "$part" || { IFS=$old_ifs; return 1; }
	done
	IFS=$old_ifs
}

# KV mount and cluster id: one path segment of [A-Za-z0-9._-], not . or ..
is_segment() {
	case "$1" in '' | . | .. | *[!A-Za-z0-9._-]*) return 1 ;; esac
}

# ── Parameters ───────────────────────────────────────────────────────────────

check_params() {
	STAGE=params
	case "$MODE" in status | init | apply) ;; *) bad "unknown mode '$MODE' (status|init|apply)" ;; esac
	if ! is_uint "$OB_KEY_SHARES" || ! is_uint "$OB_KEY_THRESHOLD" ||
		[ "$OB_KEY_SHARES" -lt 1 ] || [ "$OB_KEY_SHARES" -gt 255 ] ||
		[ "$OB_KEY_THRESHOLD" -lt 1 ] || [ "$OB_KEY_THRESHOLD" -gt "$OB_KEY_SHARES" ] ||
		{ [ "$OB_KEY_SHARES" -gt 1 ] && [ "$OB_KEY_THRESHOLD" -lt 2 ]; }; then
		bad "openbao_key_threshold ($OB_KEY_THRESHOLD) must be >= 1 and <= openbao_key_shares ($OB_KEY_SHARES), >= 2 when there is more than one share, and openbao_key_shares must be 1..255"
	fi
	{ is_uint "$OB_TIMEOUT" && [ "$OB_TIMEOUT" -ge 2 ]; } || bad "OB_TIMEOUT must be a number of seconds >= 2 (got '$OB_TIMEOUT')"
	is_segment "$OB_KV_MOUNT" || bad "OB_KV_MOUNT must be one path segment of [A-Za-z0-9._-], not . or .. (got '$OB_KV_MOUNT')"
	is_segment "$OB_CLUSTER_ID" || bad "OB_CLUSTER_ID must be one path segment of [A-Za-z0-9._-], not . or .. (got '$OB_CLUSTER_ID')"
	is_segment "$OB_AUDIENCE" || bad "OB_AUDIENCE must be a name of [A-Za-z0-9._-] (got '$OB_AUDIENCE')"
	for v in OB_ESO_NAMESPACE OB_OPERATOR_NAMESPACE OB_BACKUP_NAMESPACE; do
		eval "val=\${$v}"
		# shellcheck disable=SC2154
		is_label "$val" || bad "$v must be a DNS-1123 label (got '$val')"
	done
	for v in OB_ESO_SA OB_OPERATOR_SA OB_BACKUP_SA; do
		eval "val=\${$v}"
		is_subdomain "$val" || bad "$v must be a DNS-1123 subdomain (got '$val')"
	done
	case "$OB_OPERATOR_TOKEN_TTL" in
	'' | *[!0-9smh]* | [!0-9]*) bad "OB_OPERATOR_TOKEN_TTL must be a duration like 1h or 30m (got '$OB_OPERATOR_TOKEN_TTL')" ;;
	esac
	case "$OB_K8S_HOST" in
	https://?* ) case "$OB_K8S_HOST" in *[!A-Za-z0-9.:/_-]*) bad "OB_K8S_HOST must be an https:// URL (got '$OB_K8S_HOST')" ;; esac ;;
	*) bad "OB_K8S_HOST must be an https:// URL (got '$OB_K8S_HOST')" ;;
	esac
	for a in $OB_PEER_ADDRS; do
		case "$a" in
		http://?*:[0-9]* | https://?*:[0-9]*) case "$a" in *[!A-Za-z0-9.:/-]*) bad "bad peer address '$a'" ;; esac ;;
		*) bad "bad peer address '$a' (http[s]://<host>:<port>)" ;;
		esac
	done
	[ -n "$LAYERS" ] || bad "no layers given (<layer>:<namespace>:<worker_sa>)"
	for spec in $LAYERS; do
		case "$spec" in *:*:*:* | :* | *::* | *:) bad "bad layer spec '$spec' (<layer>:<namespace>:<worker_sa>)" ;; *:*:*) ;; *) bad "bad layer spec '$spec' (<layer>:<namespace>:<worker_sa>)" ;; esac
		l=${spec%%:*}
		rest=${spec#*:}
		is_label "$l" || bad "bad layer name '$l' in '$spec'"
		is_label "${rest%%:*}" || bad "bad worker namespace in '$spec' (DNS-1123 label)"
		is_subdomain "${rest#*:}" || bad "bad worker ServiceAccount in '$spec' (DNS-1123 subdomain)"
	done
}

# ── State detection (unauthenticated endpoints only) ─────────────────────────

# pod_status <addr|''>: sets P_INIT and P_SEALED to true | false | unknown.
pod_status() {
	if [ -n "$1" ]; then
		out=$(bao status -address="$1" -format=json 2>/dev/null)
	else
		out=$(bao status -format=json 2>/dev/null)
	fi
	flat=$(printf '%s' "$out" | tr -d ' \n\r\t')
	case "$flat" in *'"initialized":true'*) P_INIT=true ;; *'"initialized":false'*) P_INIT=false ;; *) P_INIT=unknown ;; esac
	case "$flat" in *'"sealed":false'*) P_SEALED=false ;; *'"sealed":true'*) P_SEALED=true ;; *) P_SEALED=unknown ;; esac
}

# pod_status_wait <addr|''>: pod_status, retried for up to OB_TIMEOUT seconds
# while the pod does not answer (a restarting pod or slow DNS is not a state).
pod_status_wait() {
	w=0
	while :; do
		pod_status "$1"
		[ "$P_INIT" != unknown ] && return 0
		[ "$w" -ge "$OB_TIMEOUT" ] && return 1
		sleep 2
		w=$((w + 2))
	done
}

expected_roles() {
	for spec in $LAYERS; do
		l=${spec%%:*}
		printf '%s\n' "eso-$l" "$l-secrets-worker" "$l-secrets-importer"
	done
	printf '%s\n' operator backup
}

# Markers checked without a token (none exists after the root revoke):
#   - the KV mount, through sys/internal/ui/mounts (mount tuned listing_visibility=unauth)
#   - auth/kubernetes and every AD-7 role, through login probes with a dummy JWT:
#     "invalid role name" = role missing, "permission denied" = role exists (a
#     missing auth mount answers "permission denied" for a role that never
#     exists), "could not load backend configuration" = auth never configured.
#     Any other answer is not a state: unreachable.
# Policies cannot be read without a token; a policy is written right before
# its role, so a missing role also covers an interrupted bootstrap.
check_markers() {
	STAGE=markers
	MISSING=
	mounts=$(bao read -format=json sys/internal/ui/mounts 2>/dev/null | tr -d ' \n\r\t')
	[ -n "$mounts" ] || { STATE=unreachable; fail "cannot read sys/internal/ui/mounts on pod 0"; }
	secret_part=${mounts#*'"secret":{'}
	case "$secret_part" in
	*"\"$OB_KV_MOUNT/\":{"*) ;;
	*) MISSING="$MISSING kv-mount:$OB_KV_MOUNT" ;;
	esac
	probe=$(bao write auth/kubernetes/login role=bootstrap-marker-probe jwt=probe 2>&1 >/dev/null)
	case "$probe" in
	*'invalid role name'*)
		for r in $(expected_roles); do
			probe=$(bao write auth/kubernetes/login role="$r" jwt=probe 2>&1 >/dev/null)
			case "$probe" in
			*'invalid role name'*) MISSING="$MISSING role:$r" ;;
			*'permission denied'*) ;;
			*'could not load backend configuration'*) MISSING="$MISSING auth-config:kubernetes"; break ;;
			*) STATE=unreachable; fail "unexpected answer to the role $r login probe: $(printf '%s' "$probe" | grep -v '^ *$' | tail -n 2)" ;;
			esac
		done
		;;
	*'permission denied'*) MISSING="$MISSING auth:kubernetes" ;;
	*) STATE=unreachable; fail "unexpected answer to the auth/kubernetes login probe: $(printf '%s' "$probe" | grep -v '^ *$' | tail -n 2)" ;;
	esac
	if [ -n "$MISSING" ]; then
		STATE=missing_bootstrap
	else
		STATE=ok
		BOOT_OK=true
	fi
}

detect() {
	STAGE=detect
	SEALED=
	UNREACH=
	pod_status_wait "" || { STATE=unreachable; fail "cannot read the seal status of pod 0 (bao status)"; }
	p0_init=$P_INIT
	p0_sealed=$P_SEALED
	peers_init=
	n=0
	for a in $OB_PEER_ADDRS; do
		n=$((n + 1))
		if ! pod_status_wait "$a"; then
			UNREACH="$UNREACH $n"
			continue
		fi
		[ "$P_INIT" = true ] && peers_init="$peers_init $n"
		# Once the cluster is initialized, a sealed peer needs the shares whether
		# or not it has joined yet (a not-yet-joined peer reports uninitialized).
		# Before that, only an initialized peer can be "sealed".
		if [ "$P_SEALED" != false ] && { [ "$p0_init" = true ] || [ "$P_INIT" = true ]; }; then
			SEALED="$SEALED $n"
		fi
	done
	if [ "$p0_init" = true ] && [ "$p0_sealed" != false ]; then
		SEALED="0$SEALED"
	fi
	if [ -n "$UNREACH" ]; then
		STATE=peer_unreachable
		fail "pod(s)$UNREACH did not answer bao status within ${OB_TIMEOUT}s"
	elif [ "$p0_init" = false ]; then
		if [ -z "$peers_init" ]; then
			STATE=uninitialized
		else
			STATE=mixed
			fail "pod 0 is uninitialized but pod(s)$peers_init are initialized${SEALED:+ (sealed:$SEALED)}"
		fi
	elif [ "$p0_sealed" != false ]; then
		STATE=sealed
		fail "OpenBao is initialized and sealed"
	elif [ -n "$SEALED" ]; then
		STATE=mixed
		fail "pod 0 is unsealed but pod(s)$SEALED are sealed"
	else
		check_markers
	fi
}

# ── Init run ─────────────────────────────────────────────────────────────────

wait_active() {
	i=0
	while [ "$i" -lt "$OB_TIMEOUT" ]; do
		leader=$(bao read -format=json sys/leader 2>/dev/null | tr -d ' \n\r\t')
		case "$leader" in *'"is_self":true'*) return 0 ;; esac
		sleep 2
		i=$((i + 2))
	done
	return 1
}

# unseal <addr|''>: submit the first OB_KEY_THRESHOLD shares on stdin, then wait
# for the node to report unsealed.
unseal() {
	k_i=0
	for k in $KEYS; do
		k_i=$((k_i + 1))
		[ "$k_i" -gt "$OB_KEY_THRESHOLD" ] && break
		if [ -n "$1" ]; then
			printf '%s' "$k" | BAO_CLIENT_TIMEOUT=$WRITE_TIMEOUT bao write -address="$1" sys/unseal key=- >/dev/null 2>&1 || return 1
		else
			printf '%s' "$k" | BAO_CLIENT_TIMEOUT=$WRITE_TIMEOUT bao write sys/unseal key=- >/dev/null 2>&1 || return 1
		fi
	done
	w=0
	while [ "$w" -lt "$OB_TIMEOUT" ]; do
		pod_status "$1"
		[ "$P_SEALED" = false ] && return 0
		sleep 2
		w=$((w + 2))
	done
	return 1
}

# as_root <stage> <bao args...>: one bao call with the root token; on failure
# record the stage and bao's error text (bao errors never echo the token).
as_root() {
	STAGE=$1
	shift
	if ! e=$(BAO_CLIENT_TIMEOUT=$WRITE_TIMEOUT BAO_TOKEN="$ROOT" bao "$@" 2>&1 >/dev/null); then
		ERR="$STAGE: $(printf '%s' "$e" | grep -v '^ *$' | tail -n 3)"
		log "$ERR"
		return 1
	fi
}

# put_policy <name>: policy HCL on stdin.
put_policy() {
	STAGE="policy $1"
	if ! e=$(BAO_CLIENT_TIMEOUT=$WRITE_TIMEOUT BAO_TOKEN="$ROOT" bao policy write "$1" - 2>&1 >/dev/null); then
		ERR="$STAGE: $(printf '%s' "$e" | grep -v '^ *$' | tail -n 3)"
		log "$ERR"
		return 1
	fi
}

# Init (a fresh server): create the KV mount and Kubernetes auth, then the rest.
bootstrap() {
	m=$OB_KV_MOUNT

	as_root "kv mount" secrets enable -path="$m" -version=2 kv || return 1
	# Lets the tokenless re-run check see the mount (name and type only).
	as_root "kv mount visibility" secrets tune -listing-visibility=unauth "$m/" || return 1

	as_root "auth enable" auth enable kubernetes || return 1
	as_root "auth config" write auth/kubernetes/config \
		kubernetes_host="$OB_K8S_HOST" disable_local_ca_jwt=false || return 1

	bootstrap_access
}

# Apply: the same mount and auth, created only when missing; an existing one of
# the wrong kind is an error, never replaced (it may hold data).
apply_mounts() {
	m=$OB_KV_MOUNT

	STAGE="kv mount"
	mounts=$(BAO_TOKEN="$ROOT" bao secrets list -format=json 2>/dev/null | tr -d ' \n\r\t')
	[ -n "$mounts" ] || { ERR="kv mount: cannot list secrets engines with the token"; log "$ERR"; return 1; }
	case "$mounts" in
	*"\"$m/\":{"*)
		info=$(BAO_TOKEN="$ROOT" bao read -format=json "sys/mounts/$m" 2>/dev/null | tr -d ' \n\r\t')
		case "$info" in
		*'"type":"kv"'*) ;;
		*) ERR="kv mount: $m/ exists but is not a kv secrets engine; fix it by hand"; log "$ERR"; return 1 ;;
		esac
		case "$info" in
		*'"version":"2"'*) ;;
		*) ERR="kv mount: $m/ exists but is not KV version 2; fix it by hand"; log "$ERR"; return 1 ;;
		esac
		;;
	*) as_root "kv mount" secrets enable -path="$m" -version=2 kv || return 1 ;;
	esac
	as_root "kv mount visibility" secrets tune -listing-visibility=unauth "$m/" || return 1

	STAGE="auth enable"
	auths=$(BAO_TOKEN="$ROOT" bao auth list -format=json 2>/dev/null | tr -d ' \n\r\t')
	[ -n "$auths" ] || { ERR="auth enable: cannot list auth methods with the token"; log "$ERR"; return 1; }
	case "$auths" in
	*'"kubernetes/":{'*)
		case "$(BAO_TOKEN="$ROOT" bao read -format=json sys/auth/kubernetes 2>/dev/null | tr -d ' \n\r\t')" in
		*'"type":"kubernetes"'*) ;;
		*) ERR="auth enable: auth/kubernetes exists but is not a kubernetes auth method; fix it by hand"; log "$ERR"; return 1 ;;
		esac
		;;
	*) as_root "auth enable" auth enable kubernetes || return 1 ;;
	esac
	as_root "auth config" write auth/kubernetes/config \
		kubernetes_host="$OB_K8S_HOST" disable_local_ca_jwt=false || return 1
}

# Policies and roles (AD-7) and the audit device check. Writes are full
# rewrites, so running this again converges every policy and role.
bootstrap_access() {
	m=$OB_KV_MOUNT
	c=$OB_CLUSTER_ID

	for spec in $LAYERS; do
		l=${spec%%:*}
		rest=${spec#*:}
		wns=${rest%%:*}
		wsa=${rest#*:}

		put_policy "eso-$l" <<EOF || return 1
path "$m/data/$c/$l/*" {
  capabilities = ["read"]
}
EOF
		as_root "role eso-$l" write "auth/kubernetes/role/eso-$l" \
			bound_service_account_names="$OB_ESO_SA" bound_service_account_namespaces="$OB_ESO_NAMESPACE" \
			token_policies="eso-$l" audience="$OB_AUDIENCE" || return 1

		put_policy "$l-secrets-worker" <<EOF || return 1
path "$m/data/$c/$l/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "$m/metadata/$c/$l/*" {
  capabilities = ["read", "list", "delete"]
}
EOF
		as_root "role $l-secrets-worker" write "auth/kubernetes/role/$l-secrets-worker" \
			bound_service_account_names="$wsa" bound_service_account_namespaces="$wns" \
			token_policies="$l-secrets-worker" audience="$OB_AUDIENCE" || return 1

		put_policy "$l-secrets-importer" <<EOF || return 1
path "$m/data/$c/$l/*" {
  capabilities = ["create", "update", "read"]
}
EOF
		as_root "role $l-secrets-importer" write "auth/kubernetes/role/$l-secrets-importer" \
			bound_service_account_names="$l-secrets-importer" bound_service_account_namespaces="$wns" \
			token_policies="$l-secrets-importer" audience="$OB_AUDIENCE" || return 1
	done

	# '+' is one path segment (data, metadata, ...): ACL globs only work at the end.
	# Listing audit devices (GET sys/audit) is a sudo path: read alone gets 403.
	put_policy operator <<EOF || return 1
path "$m/+/$c/*" {
  capabilities = ["read", "create", "update", "list"]
}
path "sys/audit" {
  capabilities = ["read", "sudo"]
}
EOF
	as_root "role operator" write auth/kubernetes/role/operator \
		bound_service_account_names="$OB_OPERATOR_SA" bound_service_account_namespaces="$OB_OPERATOR_NAMESPACE" \
		token_policies=operator audience="$OB_AUDIENCE" \
		token_ttl="$OB_OPERATOR_TOKEN_TTL" token_max_ttl="$OB_OPERATOR_TOKEN_TTL" || return 1

	put_policy backup <<EOF || return 1
path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}
path "sys/storage/raft/snapshot-force" {
  capabilities = ["update"]
}
EOF
	as_root "role backup" write auth/kubernetes/role/backup \
		bound_service_account_names="$OB_BACKUP_SA" bound_service_account_namespaces="$OB_BACKUP_NAMESPACE" \
		token_policies=backup audience="$OB_AUDIENCE" || return 1

	# The file audit device to stdout is declared in the server config (OpenBao
	# 2.7 refuses audit devices created through the API); make sure it is active.
	STAGE="audit device"
	audit=$(BAO_TOKEN="$ROOT" bao audit list -format=json 2>/dev/null | tr -d ' \n\r\t')
	case "$audit" in
	*'"type":"file"'*) ;;
	*) ERR="audit device: no file audit device is enabled (expected the server config audit \"file\" stanza)"; log "$ERR"; return 1 ;;
	esac
	case "$audit" in
	*'"file_path":"stdout"'*) ;;
	*) ERR="audit device: the file audit device does not write to stdout"; log "$ERR"; return 1 ;;
	esac

	STAGE=done
	BOOT_OK=true
}

# check_role <role> <sa> <namespace> <policy>: the role exists with exactly this
# binding, policy and audience (apply mode, read back with the token).
check_role() {
	r=$(BAO_TOKEN="$ROOT" bao read -format=json "auth/kubernetes/role/$1" 2>/dev/null | tr -d ' \n\r\t')
	case "$r" in
	*"\"bound_service_account_names\":[\"$2\"]"*) ;;
	*) printf '%s' " role:$1(binding)"; return ;;
	esac
	case "$r" in *"\"bound_service_account_namespaces\":[\"$3\"]"*) ;; *) printf '%s' " role:$1(namespace)"; return ;; esac
	case "$r" in *"\"token_policies\":[\"$4\"]"*) ;; *) printf '%s' " role:$1(policy)"; return ;; esac
	case "$r" in *"\"audience\":\"$OB_AUDIENCE\""*) ;; *) printf '%s' " role:$1(audience)"; return ;; esac
	BAO_TOKEN="$ROOT" bao policy read "$4" >/dev/null 2>&1 || printf '%s' " policy:$4"
}

verify_access() {
	STAGE=verify
	bad=
	for spec in $LAYERS; do
		l=${spec%%:*}
		rest=${spec#*:}
		wns=${rest%%:*}
		wsa=${rest#*:}
		bad="$bad$(check_role "eso-$l" "$OB_ESO_SA" "$OB_ESO_NAMESPACE" "eso-$l")"
		bad="$bad$(check_role "$l-secrets-worker" "$wsa" "$wns" "$l-secrets-worker")"
		bad="$bad$(check_role "$l-secrets-importer" "$l-secrets-importer" "$wns" "$l-secrets-importer")"
	done
	bad="$bad$(check_role operator "$OB_OPERATOR_SA" "$OB_OPERATOR_NAMESPACE" operator)"
	bad="$bad$(check_role backup "$OB_BACKUP_SA" "$OB_BACKUP_NAMESPACE" backup)"
	if [ -n "$bad" ]; then
		MISSING=$bad
		ERR="verify: read back differs:$bad"
		log "$ERR"
		return 1
	fi
}

# ── Apply run ────────────────────────────────────────────────────────────────

do_apply() {
	STAGE=token
	# The first line of stdin. Typed at a terminal, it is not echoed.
	if [ -t 0 ]; then
		printf 'Temporary root token (input hidden): ' >&2
		stty -echo 2>/dev/null
		IFS= read -r ROOT || true
		stty echo 2>/dev/null
		printf '\n' >&2
	else
		IFS= read -r ROOT || true
	fi
	ROOT=$(printf '%s' "$ROOT" | tr -d '\r\n\t ')
	if [ -z "$ROOT" ]; then
		STATE=token_missing
		fail "no token on stdin: pipe the temporary generate-root token in (printf '%s\\n' \"\$BAO_TOKEN\" | ...)"
	fi
	TOKEN_HELD=true
	if ! BAO_TOKEN="$ROOT" bao token lookup >/dev/null 2>&1; then
		STATE=token_invalid
		fail "the token on stdin is not valid (expired, revoked or mistyped): nothing was changed"
	fi
	ROOT_ACC=$(BAO_TOKEN="$ROOT" bao token lookup -format=json 2>/dev/null | tr -d ' \n\r\t' |
		sed -n 's/.*"accessor":"\([^"]*\)".*/\1/p')
	BOOT_OK=false
	if ! apply_mounts || ! bootstrap_access || ! verify_access; then
		STATE=apply_failed
		BOOT_OK=false
		exit 1
	fi
	# The tokenless markers a later install or validate checks.
	check_markers
	if [ "$STATE" != ok ]; then
		STATE=apply_failed
		BOOT_OK=false
		fail "bootstrap markers still missing after apply:$MISSING"
	fi
	STATE=applied
	STAGE=done
	# The EXIT trap revokes the token and prints the result.
}

do_init() {
	STAGE=init
	INIT_DONE=pending
	# stdout and stderr together: on failure it is bao's error text (no secret),
	# on success the JSON (stderr warnings around it do not affect the parse).
	init_out=$(BAO_CLIENT_TIMEOUT=$INIT_TIMEOUT bao operator init -key-shares="$OB_KEY_SHARES" -key-threshold="$OB_KEY_THRESHOLD" -format=json 2>&1)
	init_rc=$?
	flat=$(printf '%s' "$init_out" | tr -d ' \n\r\t')
	if [ "$init_rc" -ne 0 ]; then
		init_err=$(printf '%s' "$init_out" | grep -v '^ *$' | tail -n 3)
		init_out=
		flat=
		pod_status ""
		case "$P_INIT:$init_err" in
		true:*'already initialized'*)
			# The status run saw uninitialized: another run initialized in between.
			INIT_DONE=false
			STATE=concurrent_init
			fail "OpenBao was initialized by another run between the status check and init ($init_err): that run holds the unseal shares"
			;;
		false:*)
			INIT_DONE=false
			STATE=init_failed
			fail "bao operator init failed: $init_err"
			;;
		true:*)
			INIT_DONE=true
			STATE=initialized
			fail "bao operator init returned an error after the server initialized ($init_err): the shares and root token are lost"
			;;
		*)
			# Unknown: the EXIT trap checks the status again (INIT_DONE=pending).
			fail "bao operator init failed and the init state is unknown: $init_err"
			;;
		esac
	fi
	init_out=
	INIT_DONE=true
	STATE=initialized
	SHARES_JSON=$(printf '%s' "$flat" | sed -n 's/.*"unseal_keys_b64":\(\[[^]]*\]\).*/\1/p')
	ROOT=$(printf '%s' "$flat" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')
	flat=
	if ! printf '%s' "$SHARES_JSON" | grep -Eq '^\["[A-Za-z0-9+/=]+"(,"[A-Za-z0-9+/=]+")*\]$'; then
		SHARES_JSON=
		fail "could not read the unseal shares from bao operator init"
	fi
	KEYS=$(printf '%s' "$SHARES_JSON" | tr -d '[]"' | tr ',' ' ')
	[ -n "$ROOT" ] || fail "could not read the root token from bao operator init"

	STAGE="unseal pod 0"
	unseal "" || { SEALED=0; fail "unseal of pod 0 failed"; }
	STAGE="wait active"
	wait_active || fail "pod 0 did not become active within ${OB_TIMEOUT}s"
	# The accessor is not a credential; it lets an operator confirm the revoke.
	ROOT_ACC=$(BAO_TOKEN="$ROOT" bao token lookup -format=json 2>/dev/null | tr -d ' \n\r\t' |
		sed -n 's/.*"accessor":"\([^"]*\)".*/\1/p')

	n=0
	for a in $OB_PEER_ADDRS; do
		n=$((n + 1))
		STAGE="unseal pod $n"
		if ! unseal "$a"; then
			SEALED="$SEALED $n"
			log "unseal of pod $n ($a) failed"
		fi
	done
	[ -n "$SEALED" ] && ERR="pod(s) $(trim_list "$SEALED") did not unseal"

	if bootstrap; then
		STAGE=done
	else
		exit 1
	fi
	# The EXIT trap revokes the root token and prints the result.
}

# Sealed, mixed and unreachable states exit here (through the EXIT trap).
check_params
detect
if [ "$MODE" = init ] && [ "$STATE" = uninitialized ]; then
	do_init
elif [ "$MODE" = apply ]; then
	[ "$STATE" = uninitialized ] && fail "OpenBao is not initialized: run the install, which initializes it"
	do_apply
fi
exit 0
