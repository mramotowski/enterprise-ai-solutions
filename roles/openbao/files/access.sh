# shellcheck shell=sh disable=SC2154
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# openbao — the AD-7 access every mode writes: KV v2 mount, Kubernetes auth
# mount, and the ESO / worker / importer / operator policies and roles.
# POSIX sh, sourced (never run) by bootstrap.sh (internal init and apply) and
# external-template.sh (external mode), from the same directory.
#
# The caller sets:
#   ACC_KV ACC_CID          KV v2 mount, <cluster_id> path segment
#   ACC_AUTH                Kubernetes auth mount path (auth/<ACC_AUTH>)
#   ACC_PREFIX              policy name prefix ('' internal, '<cluster_id>-' external)
#   ACC_LAYERS              <layer>:<namespace>:<worker_sa> ...
#   ACC_AUDIENCE ACC_ESO_SA ACC_ESO_NS ACC_OP_SA ACC_OP_NS ACC_OP_TTL
# and defines:
#   bao_write <stage> <bao args...>  one write with the admin token; returns
#                                    non-zero (after reporting) on failure
#   bao_read <bao args...>           one read with the admin token, to stdout
#                                    (stderr: the caller decides)
#   acc_fail <message>               report an error and return non-zero
# Every function returns non-zero on the first failure. Writes are full
# rewrites, so running them again converges every policy and role.

# acc_seg <v>: one path segment of [A-Za-z0-9._-], not . or ..
acc_seg() { case "$1" in '' | . | .. | *[!A-Za-z0-9._-]*) return 1 ;; esac; }

# acc_dns <v> [dots]: DNS-1123 label (<= 63), or with 'dots' a subdomain (<= 253).
acc_dns() {
	case "$1" in '' | [!a-z0-9]* | *[!a-z0-9] | *[!a-z0-9.-]* | *..* | *.-* | *-.*) return 1 ;; esac
	if [ "${2:-}" = dots ]; then
		[ ${#1} -le 253 ]
	else
		case "$1" in *.*) return 1 ;; esac
		[ ${#1} -le 63 ]
	fi
}

# acc_params_ok: every value that goes into a path, a policy or a role is
# well-formed (they reach HCL text and bao argv); otherwise ACC_BAD says which.
acc_params_ok() {
	ACC_BAD=
	acc_seg "$ACC_KV" || ACC_BAD="kv mount '$ACC_KV': one path segment of [A-Za-z0-9._-], not . or .."
	acc_seg "$ACC_CID" || ACC_BAD="cluster id '$ACC_CID': one path segment of [A-Za-z0-9._-], not . or .."
	acc_seg "$ACC_AUDIENCE" || ACC_BAD="audience '$ACC_AUDIENCE': a name of [A-Za-z0-9._-]"
	acc_dns "$ACC_ESO_NS" || ACC_BAD="ESO namespace '$ACC_ESO_NS': a DNS-1123 label"
	acc_dns "$ACC_OP_NS" || ACC_BAD="operator namespace '$ACC_OP_NS': a DNS-1123 label"
	acc_dns "$ACC_ESO_SA" dots || ACC_BAD="ESO ServiceAccount '$ACC_ESO_SA': a DNS-1123 subdomain"
	acc_dns "$ACC_OP_SA" dots || ACC_BAD="operator ServiceAccount '$ACC_OP_SA': a DNS-1123 subdomain"
	case "$ACC_OP_TTL" in '' | *[!0-9smh]* | [!0-9]*) ACC_BAD="operator token TTL '$ACC_OP_TTL': a duration like 1h or 30m" ;; esac
	for spec in $ACC_LAYERS; do
		l=${spec%%:*}
		rest=${spec#*:}
		case "$spec" in *:*:*:* | :* | *::* | *:) l= ;; *:*:*) ;; *) l= ;; esac
		{ acc_dns "$l" && acc_dns "${rest%%:*}" && acc_dns "${rest#*:}" dots; } ||
			ACC_BAD="bad layer spec '$spec' (<layer>:<namespace>:<serviceaccount>; lower-case DNS names)"
	done
	[ -z "$ACC_BAD" ]
}

# acc_mounts: the KV v2 mount and the Kubernetes auth mount, created only when
# missing; an existing one of the wrong kind is an error, never replaced (it may
# hold data).
acc_mounts() {
	m=$ACC_KV
	mounts=$(bao_read secrets list -format=json | tr -d ' \n\r\t')
	[ -n "$mounts" ] || { acc_fail "kv mount: cannot list secrets engines with the token"; return 1; }
	case "$mounts" in
	*"\"$m/\":{"*)
		info=$(bao_read read -format=json "sys/mounts/$m" | tr -d ' \n\r\t')
		case "$info" in
		*'"type":"kv"'*) ;;
		*) acc_fail "kv mount: $m/ exists but is not a kv secrets engine; fix it by hand"; return 1 ;;
		esac
		case "$info" in
		*'"version":"2"'*) ;;
		*) acc_fail "kv mount: $m/ exists but is not KV version 2; fix it by hand"; return 1 ;;
		esac
		;;
	*) bao_write "kv mount" secrets enable -path="$m" -version=2 kv || return 1 ;;
	esac

	auths=$(bao_read auth list -format=json | tr -d ' \n\r\t')
	[ -n "$auths" ] || { acc_fail "auth enable: cannot list auth methods with the token"; return 1; }
	case "$auths" in
	*"\"$ACC_AUTH/\":{"*)
		case "$(bao_read read -format=json "sys/auth/$ACC_AUTH" | tr -d ' \n\r\t')" in
		*'"type":"kubernetes"'*) ;;
		*) acc_fail "auth enable: auth/$ACC_AUTH exists but is not a kubernetes auth method; fix it by hand"; return 1 ;;
		esac
		;;
	*) bao_write "auth enable" auth enable -path="$ACC_AUTH" kubernetes || return 1 ;;
	esac
}

# acc_role <role> <sa> <namespace> [extra args...]: role bound to one
# ServiceAccount, with the policy ACC_PREFIX<role>.
acc_role() {
	r=$1
	sa=$2
	ns=$3
	shift 3
	bao_write "role $r" write "auth/$ACC_AUTH/role/$r" \
		bound_service_account_names="$sa" bound_service_account_namespaces="$ns" \
		token_policies="$ACC_PREFIX$r" audience="$ACC_AUDIENCE" "$@"
}

# acc_policy <name>: policy ACC_PREFIX<name>, HCL on stdin.
acc_policy() {
	bao_write "policy $1" policy write "$ACC_PREFIX$1" -
}

# acc_policies: per layer ESO (read), worker (read/write/delete) and importer
# (migration), then operator (people, and the installer's read-only checks).
acc_policies() {
	m=$ACC_KV
	c=$ACC_CID
	for spec in $ACC_LAYERS; do
		l=${spec%%:*}
		rest=${spec#*:}
		wns=${rest%%:*}
		wsa=${rest#*:}

		acc_policy "eso-$l" <<EOF || return 1
path "$m/data/$c/$l/*" {
  capabilities = ["read"]
}
EOF
		acc_role "eso-$l" "$ACC_ESO_SA" "$ACC_ESO_NS" || return 1

		acc_policy "$l-secrets-worker" <<EOF || return 1
path "$m/data/$c/$l/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "$m/metadata/$c/$l/*" {
  capabilities = ["read", "list", "delete"]
}
EOF
		acc_role "$l-secrets-worker" "$wsa" "$wns" || return 1

		acc_policy "$l-secrets-importer" <<EOF || return 1
path "$m/data/$c/$l/*" {
  capabilities = ["create", "update", "read"]
}
EOF
		acc_role "$l-secrets-importer" "$l-secrets-importer" "$wns" || return 1
	done

	# '+' is one path segment (data, metadata, ...): ACL globs only work at the end.
	# Listing audit devices (GET sys/audit) is a sudo path: read alone gets 403.
	acc_policy operator <<EOF || return 1
path "$m/+/$c/*" {
  capabilities = ["read", "create", "update", "list"]
}
path "sys/audit" {
  capabilities = ["read", "sudo"]
}
EOF
	acc_role operator "$ACC_OP_SA" "$ACC_OP_NS" \
		token_ttl="$ACC_OP_TTL" token_max_ttl="$ACC_OP_TTL"
}
