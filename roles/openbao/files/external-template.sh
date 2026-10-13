#!/bin/sh
# OpenBao setup for one cluster with openbao_mode: external.
# The same mount, auth, policies and roles as roles/openbao/files/bootstrap.sh
# (internal mode; both use access.sh, which must sit next to this file), for an
# OpenBao you run. Run it as an OpenBao administrator:
# BAO_ADDR, BAO_CACERT and a token allowed to manage mounts, auth methods,
# policies and audit devices (bao login, or BAO_TOKEN) must be set.
# Safe to re-run: existing mounts are checked, policies and roles rewritten.
set -eu

# --- Must match the cluster's env/<env>/global_config.yaml --------------------
CLUSTER_ID=${CLUSTER_ID:?set CLUSTER_ID to openbao_cluster_id}
KV_MOUNT=${KV_MOUNT:-intel-ai}                 # openbao_kv_mount
AUTH_MOUNT=${AUTH_MOUNT:-kubernetes}           # openbao_auth_mount, one per cluster
AUDIENCE=${AUDIENCE:-vault}                    # openbao_auth_audience
# <layer>:<worker namespace>:<worker ServiceAccount> per layer in openbao_layers
# (erag: erag_secrets_namespace, erag_secrets_worker_sa), space-separated.
LAYERS=${LAYERS:-erag:erag-secrets:erag-secrets-worker}
ESO_SA=${ESO_SA:-external-secrets}             # ESO controller ServiceAccount
ESO_NAMESPACE=${ESO_NAMESPACE:-external-secrets}
OPERATOR_SA=${OPERATOR_SA:-openbao-operator}   # created by the installer
OPERATOR_NAMESPACE=${OPERATOR_NAMESPACE:-openbao}
OPERATOR_TOKEN_TTL=${OPERATOR_TOKEN_TTL:-1h}

# --- The cluster's API, called by OpenBao for TokenReview ---------------------
K8S_HOST=${K8S_HOST:?set K8S_HOST to the cluster API URL reachable from OpenBao}
K8S_CA_FILE=${K8S_CA_FILE:?set K8S_CA_FILE to the cluster API CA (PEM file)}
# File with the JWT of a ServiceAccount bound to ClusterRole system:auth-delegator.
# Empty: OpenBao reviews each client's own JWT, so every client ServiceAccount
# then needs system:auth-delegator.
REVIEWER_JWT_FILE=${REVIEWER_JWT_FILE:-}
# 1: overwrite an auth/$AUTH_MOUNT/config that points at another cluster's API.
FORCE=${FORCE:-0}

# Policies are global in OpenBao: prefix them with the cluster id.
c=$CLUSTER_ID
m=$KV_MOUNT
a=$AUTH_MOUNT
flat() { tr -d ' \n\r\t'; }
die() { printf 'external-template: %s\n' "$*" >&2; exit 1; }

# The mounts, policies and roles (shared with the internal bootstrap.sh) are in
# access.sh, next to this script.
ACC_KV=$m ACC_CID=$c ACC_AUTH=$a ACC_PREFIX="$c-" ACC_LAYERS=$LAYERS ACC_AUDIENCE=$AUDIENCE
ACC_ESO_SA=$ESO_SA ACC_ESO_NS=$ESO_NAMESPACE
ACC_OP_SA=$OPERATOR_SA ACC_OP_NS=$OPERATOR_NAMESPACE ACC_OP_TTL=$OPERATOR_TOKEN_TTL
bao_write() { st=$1; shift; bao "$@" >/dev/null || die "$st failed"; }
bao_read() { bao "$@"; }
acc_fail() { die "$*"; }
# Run as a file (sh <path>/external-template.sh), never piped: access.sh is
# looked up next to it.
case "$0" in
*/external-template.sh) ACC_DIR=${0%/*} ;;
external-template.sh) ACC_DIR=. ;;
*) die "run this file by path (sh <dir>/external-template.sh), not piped: it needs access.sh from its directory" ;;
esac
[ -r "$ACC_DIR/access.sh" ] || die "cannot read $ACC_DIR/access.sh: keep access.sh next to external-template.sh"
# shellcheck source=access.sh
. "$ACC_DIR/access.sh"
command -v acc_policies >/dev/null 2>&1 || die "$ACC_DIR/access.sh does not define acc_policies: use the access.sh of the same repo checkout"

acc_params_ok || die "$ACC_BAD"

# 1. KV v2 mount (shared by every cluster; paths are <mount>/<kind>/<cluster_id>/...)
#    and Kubernetes auth for this cluster
acc_mounts
# On a shared OpenBao the mount may already serve another cluster: never repoint it silently.
old_host=$(bao read -format=json "auth/$a/config" 2>/dev/null | flat | sed -n 's/.*"kubernetes_host":"\([^"]*\)".*/\1/p')
if [ -n "$old_host" ] && [ "$old_host" != "$K8S_HOST" ] && [ "$FORCE" != 1 ]; then
	die "auth/$a/config points at $old_host, not $K8S_HOST: use another AUTH_MOUNT for this cluster, or FORCE=1 to overwrite"
fi
if [ -n "$REVIEWER_JWT_FILE" ]; then
	bao_write "auth config" write "auth/$a/config" kubernetes_host="$K8S_HOST" kubernetes_ca_cert=@"$K8S_CA_FILE" \
		token_reviewer_jwt=@"$REVIEWER_JWT_FILE" disable_local_ca_jwt=true
else
	bao_write "auth config" write "auth/$a/config" kubernetes_host="$K8S_HOST" kubernetes_ca_cert=@"$K8S_CA_FILE" \
		disable_local_ca_jwt=true
fi

# 2. Per layer: ESO (read), worker (read/write/delete), importer (migration);
#    then operator (people, and the installer's read-only checks).
acc_policies

# 3. Audit device (AD-18): at least one must be enabled. OpenBao 2.7 refuses
#    audit devices created through the API: declare one in the server config,
#    e.g. audit "file" "file" { options { file_path = "stdout" } }.
audit=$(bao audit list -format=json 2>/dev/null) || die "cannot list audit devices (needs sudo on sys/audit)"
if ! printf '%s' "$audit" | flat | grep -q '"type":'; then
	bao audit enable -path=file file file_path=stdout >/dev/null 2>&1 ||
		die "no audit device is enabled: declare one in the OpenBao server configuration (audit \"file\" \"file\" { options { file_path = \"stdout\" } }), restart, and re-run"
fi
echo "OpenBao is set up for cluster '$c' (auth/$a, KV $m/)."
