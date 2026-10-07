#!/bin/sh
# OpenBao setup for one cluster with openbao_mode: external.
# The same mount, auth, policies and roles as roles/openbao/files/bootstrap.sh
# (internal mode), for an OpenBao you run. Run it as an OpenBao administrator:
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

for spec in $LAYERS; do
	case "$spec" in
	*:*:*:* | :* | *::* | *:) die "bad LAYERS entry '$spec' (<layer>:<namespace>:<serviceaccount>)" ;;
	*:*:*) ;;
	*) die "bad LAYERS entry '$spec' (<layer>:<namespace>:<serviceaccount>)" ;;
	esac
done

# 1. KV v2 mount (shared by every cluster; paths are <mount>/<kind>/<cluster_id>/...)
if bao secrets list -format=json | flat | grep -qF "\"$m/\":{"; then
	info=$(bao read -format=json "sys/mounts/$m" | flat)
	case "$info" in *'"type":"kv"'*'"version":"2"'* | *'"version":"2"'*'"type":"kv"'*) ;;
	*) die "mount $m/ exists but is not KV version 2" ;;
	esac
else
	bao secrets enable -path="$m" -version=2 kv
fi

# 2. Kubernetes auth for this cluster
if bao auth list -format=json | flat | grep -qF "\"$a/\":{"; then
	case "$(bao read -format=json "sys/auth/$a" | flat)" in *'"type":"kubernetes"'*) ;;
	*) die "auth/$a exists but is not a kubernetes auth method" ;;
	esac
else
	bao auth enable -path="$a" kubernetes
fi
# On a shared OpenBao the mount may already serve another cluster: never repoint it silently.
old_host=$(bao read -format=json "auth/$a/config" 2>/dev/null | flat | sed -n 's/.*"kubernetes_host":"\([^"]*\)".*/\1/p')
if [ -n "$old_host" ] && [ "$old_host" != "$K8S_HOST" ] && [ "$FORCE" != 1 ]; then
	die "auth/$a/config points at $old_host, not $K8S_HOST: use another AUTH_MOUNT for this cluster, or FORCE=1 to overwrite"
fi
if [ -n "$REVIEWER_JWT_FILE" ]; then
	bao write "auth/$a/config" kubernetes_host="$K8S_HOST" kubernetes_ca_cert=@"$K8S_CA_FILE" \
		token_reviewer_jwt=@"$REVIEWER_JWT_FILE" disable_local_ca_jwt=true
else
	bao write "auth/$a/config" kubernetes_host="$K8S_HOST" kubernetes_ca_cert=@"$K8S_CA_FILE" \
		disable_local_ca_jwt=true
fi

# 3. Per layer: ESO (read), worker (read/write/delete), importer (migration)
for spec in $LAYERS; do
	l=${spec%%:*}
	rest=${spec#*:}
	wns=${rest%%:*}
	wsa=${rest#*:}

	bao policy write "$c-eso-$l" - <<EOF
path "$m/data/$c/$l/*" {
  capabilities = ["read"]
}
EOF
	bao write "auth/$a/role/eso-$l" \
		bound_service_account_names="$ESO_SA" bound_service_account_namespaces="$ESO_NAMESPACE" \
		token_policies="$c-eso-$l" audience="$AUDIENCE"

	bao policy write "$c-$l-secrets-worker" - <<EOF
path "$m/data/$c/$l/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "$m/metadata/$c/$l/*" {
  capabilities = ["read", "list", "delete"]
}
EOF
	bao write "auth/$a/role/$l-secrets-worker" \
		bound_service_account_names="$wsa" bound_service_account_namespaces="$wns" \
		token_policies="$c-$l-secrets-worker" audience="$AUDIENCE"

	bao policy write "$c-$l-secrets-importer" - <<EOF
path "$m/data/$c/$l/*" {
  capabilities = ["create", "update", "read"]
}
EOF
	bao write "auth/$a/role/$l-secrets-importer" \
		bound_service_account_names="$l-secrets-importer" bound_service_account_namespaces="$wns" \
		token_policies="$c-$l-secrets-importer" audience="$AUDIENCE"
done

# 4. Operator (people, and the installer's read-only checks). '+' is one path
#    segment (data, metadata); listing audit devices needs sudo on sys/audit.
bao policy write "$c-operator" - <<EOF
path "$m/+/$c/*" {
  capabilities = ["read", "create", "update", "list"]
}
path "sys/audit" {
  capabilities = ["read", "sudo"]
}
EOF
bao write "auth/$a/role/operator" \
	bound_service_account_names="$OPERATOR_SA" bound_service_account_namespaces="$OPERATOR_NAMESPACE" \
	token_policies="$c-operator" audience="$AUDIENCE" \
	token_ttl="$OPERATOR_TOKEN_TTL" token_max_ttl="$OPERATOR_TOKEN_TTL"

# 5. Audit device (AD-18): at least one must be enabled. OpenBao 2.7 refuses
#    audit devices created through the API: declare one in the server config,
#    e.g. audit "file" "file" { options { file_path = "stdout" } }.
audit=$(bao audit list -format=json 2>/dev/null) || die "cannot list audit devices (needs sudo on sys/audit)"
if ! printf '%s' "$audit" | flat | grep -q '"type":'; then
	bao audit enable -path=file file file_path=stdout >/dev/null 2>&1 ||
		die "no audit device is enabled: declare one in the OpenBao server configuration (audit \"file\" \"file\" { options { file_path = \"stdout\" } }), restart, and re-run"
fi
echo "OpenBao is set up for cluster '$c' (auth/$a, KV $m/)."
