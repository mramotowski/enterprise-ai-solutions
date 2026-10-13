#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Test helper for bootstrap_test.yaml only (runs in the throwaway container).
# Reads the unseal shares (one per line) on stdin, mints a temporary root token
# with the legacy unauthenticated generate-root endpoints (the generate-root
# runbook path), then:
#   inspect <root_accessor> [<role>...]   print a JSON summary of the bootstrap
#   delete-role <role>                    delete one Kubernetes-auth role
#   disable-mount <path>                  disable a secrets engine mount
#   disable-auth <path>                   disable an auth method
#   remount-kv1 <path>                    replace a mount with a KV version 1 one
#   apply <layer spec>...                 pipe the token into bootstrap.sh apply
#                                         (the runbook path); print its JSON result
#                                         and whether the token still works
# and revokes the temporary token. Prints no share and no token.
set -u
set -f
ACTION=$1
shift

KEYS=$(cat)
THRESHOLD=$(bao status -format=json 2>/dev/null | tr -d ' \n' | sed -n 's/.*"t":\([0-9]*\).*/\1/p')

att=$(bao write -f -format=json sys/generate-root/attempt | tr -d ' \n\r\t') || exit 1
nonce=$(printf '%s' "$att" | sed -n 's/.*"nonce":"\([^"]*\)".*/\1/p')
otp=$(printf '%s' "$att" | sed -n 's/.*"otp":"\([^"]*\)".*/\1/p')
i=0
enc=
for k in $KEYS; do
	i=$((i + 1))
	[ "$i" -gt "$THRESHOLD" ] && break
	r=$(printf '%s' "$k" | bao write -format=json sys/generate-root/update nonce="$nonce" key=- | tr -d ' \n\r\t') || exit 1
	enc=$(printf '%s' "$r" | sed -n 's/.*"encoded_token":"\([^"]*\)".*/\1/p')
done
[ -n "$enc" ] || { echo "generate-root did not complete" >&2; exit 1; }
# token = base64(encoded) XOR otp (the CLI -decode needs the new authenticated endpoint).
while [ $((${#enc} % 4)) -ne 0 ]; do enc="$enc="; done
a=$(printf '%s' "$enc" | base64 -d | od -An -v -tu1 | tr -s ' \n' '  ')
b=$(printf '%s' "$otp" | od -An -v -tu1 | tr -s ' \n' '  ')
TOK=$(printf '%s\n%s\n' "$a" "$b" | awk 'NR==1{n=split($0,x," ")} NR==2{split($0,y," "); for(i=1;i<=n;i++) printf("%c", xor(x[i],y[i]))}')

t() { BAO_TOKEN="$TOK" bao "$@"; }
# j <bao args>: the command's JSON on one line, or null when it fails.
j() {
	if out=$(t "$@" 2>/dev/null) && [ -n "$out" ]; then printf '%s' "$out" | tr -d '\n'; else printf null; fi
}

case "$ACTION" in
inspect)
	acc=$1
	shift
	roles=
	for r in "$@"; do
		roles="$roles${roles:+,}\"$r\":$(j read -format=json "auth/kubernetes/role/$r")"
	done
	pols=
	for r in "$@"; do
		pols="$pols${pols:+,}\"$r\":$(j policy read -format=json "$r")"
	done
	t token lookup -accessor "$acc" >/dev/null 2>&1
	acc_rc=$?
	printf '{"mounts":%s,"auths":%s,"k8s_config":%s,"audit":%s,"roles":{%s},"policies":{%s},"root_accessor_lookup_rc":%s}\n' \
		"$(j secrets list -format=json)" "$(j auth list -format=json)" \
		"$(j read -format=json auth/kubernetes/config)" "$(j audit list -format=json)" \
		"$roles" "$pols" "$acc_rc"
	;;
delete-role)
	t delete "auth/kubernetes/role/$1" >/dev/null
	;;
disable-mount)
	t secrets disable "$1" >/dev/null
	;;
disable-auth)
	t auth disable "$1" >/dev/null
	;;
remount-kv1)
	t secrets disable "$1" >/dev/null && t secrets enable -path="$1" -version=1 kv >/dev/null
	;;
apply)
	res=$(printf '%s\n' "$TOK" | /bin/sh /openbao/userconfig/openbao-bootstrap/bootstrap.sh apply "$@" 2>/dev/null)
	arc=$?
	t token lookup >/dev/null 2>&1
	lrc=$?
	printf '{"apply":%s,"apply_rc":%s,"temp_token_lookup_rc":%s}\n' "$(printf '%s' "$res" | tail -n 1)" "$arc" "$lrc"
	true
	;;
esac
rc=$?
t token revoke -self >/dev/null 2>&1
TOK=
exit "$rc"
