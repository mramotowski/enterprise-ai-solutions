#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Test helper for ops_test.yaml only: an RS256 JWT shaped like a projected
# ServiceAccount token, signed with a throwaway key, so snapshot.sh can log in
# through a jwt auth method mounted at auth/kubernetes (Kubernetes TokenReview
# is not available in Docker; the request is the same: role + jwt).
#   make_jwt.sh <key.pem> <audience> <subject> > token
set -eu
key=$1
aud=$2
sub=$3
now=$(date +%s)
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
p=$(printf '{"iss":"ops-test","sub":"%s","aud":"%s","iat":%s,"nbf":%s,"exp":%s}' "$sub" "$aud" "$now" "$((now - 5))" "$((now + 600))" | b64url)
s=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$key" -binary | b64url)
printf '%s.%s.%s' "$h" "$p" "$s"
