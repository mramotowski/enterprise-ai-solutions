# OpenBao secrets backend: operations runbook

With `secrets_backend: openbao` and `openbao_mode: internal`, the platform layer runs
OpenBao in namespace `openbao` (pods `openbao-0` … `openbao-<N-1>` for
`openbao_replicas: N`). This page covers the first install and the procedures the
installer's error messages point to. With `openbao_mode: external` you run OpenBao
yourself: see [External OpenBao](#external-openbao). The optional gateway route
(internal mode) is described in [Route](#route), and how layers read OpenBao through
External Secrets Operator in [External Secrets Operator](#external-secrets-operator).
Day-2 operations: [Upgrades](#upgrades), [Scale up](#scale-up) and
[Scale down](#scale-down), [Server certificate renewal](#server-certificate-renewal),
[Backup and restore](#backup-and-restore). The settings are listed in the
[Configuration Reference](../customize/configuration.md#secrets-backend), and what
OpenBao cannot do in [Limitations](#limitations). How the erag layer uses OpenBao (paths,
first-login credentials, operator-supplied secrets, migration, rotation, teardown) is in
its guide,
[Credentials in OpenBao](https://github.com/intel/enterprise-rag/blob/main/docs/deploy/openbao.md).

All commands below assume the default names: namespace `openbao`, release and
pods `openbao-*`, container `openbao`, and the KV mount `intel-ai`. Inside a pod,
the `bao` CLI already talks to the local server over TLS (`BAO_ADDR` and
`BAO_CACERT` are set by the chart).

## First install: init, unseal, bootstrap

The first `./es_auto_installer.sh install platform --env <env>` with OpenBao enabled
runs one script inside `openbao-0`. The script:

1. initializes OpenBao with Shamir, using `openbao_key_shares` shares (default 5) and
   `openbao_key_threshold` (default 3);
2. unseals every pod;
3. creates the KV v2 mount, Kubernetes auth, and the roles and policies for every
   layer in `openbao_layers`, plus the shared `operator` and `backup` roles;
4. revokes the root token.

The run then writes the unseal shares **to your terminal only** (the terminal
device on the installer's stdin, for example `/dev/pts/4`). They
never go to stdout or the env log. The run waits until you type `saved`. Before you
type it, store every share separately, for example one per key holder. The shares
are shown only this once. You need them after every pod restart, every upgrade and
every restore.

After the confirmation the installer clears the screen and the terminal's
scrollback. That does **not** erase the scrollback of tmux, screen or `script`
sessions, or a terminal log: clear those yourself (for example tmux
`clear-history`).

The installer checks the following before init. If any check fails, it stops and
changes nothing in OpenBao:

- You must run it from an interactive terminal on a Linux controller (it reads
  `/proc` to find the terminal on the installer's stdin), not CI and not with stdin
  redirected, as the user who owns that terminal (not after `su` or `sudo -u`).
  Otherwise it stops with "This OpenBao step needs an interactive terminal". The
  same check runs before an OpenBao upgrade restarts pods.
- `ES_LOG_LEVEL=trace` is not allowed, because it sets `ANSIBLE_DEBUG`, which logs
  raw module results. Use `info` or `debug` for this run.
- `ANSIBLE_KEEP_REMOTE_FILES` must not be set.
- `openbao_key_threshold` must be between 1 and `openbao_key_shares`.

No root token exists after the bootstrap, and no other standing privileged token
exists either. The installer can no longer change the bootstrap itself. Later
changes need a temporary root token from the unseal shares, as described in
[Change the bootstrap (generate-root)](#change-the-bootstrap-generate-root).

Later installs and `validate` are read-only. They check that every pod is
initialized and unsealed, and that the bootstrap markers exist: the KV mount,
`auth/kubernetes` and every expected role. Policies cannot be read without a token,
so these runs do not check them.

The file audit device writes every request and response to the server's stdout,
where platform Loki collects it. It is declared in the server config, because
OpenBao 2.7 does not accept `bao audit enable`.

## Unseal after a restart

Any OpenBao pod that restarts comes back sealed. The installer stops and lists the
sealed pods, for example: "OpenBao is initialized but sealed on openbao-0, …".
Unseal each pod listed, starting with `openbao-0`. Run the command
`openbao_key_threshold` times per pod, each time with a different share. The prompt
hides what you type.

```bash
kubectl -n openbao exec -ti openbao-0 -c openbao -- bao operator unseal
kubectl -n openbao exec -ti openbao-0 -c openbao -- bao operator unseal
kubectl -n openbao exec -ti openbao-0 -c openbao -- bao operator unseal
# then openbao-1, openbao-2, ... the same way
kubectl -n openbao exec openbao-0 -c openbao -- bao status   # Sealed: false
```

Then re-run the install.

## Pods in mixed states

"Pods in mixed states" means `openbao-0` and the other pods disagree.

- **`openbao-0` is unsealed and other pods are sealed.** Unseal the listed pods as
  shown in [Unseal after a restart](#unseal-after-a-restart).
- **`openbao-0` is uninitialized and other pods are initialized.** `openbao-0` lost
  its data, for example because its PVC was replaced. Do not re-run the install: it
  will refuse to initialize. The surviving pods still list the old `openbao-0` as a
  Raft peer, so remove it first, then let a fresh `openbao-0` rejoin through
  `retry_join`:

  1. Mint a temporary root token on a surviving, unsealed pod (for example
     `openbao-1`), as in [Change the bootstrap (generate-root)](#change-the-bootstrap-generate-root),
     steps 1-3.
  2. In that shell, remove the lost peer and revoke the token:

     ```bash
     bao operator raft list-peers
     bao operator raft remove-peer openbao-0
     bao token revoke -self
     ```

  3. Replace the empty volume and pod, then unseal `openbao-0` with the shares:

     ```bash
     kubectl -n openbao delete pvc data-openbao-0 --wait=false
     kubectl -n openbao delete pod openbao-0
     ```

  Then re-run the install.

## A pod did not answer

"did not answer from pod openbao-0" (state `peer_unreachable`) means `openbao-0`
could not reach another pod's API within `openbao_init_timeout` seconds. Nothing
was changed and no data is at risk. Check that every pod is Running
(`kubectl -n openbao get pods`), and that DNS and the NetworkPolicy let `openbao-0`
reach `openbao-<n>.openbao-internal:8200`. Then re-run the install.

## Upgrades

The StatefulSet uses `updateStrategy: OnDelete`: an install applies chart and config
changes (a bumped `openbao_chart_version` or `openbao_image_tag`, new values) to the
StatefulSet, but no running pod picks them up until it restarts, and every restarted
pod comes back sealed. A plain install only warns about pods that still run an old
revision. To roll the change out, run the upgrade from an interactive terminal, with
your unseal shares at hand:

```bash
./es_auto_installer.sh install openbao --env <env> --only -- -e openbao_upgrade=true
```

(The installer CLI has no `upgrade` verb; this runs the role's upgrade path. The
role's `upgrade` action does the same.)

Before you upgrade, take a backup (the profile that includes the
[snapshot hooks](#backup-and-restore)), or save a snapshot by hand with a temporary
root token (`bao operator raft snapshot save /tmp/pre-upgrade.snap` in `openbao-0`, then
`kubectl cp` it off the cluster). Read the OpenBao release notes: a newer server may
migrate the Raft data, and going back to the old image may then not work. If the new
image fails on the first restarted pod, stop. Set `openbao_image_tag` back and run the
upgrade again while the other pods still run the old version. Once all pods have
moved, a downgrade means restoring that snapshot.

The run:

1. checks, before it changes anything, that every pod is initialized, unsealed and
   bootstrapped; otherwise it stops with the usual instructions;
2. applies the chart and config;
3. restarts the pods that run an old revision one at a time, the standbys first
   and the active pod last. After each restart it pauses and shows the command to
   run in another terminal:

   ```bash
   kubectl -n openbao exec -ti openbao-1 -c openbao -- bao operator unseal   # threshold times
   ```

   Press Enter when it is unsealed. The run waits up to 5 minutes until the pod reports
   unsealed, knows the leader and has applied the Raft log up to the commit index.
   Only then does it go on to the next one.

The upgrade needs an interactive terminal (it checks before any change). The shares
are typed into `kubectl exec`, never into the installer. If a pod does
not unseal in time, the run stops; unseal it and re-run the same command (pods that
are done are skipped). With `openbao_replicas: 1`, the only pod is restarted, so
OpenBao is unavailable until you unseal it. Running workloads keep their Secrets;
only ESO refreshes and installs fail meanwhile.

## Scale up

Raise `openbao_replicas` (1 → 3, or any odd number) and run the upgrade above. The
server certificate gets the new pods' names, every pod is told to reload it, and the
run pauses for each new pod. Unsealing a new pod with the cluster's shares joins it
to the Raft cluster (`retry_join`). Check the result with a temporary root token:
`bao operator raft list-peers`.

## Scale down

Every pod is a Raft voter. Stopping pods without removing them from the Raft
configuration leaves too few voters for a quorum (3 → 1 leaves one voter of three:
no leader). The install and the upgrade therefore refuse a lower `openbao_replicas`
until you confirm that the peers were removed:

1. Mint a temporary root token in `openbao-0`
   ([Change the bootstrap (generate-root)](#change-the-bootstrap-generate-root),
   steps 1-3). If a pod that will be removed is the active node (`bao operator raft
   list-peers` shows it as `leader`), first make another pod the leader: run
   `kubectl -n openbao exec openbao-<n> -c openbao -- bao operator step-down` with a
   token, or delete that pod once and unseal it. Then remove the highest pods, one at a
   time:

   ```bash
   bao operator raft remove-peer openbao-2
   bao operator raft remove-peer openbao-1
   bao operator raft list-peers      # must list only the pods you keep, e.g. openbao-0 as leader
   bao token revoke -self
   ```

   The installer cannot check this without a token: `openbao_raft_peers_removed=true`
   is your confirmation.

2. Set `openbao_replicas` and run the upgrade with the confirmation:

   ```bash
   ./es_auto_installer.sh install openbao --env <env> --only -- -e openbao_upgrade=true -e openbao_raft_peers_removed=true
   ```

   The kept pods also restart once (their Raft `retry_join` list changed). With a target
   of one replica, `openbao-0` is unavailable until you unseal it.

3. Delete the volumes of the removed pods. The run prints the commands, for example
   `kubectl -n openbao delete pvc data-openbao-2`. Do this before any later scale-up:
   an old volume would bring an old copy of the Raft data back under the same name.

## Server certificate renewal

cert-manager renews the server certificate (`openbao-server-tls`, 1 year, renewed 30
days before expiry), and the kubelet updates the mounted files. OpenBao, however,
reads its listener certificate only at start and on SIGHUP. The `tls-reloader`
sidecar in every server pod (`openbao_tls_reloader_enabled`, default `true`) hashes
the mounted `tls.crt` every `openbao_tls_reloader_interval` seconds (60) and sends
SIGHUP to the `bao server` process once after it starts and whenever the hash changed,
until the listener serves the mounted certificate. A SIGHUP does not seal OpenBao
and does not interrupt requests. After an installer update that changes the sidecar
(its command or env), run the upgrade ([Upgrades](#upgrades)) so that the pods
restart with the new sidecar.

The sidecar shares the pod's process namespace (it has to, to signal the server).
It runs the server image as the same non-root user, with no ports and no Kubernetes
API rights; its script reads only the public certificate files. See
[Limitations](#limitations) for what the shared namespace exposes.

To reload by hand (for example with `openbao_tls_reloader_enabled: false`), after
every renewal:

```bash
kubectl -n openbao exec openbao-0 -c openbao -- sh -c \
  'for p in $(pidof bao); do tr "\000" " " </proc/$p/cmdline | grep -Eq "(^|/)bao server" && kill -HUP $p; done'
# repeat for every pod; or restart the pods one at a time and unseal each
```

## Operator login

The `operator` role (read/write on every layer's KV paths, `read` and `sudo` on
`sys/audit` (listing audit devices is a sudo path), 1h tokens) is bound to the ServiceAccount `openbao-operator` in namespace `openbao`,
which the install creates. To log in from inside a pod:

```bash
# On your workstation: a short-lived ServiceAccount token for the audience
kubectl -n openbao create token openbao-operator --audience vault --duration 10m
kubectl -n openbao exec -ti openbao-0 -c openbao -- sh
# In the pod: paste the token when asked (it goes to bao on stdin, not argv)
printf 'jwt: '; read -r JWT
export BAO_TOKEN=$(printf '%s' "$JWT" | bao write -field=token auth/kubernetes/login role=operator jwt=-)
unset JWT
bao kv list intel-ai/<cluster_id>/erag
bao token revoke -self
```

Use the audience from `openbao_auth_audience` if you changed it.

## Change the bootstrap (generate-root)

You need a temporary root token when:

- the installer reports missing bootstrap markers;
- a bootstrap failed partway (the shares were shown);
- you deliberately change a role or policy.

A quorum of share holders mints the token. The listener keeps OpenBao's legacy,
unauthenticated `sys/generate-root/*` endpoints enabled for this
(`disable_unauthed_generate_root_endpoints = false`), and the NetworkPolicy limits
who can reach them. `bao operator generate-root` in 2.7 uses the authenticated
endpoint, which cannot work without a token. Use `bao write` instead:

```bash
kubectl -n openbao exec -ti openbao-0 -c openbao -- sh

# 1. Start an attempt. Note "nonce" and "otp" (the OTP is needed to decode the token).
bao write -f sys/generate-root/attempt

# 2. Each share holder in turn: paste one share, press Enter, then Ctrl-D.
#    Repeat until "complete" is true. The last response holds "encoded_token".
bao write sys/generate-root/update nonce=<nonce> key=-

# 3. Decode: the token is base64(encoded_token) XOR otp.
printf 'encoded_token: '; read -r enc; printf 'otp: '; read -r otp
while [ $((${#enc} % 4)) -ne 0 ]; do enc="$enc="; done
a=$(printf '%s' "$enc" | base64 -d | od -An -v -tu1 | tr -s ' \n' '  ')
b=$(printf '%s' "$otp" | od -An -v -tu1 | tr -s ' \n' '  ')
export BAO_TOKEN=$(printf '%s\n%s\n' "$a" "$b" | awk 'NR==1{n=split($0,x," ")} NR==2{split($0,y," "); for(i=1;i<=n;i++) printf("%c", xor(x[i],y[i]))}')
unset enc otp a b

# 4. Make the change. To restore, complete or extend the installer's bootstrap
#    (a missing role, policy, KV mount or auth/kubernetes; a new layer in
#    openbao_layers), pipe the token into the bootstrap's apply mode.
#    The installer prints the exact command (with this env's values) when it finds
#    missing bootstrap markers; it looks like this:
printf '%s\n' "$BAO_TOKEN" | env OB_KV_MOUNT=intel-ai OB_CLUSTER_ID=<cluster_id> ... \
  /bin/sh /openbao/userconfig/openbao-bootstrap/bootstrap.sh apply erag:erag-secrets:erag-secrets-worker
#    It creates what is missing (it never replaces a mount or auth method of the
#    wrong type), rewrites every policy and role, checks the audit device and the
#    bootstrap markers, prints one JSON line ("state":"applied") and revokes the token.
#    Other changes by hand, for example:
bao policy list
bao read auth/kubernetes/role/erag-secrets-worker

# 5. Always revoke the temporary token (apply already did) and leave the shell.
bao token revoke -self
unset BAO_TOKEN
exit
```

The apply mode refuses to run when OpenBao is sealed or not initialized
(`"state":"sealed"`, ...), when no token arrives on stdin (`token_missing`) or the
token does not work (`token_invalid`); it changes nothing then. Roles of a layer you
removed from `openbao_layers` are not deleted: delete them by hand.

If an attempt is left half done, cancel it with
`bao delete sys/generate-root/attempt`.

## Revoke a leftover root token

The installer stops with "root token may still be valid" when the script could not
confirm that it revoked the init root token. The script runs the revoke on exit;
this message means the revoke failed or the script was killed. Mint a temporary
token as described in [Change the bootstrap (generate-root)](#change-the-bootstrap-generate-root)
(steps 1-3). Then, in the same shell:

```bash
# The init token's accessor is in the install log ("Root token revoked (accessor ...)")
# when it could be read. Otherwise list the accessors and look each one up:
bao list auth/token/accessors
bao token lookup -accessor <accessor>      # policies [root] and no TTL = a root token
bao token revoke -accessor <accessor>      # every root token except your own
bao token revoke -self
```

## Lost unseal shares

Without `openbao_key_threshold` shares, sealed data cannot be recovered. This
happens when:

- the shares were never shown, for example because the exec connection broke during
  init;
- fewer than the threshold were kept.

If OpenBao is still unsealed, keep it running. Use the time to move secrets out
through their normal consumers.

To start over, delete OpenBao **with its data**, and with it every secret it held,
then install again:

```bash
./es_auto_installer.sh teardown openbao --env <env> -- -e openbao_teardown_delete_data=true
./es_auto_installer.sh install platform --env <env>
```

The new instance has new credentials. Layers that stored credentials in it
re-create theirs on their next install. Data that was protected by the old
credentials, such as database passwords already set on servers, may need those
layers to be reinstalled.

## External OpenBao

With `openbao_mode: external` the installer uses an OpenBao that you run. `install`
and `validate` only **check** it from the installer host. They never write its
configuration. The installer's requests change nothing in its configuration: the
`operator` login creates one short-lived token (and audit log entries, like every
request), and `auth/token/revoke-self` revokes that token at the end. You create the KV mount, Kubernetes
auth, policies, roles and the audit device beforehand, with the template below.

Set in `env/<env>/global_config.yaml`:

```yaml
secrets_backend: openbao
openbao_mode: external
openbao_address: https://openbao.example.com:8200   # https only, host and port
openbao_ca_file: /path/on/installer/host/openbao-ca.pem   # CA certificate, no key
openbao_cluster_id: cluster-a                       # required, unique per cluster
openbao_auth_mount: kubernetes                      # e.g. k8s-cluster-a when clusters share an OpenBao
openbao_kv_mount: intel-ai
```

Preflight fails, naming the key, when `openbao_address` is empty or not `https://`,
`openbao_ca_file` is empty, missing or holds no certificate (or a private key), or
`openbao_cluster_id` is empty. `openbao_route_enabled: true` is rejected: the route
is for internal mode only.

On the cluster the installer creates only namespace `openbao`, ServiceAccount
`openbao-operator` (bound by the `operator` role) and ConfigMap `openbao-ca-bundle`
(key `ca.crt`, copied from `openbao_ca_file`). Then it checks, and stops before ESO
and the layers if a check fails:

1. `sys/health` answers over TLS with `openbao_ca_file`, and OpenBao is initialized
   and unsealed. If it cannot connect, check the address, the CA, and the proxy: with
   `http(s)_proxy` set, add the OpenBao host to `no_proxy` or set
   `openbao_external_use_proxy: false`.
2. Tokenless login probes on `auth/<openbao_auth_mount>/login` find the auth mount,
   its configuration and every role: `eso-<layer>`, `<layer>-secrets-worker`,
   `<layer>-secrets-importer` per layer in `openbao_layers`, and `operator`.
3. It logs in as `operator` with a 10-minute TokenRequest token for
   `openbao-operator` (audience `openbao_auth_audience`), checks that
   `openbao_kv_mount` is KV version 2 and that at least one audit device is enabled
   (AD-18), then revokes its token.

The login needs OpenBao to call this cluster's TokenReview API: `kubernetes_host`
must be reachable from OpenBao, and the reviewer must be allowed to review tokens.
Create a reviewer ServiceAccount and give its token to the template:

```bash
kubectl create namespace openbao --dry-run=client -o yaml | kubectl apply -f -
kubectl -n openbao create serviceaccount openbao-token-reviewer
kubectl create clusterrolebinding openbao-token-reviewer \
  --clusterrole=system:auth-delegator --serviceaccount=openbao:openbao-token-reviewer
kubectl -n openbao create token openbao-token-reviewer --duration 8760h > reviewer.jwt
kubectl -n kube-system get cm kube-root-ca.crt -o jsonpath='{.data.ca\.crt}' > k8s-ca.pem
```

The reviewer token expires: the API server may cap `--duration` well below the
requested value. When it expires, every Kubernetes-auth login for this cluster fails
until you write a new one to `auth/<openbao_auth_mount>/config` (re-run the
template). A Secret of type `kubernetes.io/service-account-token` gives a
non-expiring token instead, but that is a long-lived credential that can review any
token of the cluster: store and rotate it like one. Deleting the reviewer
ServiceAccount, or its namespace (`teardown` keeps namespace `openbao`; deleting it by
hand removes the reviewer too), also breaks every login for the cluster.

Without `REVIEWER_JWT_FILE`, OpenBao reviews each client's own token, and every
client ServiceAccount then needs `system:auth-delegator`.

### Template

Run it once per cluster as an OpenBao administrator (`BAO_ADDR`, `BAO_CACERT` and a
token that may manage mounts, auth methods, policies and audit devices). It mirrors
the internal bootstrap (`roles/openbao/files/bootstrap.sh`), with two differences
for a shared OpenBao: policies are global, so their names start with the cluster id
(`<cluster_id>-operator`, ...), and each cluster has its own auth mount. The KV
mount is shared; every path is under `<cluster_id>/`. It is safe to re-run. It stops, changing nothing more, when `auth/<AUTH_MOUNT>/config`
already points at another cluster's API (use another `AUTH_MOUNT`, or `FORCE=1` to
overwrite), when a `LAYERS` entry is not `<layer>:<namespace>:<serviceaccount>`, and
when the token cannot list audit devices (needs `sudo` on `sys/audit`). If a check
fails, the installer's message prints the exact `export` line for this cluster.

```bash
export CLUSTER_ID=cluster-a AUTH_MOUNT=kubernetes \
  K8S_HOST=https://api.cluster-a.example.com:6443 K8S_CA_FILE=k8s-ca.pem REVIEWER_JWT_FILE=reviewer.jwt
sh roles/openbao/files/external-template.sh
```

The script is `roles/openbao/files/external-template.sh`. It sources
`roles/openbao/files/access.sh` from its own directory (the same mount, policy and
role writes as the internal bootstrap), so run it from a checkout of this repo, or
copy both files into one directory. Its header lists every variable and default.

If no audit device is enabled, the template tries `bao audit enable`. OpenBao 2.7
refuses audit devices created through the API, so it then stops: declare the device
in the server configuration, restart OpenBao and re-run the template. There is no
`backup` role in external mode: backing up your OpenBao is up to you. Then run
`./es_auto_installer.sh install platform --env <env>`.

`teardown` removes the ServiceAccount and the ConfigMap. It never touches your
OpenBao or the secrets in it.

To log in as `operator` (from a workstation with `kubectl` and the `bao` CLI), use
your auth mount:

```bash
export BAO_ADDR=https://openbao.example.com:8200 BAO_CACERT=/path/to/openbao-ca.pem
JWT=$(kubectl -n openbao create token openbao-operator --audience vault --duration 10m)
export BAO_TOKEN=$(printf '%s' "$JWT" | bao write -field=token auth/<openbao_auth_mount>/login role=operator jwt=-)
unset JWT
bao kv list intel-ai/<cluster_id>/erag
bao token revoke -self
```

## Route

With `openbao_mode: internal` and `openbao_route_enabled: true`, the install publishes
`https://openbao.<base_domain_name>` on `eg-gateway` (the `https` listener only, with
HSTS), so operators can use the `bao` CLI from outside the cluster. The gateway
re-encrypts to `openbao-active:8200` and checks the server certificate against the
role CA (`BackendTLSPolicy` with ConfigMap `openbao-ca-bundle`, hostname
`openbao-active.openbao.svc`). The gateway's JWT policy is off for this route
(`SecurityPolicy openbao-no-auth`), because OpenBao authenticates every request.

Only these paths are forwarded. Every other path, including `sys/generate-root`,
`sys/unseal`, `sys/init`, `sys/seal-status`, `sys/rekey` and `sys/health`, gets a 404
from Envoy:

| Path | Type |
| --- | --- |
| `/v1/<openbao_kv_mount>` | prefix |
| `/v1/sys/internal/ui/mounts/<openbao_kv_mount>` | prefix |
| `/v1/auth/<openbao_auth_mount>/login` | exact |
| `/v1/auth/token/lookup-self`, `renew-self`, `revoke-self` | exact |

`openbao.<base_domain_name>` is reserved to namespace `openbao` in
`gateway_protected_hostnames` whenever `secrets_backend: openbao`, so no other
namespace can claim it. Setting `openbao_route_enabled: false` and re-running the
install removes the route objects. The route needs Envoy Gateway with Gateway API
v1.4 or later (`BackendTLSPolicy` v1) and a gateway certificate that covers
`openbao.<base_domain_name>`. Log in through it with a ServiceAccount token, as in
[Operator login](#operator-login):

```bash
export BAO_ADDR=https://openbao.<base_domain_name> BAO_CACERT=<gateway CA>
printf 'jwt: '; read -r JWT
export BAO_TOKEN=$(printf '%s' "$JWT" | bao write -field=token auth/kubernetes/login role=operator jwt=-)
unset JWT
bao kv list intel-ai/<cluster_id>/erag
bao token revoke -self
```

## External Secrets Operator

After `openbao`, the platform layer installs and owns External Secrets Operator (component
`external_secrets`, chart `external-secrets` pinned by `external_secrets_chart_version`
in `roles/external_secrets/defaults/main.yaml`) in namespace `external-secrets`. For each
layer `L` in `openbao_layers` it creates one `ClusterSecretStore openbao-L`:

- the stable `vault` provider, KV v2 at `openbao_kv_mount`. The server is
  `https://openbao-active.openbao.svc:8200` in internal mode and `openbao_address` in
  external mode. It trusts ConfigMap `openbao/openbao-ca-bundle` (key `ca.crt`).
- Kubernetes auth at `auth/<openbao_auth_mount>` as role `eso-L`, with a token that
  ESO requests for its own ServiceAccount `external-secrets/external-secrets` (audience
  `openbao_auth_audience`). The controller may mint tokens only for that
  ServiceAccount: the chart's cluster-wide `serviceaccounts/token` grant is off.
- Only namespaces labelled `secrets.ai-solutions/L: "true"` may use it.

The install fails if the cluster already runs an ESO from another installation
(its CRDs belong to another Helm release).

The install waits until every store is `Ready` with reason `Valid`, which means ESO
logged in to OpenBao. `validate` checks the release, the Deployments, the stores and
the admission policy. If a store is not valid, the install prints its condition. Check
that OpenBao is unsealed, that role `eso-L` exists and is bound to
`external-secrets/external-secrets`, the OpenBao NetworkPolicy, and
`kubectl -n external-secrets logs deploy/external-secrets`. In external mode without a
reviewer JWT, the ESO ServiceAccount also needs `system:auth-delegator` (see
[External OpenBao](#external-openbao)).

### Which paths a namespace may read

ValidatingAdmissionPolicy `openbao-externalsecret-paths` checks every ExternalSecret
that uses an `openbao-L` store. The store is `data[].sourceRef.storeRef`,
`dataFrom[].sourceRef.storeRef` or `spec.secretStoreRef`. Every such entry must
satisfy all of these rules:

- The namespace carries the label `secrets.ai-solutions/L: "true"`.
- The entry is `data[].remoteRef.key` or `dataFrom[].extract.key`. `dataFrom.find` is
  refused.
- The key is `<cluster_id>/<path>`, where `<path>` lies under `L/` and is listed in
  the namespace annotation `secrets.ai-solutions/L-paths`: a comma-separated list of
  paths relative to `<cluster_id>/`.

The layer writes the label and the annotation when it creates its ExternalSecrets.
For example:

```yaml
metadata:
  labels:
    secrets.ai-solutions/erag: "true"
  annotations:
    secrets.ai-solutions/erag-paths: "erag/keycloak/erag-admin,erag/keycloak/mcp-client"
# admitted: remoteRef.key: <cluster_id>/erag/keycloak/erag-admin
```

Write keys in exactly this form, without the `<mount>/` or `<mount>/data/` prefix.
ExternalSecrets that use other stores, or generators, are not restricted. Neither are
PushSecrets: writes through an `openbao-L` store fail because the `eso-L` OpenBao
policy is read-only. A denied
request names the namespace, the store and the key. When an ExternalSecret stops
syncing (`SecretSyncedError`), `kubectl describe externalsecret` shows why. The
projected Secret keeps its last value.

### Upgrade and teardown

To upgrade ESO, read the ESO release notes for CRD changes, bump
`external_secrets_chart_version` in `roles/external_secrets/defaults/main.yaml` and run
`./es_auto_installer.sh install external_secrets --env <env> --only` (the install is
idempotent and upgrades the release, then re-applies the stores and the policy). `teardown` removes the policy, the `openbao-*` stores, the release
and the namespace. The ESO CRDs are kept (`helm.sh/resource-policy: keep`), so
ExternalSecrets that are left over, and the Secrets they own, are kept but no longer
refreshed. The run prints how many still use an OpenBao store. To delete the CRDs,
pass `-e external_secrets_teardown_delete_crds=true`. The run refuses while any ESO
object other than the installer's stores exists (ExternalSecrets, PushSecrets, other
stores, generators), so tear the layers down first.

## Backup and restore

With internal OpenBao, the `openbao` role provides two hooks for backup profiles
(`configs/backup.yaml`, hook kind `role`). Any profile that backs up data whose
credentials live in OpenBao must include them, so that a restore brings back
credentials that match the restored databases:

```yaml
namespace_order:
  - openbao-backup              # openbao_backup_namespace: the snapshot PVC
  # ... the profile's own namespaces
pre_backup:
  - kind: role
    name: "OpenBao raft snapshot"
    role: openbao
    tasks_from: snapshot_backup.yaml
  # ... other hooks
post_restore:
  - kind: role                  # first: before hooks that restart consumers
    name: "OpenBao raft snapshot restore"
    role: openbao
    tasks_from: snapshot_restore.yaml
  # ... other hooks
```

Both hooks do nothing (with a message) unless `secrets_backend: openbao` and
`openbao_mode: internal`, so a profile can list them unconditionally. The erag
profile (`deployment/backup_profile.yaml` in enterprise-rag) is owned by the erag
layer.

**Backup.** `snapshot_backup.yaml` runs a Job in namespace `openbao-backup`. It logs in
to OpenBao as role `backup` with a projected, audience-bound token of ServiceAccount
`openbao-snapshot` and writes `bao operator raft snapshot save` output to PVC
`openbao-snapshot` (`openbao.snap` and `openbao.snap.sha256`). The Job is deleted
afterwards, and the backup captures the namespace. The snapshot never passes through
the installer host or a `capture` hook. It is encrypted by OpenBao: it is useless
without the unseal shares, and the shares are not in any backup. Keep them.

Namespace `openbao` itself must never be in a profile. A restore deletes every PVC of
the backup (the live Raft volumes) and replays every object over the running one.

**Restore.** The backup engine replaces the PVC with the one from the backup. Then
`snapshot_restore.yaml` checks the checksum and runs
`bao operator raft snapshot restore -force`. OpenBao returns to the state of the
backup for **every layer's** paths: credentials created or rotated after the backup are
gone. In the same cluster OpenBao stays unsealed. The hook then annotates every
ExternalSecret on an `openbao-*` store with `force-sync`, so the projected Secrets
follow at once instead of after `eso_refresh_interval`. Pods that read a Secret only
at start still need their usual restart; the profile's own hooks do that.

### Restore into a new cluster

The snapshot belongs to the OpenBao that took it. Restoring it into another OpenBao,
for example a cluster rebuilt after a loss and installed fresh (with new shares), works
(`-force`), but OpenBao is then **sealed**, and the hook fails with the commands to
unseal it. Unseal every pod, `openbao-0` first, with the shares of the **original**
cluster. From then on those are the cluster's shares and its bootstrap is the
original one; the new init's shares are void. Then restart the ESO controller
(`kubectl -n external-secrets rollout restart deploy`) and re-run the install so that
validate passes. Without the original shares the snapshot cannot be used.

## Limitations

- **Secrets changed outside OpenBao.** OpenBao is the only source. A credential that is
  changed somewhere else is not detected: for example a client secret regenerated in the
  Keycloak UI, or a password changed in a database. The service and OpenBao then
  disagree until you write the new value to OpenBao. A change to a projected Secret
  (`kubectl edit`) is overwritten by ESO at its next refresh (`eso_refresh_interval`), or
  earlier on a force-sync.
- **One `secrets_backend` per env.** `secrets_backend` is one global key: every layer
  and solution of the env uses the same backend; there is no per-solution choice.
  Switching an env from
  `openbao` back to `local` is not supported: the layers would generate new credentials
  against existing databases.
- Where each layer's credentials are, and how to migrate, rotate and tear them down: for
  erag, [Credentials in OpenBao](https://github.com/intel/enterprise-rag/blob/main/docs/deploy/openbao.md)
  in Intel® AI for Enterprise RAG.
- The legacy generate-root endpoints (`sys/generate-root/*`) are enabled and
  unauthenticated, like `sys/health`, `sys/seal-status`, `sys/unseal` and the
  mount listing of the KV mount. Anyone who can reach port 8200 can start or cancel
  a root generation attempt; completing one needs the threshold of shares. The
  NetworkPolicy limits port 8200 to the `openbao` and ESO namespaces, each layer's
  secrets namespace and, with `openbao_route_enabled`, the gateway. The route
  itself forwards none of these endpoints.

- Re-runs and `validate` check the KV mount, auth and roles, but not the policy
  contents. The checks run without a token, and policies cannot be read without one.
- The `operator` role is shared, so audit records cannot be attributed to a person.
- The `tls-reloader` sidecar shares the server pod's process namespace and runs as the
  same user as the server. Code running in the sidecar could therefore read the
  server's `/proc/<pid>/environ` and, through `/proc/<pid>/root`, the server
  container's files, including `tls.key` and the (encrypted) Raft data. On nodes where
  `kernel.yama.ptrace_scope` is 0, it could also attach to the server and read its
  memory, which holds the unsealed keys. A different user would need `CAP_KILL` to
  send the signal, which PSS restricted forbids. The sidecar runs only `tls-reload.sh`
  from the role's ConfigMap, in the pinned server image, with no ports and no API
  rights, so this matters only if that image or ConfigMap is compromised. Set
  `openbao_tls_reloader_enabled: false` to drop it; a renewed certificate is then
  served only after a manual SIGHUP or a pod restart
  ([Server certificate renewal](#server-certificate-renewal)).
- The route allowlist relies on Envoy Gateway's default path normalization (RFC 3986,
  merged slashes): a request such as `/v1/intel-ai/../sys/generate-root` is matched as
  `/v1/sys/generate-root` and gets a 404. This was not verified against a running
  gateway.
- External mode checks roles by name and the KV mount and audit device with the
  operator token. It does not read the other roles' bindings or policies.
- The CA bundle ConfigMap is refreshed on every install. After the internal CA is
  renewed (10-year CA, renewed 30 days before expiry), re-run the install so that the
  gateway and the clients trust the new CA.
- The ExternalSecret path policy acts at admission. If you remove a path from a
  namespace annotation, or the label from a namespace, ExternalSecrets that already
  exist are not re-checked. The store's `namespaceSelector` still stops an unlabelled
  namespace at sync time. Delete stale ExternalSecrets yourself.
- The cluster id must differ from `openbao_kv_mount`: the ESO `vault` provider strips
  a leading `<mount>/` from every key. Preflight rejects that combination.
