# Secrets with on-prem HashiCorp Vault

The API's JWT signing key lives in HashiCorp Vault. At pod start the **Secrets Store CSI driver** with the **Vault CSI provider** logs in to Vault using the pod's Kubernetes service-account identity, reads the key, and mounts it as a read-only file at `/mnt/secrets/jwt_secret_key`. The app reads it through `SECRET_KEY_FILE`.

The key is never in the Helm chart, in a Kubernetes `Secret` object, in an environment variable, or in the container image.

```
 +--------------------- Kubernetes node ---------------------+
 |                                                            |
 |  vulntracker pod                  Secrets Store CSI driver |
 |  (uid 65532, read-only FS)   <--- + Vault CSI provider     |
 |  /mnt/secrets/jwt_secret_key       |                      |
 +------------------------------------|----------------------+
                                      | 1. login with the pod's service-account
                                      |    token (audience "vault")
                                      v
                          On-prem HashiCorp Vault
                          - auth/kubernetes  (verifies the token with the
                            cluster's TokenReview API)
                          - role vulntracker-api -> policy vulntracker-api-read
                          - secret/data/vulntracker/api  (KV v2)
```

Why this design:

| Choice | Reason |
|---|---|
| Vault **Kubernetes auth** | No static Vault token or password anywhere. The pod proves who it is with a short-lived, audience-bound service-account token that Kubernetes signs. |
| Role bound to **one service account in one namespace** | Another workload (even in the same namespace) cannot log in as this app. Verified: a `default` service-account token gets 403. |
| **Audience** `vault` on the role | A token issued for any other purpose is rejected. Verified: a token without that audience gets 403. |
| **Read-only policy** on a single path | Even with a valid login, the app can only read its own key; it cannot list or write. Vault token TTL is 20 minutes. |
| **CSI file mount**, not a Kubernetes Secret | A Kubernetes Secret is only base64-encoded in etcd and readable by anyone with `get secrets` RBAC. The CSI mount goes straight from Vault into the pod's memory-backed volume. `syncSecret` is disabled. |
| App pod has **no egress to Vault** | The CSI provider on the node talks to Vault, not the app, so the NetworkPolicy stays tight (DNS + notify only) and a compromised app cannot query Vault. |
| `automountServiceAccountToken: false` | The CSI provider requests its own token for the service account; nothing is mounted inside the app container. |

## 1. Vault administrator setup (production, on-prem)

Run once with an admin token, against your Vault cluster (TLS enabled):

```bash
export VAULT_ADDR=https://vault.internal.example.com:8200

# Store the key (KV v2 engine mounted at secret/)
vault kv put secret/vulntracker/api jwt_secret_key="$(openssl rand -base64 48)"

# Read-only policy for exactly that path
vault policy write vulntracker-api-read - <<'EOF'
path "secret/data/vulntracker/api" {
  capabilities = ["read"]
}
EOF

# Kubernetes auth: Vault validates pod tokens with the cluster's TokenReview API
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host=https://<k8s-api-server>:6443 \
  kubernetes_ca_cert=@k8s-ca.crt \
  token_reviewer_jwt="<token of a service account with system:auth-delegator>"

# Role: only this service account, in this namespace, read-only, short TTL
vault write auth/kubernetes/role/vulntracker-api \
  bound_service_account_names=vulntracker \
  bound_service_account_namespaces=vulntracker \
  audience=vault \
  policies=vulntracker-api-read \
  ttl=20m
```

The service-account name is the Helm release's full name (`<release>-vulntracker`, or `vulntracker` when the release is named `vulntracker`).

Token reviewer account (in the cluster):

```bash
kubectl create serviceaccount vault-token-reviewer -n kube-system
kubectl create clusterrolebinding vault-token-reviewer \
  --clusterrole=system:auth-delegator --serviceaccount=kube-system:vault-token-reviewer
kubectl get configmap kube-root-ca.crt -n kube-system -o jsonpath='{.data.ca\.crt}' > k8s-ca.crt
```

## 2. Cluster setup

```bash
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm repo add hashicorp https://helm.releases.hashicorp.com

# CSI driver; syncSecret disabled so no Kubernetes Secret copy is ever created
helm install csi secrets-store-csi-driver/secrets-store-csi-driver \
  --version 1.6.0 -n kube-system --set syncSecret.enabled=false

# Vault CSI provider only (Vault itself runs outside the cluster)
helm install vault-csi hashicorp/vault --version 0.34.0 -n vault-csi --create-namespace \
  --set server.enabled=false --set injector.enabled=false --set csi.enabled=true
```

## 3. Deploy the app

```bash
kubectl create namespace vulntracker
kubectl label namespace vulntracker pod-security.kubernetes.io/enforce=restricted

helm upgrade --install vulntracker helm/vulntracker -n vulntracker \
  --set image.repository=<registry>/vulntracker-api \
  --set image.digest=sha256:<digest-from-ci> \
  --set secrets.vault.address=https://vault.internal.example.com:8200 \
  --set secrets.vault.caCertPath=/etc/ssl/certs/internal-ca.pem
```

To use AWS Secrets Manager instead: `--set secrets.provider=aws` plus the `secrets.aws.*` values.

## 4. How this was tested

The full flow was run locally on 2026-10-24 with:

* **kind** v0.33.0 (Kubernetes v1.37.0) as the cluster, with a local registry so the image is deployed **by digest**.
* **Vault 2.0.3 running as a separate container outside the cluster** (on the same Docker network), standing in for the on-prem server. Dev mode, HTTP, for the test only.
* Secrets Store CSI driver 1.6.0 and Vault CSI provider 1.7.3 (chart 0.34.0).
* The real application image and this Helm chart, in a namespace enforcing Pod Security **restricted**.

Results:

| Check | Result |
|---|---|
| Pod starts (the app refuses to start without a valid key) | Running, Ready |
| Key in the pod matches the key in Vault | SHA-256 match (value never printed) |
| Environment variables | Only `SECRET_KEY_FILE=/mnt/secrets/jwt_secret_key` |
| Kubernetes Secrets in the namespace | Only Helm's own release record; no app secret |
| Container user / filesystem | uid 65532, root filesystem read-only |
| Service-account token in the pod | Not mounted |
| App end to end (register, login, scan, password-protected share link) | Works |
| Vault login with another service account's token | **403** |
| Vault login with a token for a different audience | **403** |
| Vault login with the app's own token | Gets only `vulntracker-api-read`, 20-minute TTL |
| Checkov on the updated chart | 96 passed, 0 failed |

Reproduce it:

```bash
# Cluster + local registry
kind create cluster --name vt --config kind.yaml        # containerd config_path = /etc/containerd/certs.d
docker run -d -p 127.0.0.1:5001:5000 --name kind-registry registry:2
docker network connect kind kind-registry
docker exec vt-control-plane sh -c 'mkdir -p /etc/containerd/certs.d/localhost:5001 &&
  printf "[host.\"http://kind-registry:5000\"]\n" > /etc/containerd/certs.d/localhost:5001/hosts.toml'

# App image by digest
docker build -t localhost:5001/vulntracker-api:test . && docker push localhost:5001/vulntracker-api:test

# "On-prem" Vault outside the cluster
docker run -d --name onprem-vault --network kind -p 127.0.0.1:8200:8200 --cap-add IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root-token -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 hashicorp/vault:2.0.3

# Then sections 1-3 above, with
#   kubernetes_host=https://vt-control-plane:6443
#   --set secrets.vault.address=http://onprem-vault:8200 --set ingress.enabled=false

# Clean up
kind delete cluster --name vt && docker rm -f onprem-vault kind-registry
```

**Not production settings:** the test Vault ran in dev mode over HTTP with a root token. Production Vault must use TLS (set `secrets.vault.caCertPath`), be initialised and unsealed properly (ideally auto-unseal with an HSM or KMS), have audit logging enabled, and never use the root token for day-to-day work.
