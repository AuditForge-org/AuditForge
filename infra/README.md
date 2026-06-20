<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Deploying Forensiq to production

This document walks through a from-scratch production deployment on AWS (EKS + RDS + ElastiCache + S3 + ECR). The architecture transfers to GCP/Azure with provider swaps; the resource shapes are portable.

Estimated end-to-end time: **2-3 hours** for first deploy, ~5 minutes per subsequent release once CI is wired up.

## Layout

```
infra/
├── k8s/             # Kubernetes manifests, applied in numerical order
│   ├── 00-namespace.yaml         pod-security standards: restricted
│   ├── 10-secrets.yaml           secret skeleton (replace with sealed-secrets / external-secrets)
│   ├── 20-rbac.yaml              ServiceAccounts + IRSA annotations
│   ├── 30-networkpolicy.yaml     deny-by-default ingress/egress
│   ├── 40-data.yaml              postgres + redis (for non-managed deployments)
│   ├── 50-api.yaml               API Deployment + HPA + PDB
│   ├── 60-worker.yaml            Worker Deployment
│   ├── 70-ingress.yaml           ingress + cert-manager
│   ├── 80-migrate-backup.yaml    init/migration + CronJob backups
│   ├── 90-monitoring.yaml        ServiceMonitor for Prometheus operator
│   └── 95-keda-scaler.yaml       queue-depth based worker autoscaling
└── terraform/
    ├── main.tf
    ├── variables.tf
    └── prod.tfvars.example
```

## Architecture

```
                       ┌────────────────┐
                       │  Route 53 +    │
                       │  ACM TLS cert  │
                       └────────┬───────┘
                                ▼
                      ┌─────────────────┐
                      │ NLB / ALB       │
                      │ (k8s ingress)   │
                      └─────────┬───────┘
                                ▼
   ┌────────────────────────────────────────────────────────┐
   │                       EKS cluster                       │
   │  ┌─────────────┐                  ┌────────────────┐   │
   │  │ API pods    │ ──BullMQ jobs─►  │ Worker pods    │   │
   │  │ (HPA 3-20)  │                  │ (KEDA 2-30)    │   │
   │  └──────┬──────┘                  └────────┬───────┘   │
   │         │                                  │           │
   │         │ /metrics → Prometheus           │           │
   │         │                                  │ docker-in-docker │
   │  ┌──────▼──────────────────────────────────▼──────┐    │
   │  │  Service mesh (default cluster DNS)            │    │
   │  └─────────┬──────────────────────────┬───────────┘    │
   └────────────│──────────────────────────│───────────────┘
                ▼                          ▼
       ┌────────────────┐         ┌────────────────┐
       │ RDS Postgres   │         │ ElastiCache    │
       │ Multi-AZ       │         │ Redis HA       │
       └────────────────┘         └────────────────┘

                ┌──────────────┐
                │ S3: reports + │  ← worker writes via IRSA
                │ raw outputs   │
                └──────────────┘
```

## Step 1 — Terraform: provision infrastructure

```bash
cd infra/terraform

# First-time setup: create a state bucket + lock table for collaboration
aws s3api create-bucket --bucket forensiq-tfstate --region us-east-1
aws s3api put-bucket-versioning --bucket forensiq-tfstate \
  --versioning-configuration Status=Enabled
aws dynamodb create-table --table-name forensiq-tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Edit main.tf to uncomment the `backend "s3"` block.

cp prod.tfvars.example prod.tfvars
# Edit prod.tfvars with your domain, instance sizes, region.

terraform init
terraform plan -var-file=prod.tfvars
terraform apply -var-file=prod.tfvars
```

Capture outputs (use a real secret manager — these are operator-side intermediates):

```bash
mkdir -p .secrets
terraform output -raw database_url       > .secrets/PROD_DATABASE_URL
terraform output -raw redis_url          > .secrets/PROD_REDIS_URL
terraform output -raw ecr_repository_url > .secrets/ECR_URL
terraform output -raw reports_bucket     > .secrets/S3_BUCKET
terraform output -raw worker_iam_role_arn > .secrets/WORKER_ROLE_ARN
```

## Step 2 — Cluster add-ons

```bash
aws eks update-kubeconfig --name forensiq

# nginx ingress controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/aws/deploy.yaml

# cert-manager + Let's Encrypt ClusterIssuer
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.5/cert-manager.yaml
kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: { name: letsencrypt-prod }
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@forensiq.example.com
    privateKeySecretRef: { name: letsencrypt-prod-key }
    solvers:
      - http01:
          ingress: { class: nginx }
EOF

# KEDA for queue-depth based worker scaling
helm repo add kedacore https://kedacore.github.io/charts && helm repo update
helm install keda kedacore/keda --namespace keda --create-namespace

# Prometheus + Grafana (optional but recommended)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace
```

## Step 3 — Register GitHub Apps

See [docs/auth.md](../docs/auth.md) and [docs/github-app.md](../docs/github-app.md). You need **two** GitHub Apps:

- **OAuth App** — user login. Callback: `https://<host>/api/auth/github/callback`
- **GitHub App** — repo integration. Webhook: `https://<host>/api/gh/app`

Capture: Client ID/Secret for OAuth, App ID/private-key/webhook-secret for the App.

## Step 4 — Push application image

The CI workflow does this on tag pushes. To deploy manually:

```bash
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin $(cat infra/terraform/.secrets/ECR_URL)

cd backend
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile.app \
  -t $(cat ../infra/terraform/.secrets/ECR_URL):v1.0.0 \
  --push .

# Engine images (one-time, ~20 min)
for engine in slither aderyn mythril semgrep solhint echidna; do
  docker buildx build --platform linux/amd64 \
    -f docker/${engine}.Dockerfile \
    -t $(cat ../infra/terraform/.secrets/ECR_URL)-${engine}:latest \
    --push docker
done
```

## Step 5 — Create cluster secrets

The Secret in `k8s/10-secrets.yaml` is a **skeleton**. Create the real values:

```bash
kubectl create namespace forensiq

kubectl -n forensiq create secret generic forensiq-secrets \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=ANTHROPIC_API_KEY=sk-ant-... \
  --from-literal=GITHUB_OAUTH_CLIENT_ID=Iv1.xxx \
  --from-literal=GITHUB_OAUTH_CLIENT_SECRET=... \
  --from-literal=GITHUB_APP_ID=123456 \
  --from-literal=GITHUB_APP_PRIVATE_KEY="$(base64 -i forensiq-app.pem)" \
  --from-literal=GITHUB_APP_WEBHOOK_SECRET=... \
  --from-literal=ETHERSCAN_API_KEY=... \
  --from-literal=SENDGRID_API_KEY=...

# Connection strings come from terraform outputs
kubectl -n forensiq create configmap forensiq-config \
  --from-literal=NODE_ENV=production \
  --from-literal=PORT=3000 \
  --from-literal=WORKER_CONCURRENCY=8 \
  --from-literal=ANTHROPIC_MODEL=claude-opus-4-7 \
  --from-literal=PUBLIC_URL=https://forensiq.example.com \
  --from-literal=FRONTEND_URL=https://forensiq.example.com \
  --from-literal=DATABASE_URL="$(cat infra/terraform/.secrets/PROD_DATABASE_URL)" \
  --from-literal=REDIS_URL="$(cat infra/terraform/.secrets/PROD_REDIS_URL)" \
  --from-literal=S3_REPORTS_BUCKET="$(cat infra/terraform/.secrets/S3_BUCKET)" \
  --from-literal=AWS_REGION=us-east-1
```

Production-grade secret management options:
- **External Secrets Operator** — pulls live from AWS Secrets Manager / Vault
- **sealed-secrets** — encrypt YAML and commit to git for GitOps
- **SOPS + age** — encrypted-at-rest YAML in git

## Step 6 — Apply manifests

```bash
# Patch the image references in 50-api.yaml + 60-worker.yaml to use your
# ECR URL @ the digest you just pushed. Then:
kubectl apply -f infra/k8s/

# Wait for everything to come up
kubectl -n forensiq rollout status deployment/forensiq-api    --timeout=5m
kubectl -n forensiq rollout status deployment/forensiq-worker --timeout=10m
```

## Step 7 — Bootstrap the database

```bash
psql "$(cat infra/terraform/.secrets/PROD_DATABASE_URL)" < backend/docker/init.sql
```

Idempotent — uses `CREATE TABLE IF NOT EXISTS` throughout.

## Step 8 — Configure DNS

```bash
# Get the ingress LB hostname
kubectl -n forensiq get ingress -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}'

# Create a Route53 ALIAS forensiq.example.com → that hostname.
# cert-manager will provision the TLS cert via HTTP-01 within ~60s.
```

## Step 9 — Smoke test

```bash
curl https://forensiq.example.com/api/health
# {"ok":true,"time":"..."}
```

Open the app, sign in with GitHub, submit a paste audit, watch it process, view the report.

## Step 10 — Wire up CI for future releases

GitHub secrets to set in the `production` environment:

| Secret | From |
|---|---|
| `AWS_ROLE_TO_ASSUME` | IAM role ARN with OIDC trust to GitHub |
| `AWS_REGION` | e.g. `us-east-1` |
| `ECR_REPOSITORY` | `forensiq` |
| `EKS_CLUSTER_NAME` | `forensiq` |
| `PROD_DATABASE_URL` | terraform output |
| `PROD_REDIS_URL` | terraform output |
| `PROD_HOST` | `forensiq.example.com` |

OIDC setup gives GitHub Actions short-lived AWS creds without static keys:
https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services

After that, tag and push:

```bash
git tag v1.0.0
git push origin v1.0.0
```

`release.yml` validates, builds, pushes to ECR, applies manifests, waits for rollout, smoke-tests, and Slacks on success/failure.

## Operational runbook

### Rollback

```bash
kubectl -n forensiq rollout undo deployment/forensiq-api
kubectl -n forensiq rollout undo deployment/forensiq-worker
```

### Inspect the queue

```bash
kubectl -n forensiq port-forward svc/redis 6379:6379 &
redis-cli LLEN "bull:audits:wait"        # pending
redis-cli LLEN "bull:audits:active"      # in-flight
redis-cli ZCARD "bull:audits:completed"  # done (recent)
```

### Stuck audit

```bash
kubectl -n forensiq logs -l app.kubernetes.io/component=worker --tail=200 | grep <auditId>
```

### Database backup test

```bash
# Manual snapshot
aws rds create-db-snapshot --db-instance-identifier forensiq \
  --db-snapshot-identifier forensiq-manual-$(date +%Y%m%d)

# Test restore in a non-prod environment monthly
aws rds restore-db-instance-from-db-snapshot \
  --db-snapshot-identifier forensiq-manual-... \
  --db-instance-identifier forensiq-restore-test
```

### Update Docker base images

```bash
./scripts/pin-images.sh
git diff
git commit -am "chore: bump pinned image digests"
```

## What to know

- **Cost**: minimal deploy (1 NAT, t4g.medium DB, t4g.micro Redis, 2 t3a.large nodes) is ~$200/mo before traffic. Audit-heavy traffic dominates compute; budget accordingly.
- **AGPL compliance**: the footer link in the frontend (`<a href="...">Source code (AGPL-3.0)</a>`) must point at the actual deployed source. If you fork and modify, update the link before deploying.
- **Disaster recovery**: RDS daily backups + 7-day retention covers most failure modes. For a full DR plan, add cross-region snapshot replication and document your RTO/RPO.
