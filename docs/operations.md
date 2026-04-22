# Operations guide

## Running

### Bare metal / VM

```bash
pip install -r requirements.txt
uvicorn aegis.main:app --host 0.0.0.0 --port 8080 --workers 4
```

Put a TLS-terminating reverse proxy (Caddy / Nginx / ALB) in front. Forward
the original `Host` header.

### Docker

```bash
docker compose up --build -d
```

### Kubernetes

A minimal deployment (sketch):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: aegis-gateway }
spec:
  replicas: 3
  selector: { matchLabels: { app: aegis } }
  template:
    metadata: { labels: { app: aegis } }
    spec:
      containers:
        - name: gateway
          image: aegis-ai-gateway:0.1.0
          ports: [{ containerPort: 8080 }]
          envFrom:
            - secretRef: { name: aegis-env }
          readinessProbe:
            httpGet: { path: /healthz, port: 8080 }
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
            initialDelaySeconds: 15
```

For Postgres, set `AEGIS_DATABASE_URL=postgresql+psycopg://...`.

## First-run bootstrap

If the DB has no users, Aegis creates a tenant + admin user from
`AEGIS_BOOTSTRAP_*` env vars on startup. Once you've created real admin
accounts in the console, **delete the bootstrap admin** and remove the
bootstrap variables from your environment.

## Backups

- Postgres: standard PITR snapshots.
- SQLite (dev): the file at `data/aegis.db`. Stop the gateway during backup.
- Audit log: replicate to your immutable store (S3 Object Lock / QLDB / immudb)
  on a Kafka or logical-replication tap from `audit_events`.

## Observability

- `/healthz` for liveness.
- Structured JSON logs include `request_id`, `tenant_id`, `policy_decision`.
- Per-tenant counters: `GET /v1/policy/me` returns the current sliding-window
  decision histogram.
- `/admin/api/dashboard/summary` returns 24h aggregates for dashboards.

Wire Prometheus / OTel via `uvicorn` middleware; the application is plain
FastAPI so any standard instrumentation works.

## Capacity

A single replica comfortably handles thousands of requests per second of
*policy work*; the bottleneck is upstream latency (OpenAI/Anthropic). Scale
horizontally behind any L7 load balancer; sessions are stateless JWTs and
audit writes are simple inserts.

## Upgrades

Migrations: this MVP creates tables on startup with `Base.metadata.create_all`.
For production, swap in Alembic and run migrations as a separate Job before
rolling pods.

## Disaster recovery

- Aegis is stateless except for its DB. Restore the DB and the service is
  back. API keys, policies, and audit history all live in the DB.
- Provider credentials are the only thing that must survive: encrypt them in
  the DB with a KMS-backed key whose ARN is the only thing you must keep
  outside the DB.
