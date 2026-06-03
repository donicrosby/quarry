# Kubernetes Scale Plan

This document describes the path from the current single-process local harness to a
horizontally-scaled Kubernetes deployment. It is a design doc — no manifests or Helm
charts are included.

## Current state

Everything runs on one machine:

- `quarry_server` — FastAPI app with an in-process Temporal worker (lifespan hook). All
  activities run in a `ThreadPoolExecutor(max_workers=10)` on the same process.
- `quarry_worker` — standalone alternative worker for the same `quarry-control` task queue.
- Artifacts — `LocalArtifactStore` in `quarry_artifacts` writes blobs to the local filesystem
  under `.quarry/artifacts/`.
- Database — SQLite via SQLAlchemy in `quarry_persistence`, file at `.quarry/quarry.db`.
- Temporal server — single-node, run via `docker compose -f docker-compose.temporal.yml up`.

This works for a single developer running one scan at a time. It breaks under concurrency
(SQLite write contention), across nodes (no shared FS or DB), and at volume (one process,
one queue).

## Worker pools and task queues

Today all activities share `quarry-control`. The split point is activity character:

| Pool | Task queue | Activities | Worker sizing |
|---|---|---|---|
| **Scan** | `quarry-control` | snapshot, attack-surface, secrets/IDOR/cmdi scanning, coverage ledger | CPU-bound; scale on Temporal backlog |
| **Model/tool** | `quarry-model` | model invocations, validation, proof execution | I/O-bound; scale on queue depth + latency SLO |
| **Persistence** | `quarry-persist` | `persist-scan-state`, integration delivery | Low concurrency; 1–2 replicas |

The server no longer runs an in-process worker in this model — it becomes a pure API gateway
that enqueues work. Workers are standalone `quarry_worker`-style processes deployed as
Kubernetes `Deployment` objects.

To add a queue today: pass `task_queue="quarry-model"` to `Worker(...)` in `quarry_worker/main.py`
and update the `@activity.defn` + workflow `schedule_activity` call to target that queue.
No schema changes required — Temporal routes by queue name.

## Artifact storage

`LocalArtifactStore.put_bytes` / `put_json` return an `ArtifactRef` with a `file://` URI.
The consumer only sees the `ArtifactRef`, never the store implementation — this is the seam.

For multi-node:

1. Add an `S3ArtifactStore` (or `MinIOArtifactStore`) that writes to object storage and
   returns `s3://` / `https://` URIs in the `ArtifactRef`.
2. Wire it into the worker via config (`QUARRY_ARTIFACT_BACKEND=s3`,
   `QUARRY_ARTIFACT_BUCKET=...`).
3. `http_utils.py` in `quarry_artifacts` already has helpers for fetching artifact bytes by
   URI — update it to handle `s3://` schemes.

No activity or workflow code changes required; the protocol is unchanged.

## Postgres path

SQLite works for one writer. For concurrent workers on separate nodes:

1. `quarry_persistence` uses SQLAlchemy — swapping the engine URL from
   `sqlite+aiosqlite:///...` to `postgresql+asyncpg://...` is the only config change, as
   long as no SQLite-specific SQL is used. Audit `quarry_persistence/` for `PRAGMA` or
   `RETURNING` dialect quirks before migrating.
2. Run Alembic migrations on startup (`alembic upgrade head`) or as an init container.
3. Connection pooling: use `pool_size=5, max_overflow=10` via SQLAlchemy's `create_async_engine`
   for each worker pod.

This is explicitly deferred from Milestone 1. The SQLAlchemy seam is already in place.

## Autoscaling — KEDA (future)

Temporal exposes task-queue backlog depth via its SDK metrics. KEDA's `TemporalWorkflowTaskQueueScaler`
(or a custom external scaler) can scale worker `Deployment` replicas on:

- `temporal_workflow_task_queue_pending_count` — pending workflow tasks on `quarry-control`
- `temporal_activity_task_queue_pending_count` — pending activity tasks per queue

Target: keep queue depth < 5 pending tasks per replica. This is deferred until baseline
load numbers are known.

## Multi-hunter requirements

Running concurrent scans today works at the workflow level (Temporal fan-out), but several
per-scan isolation properties must hold at scale:

| Property | Current state | Scale requirement |
|---|---|---|
| Finding primary keys | Scoped per `scan_id` (fixed in PR #5) | Already safe |
| Artifact namespace | `LocalArtifactStore` keys include `scan_id` | Preserve this in S3 key prefix |
| Integration idempotency | `build_idempotency_key(scan_id, sink_name, fingerprint)` | Already safe — key is scan-scoped |
| DB writes | `persist-scan-state` activity serializes per scan | Add a per-scan row-level lock or optimistic retry for Postgres |
| Repo snapshot isolation | Snapshot written to `.quarry/snapshots/<scan_id>/` | Ensure workers mount a shared FS or use artifact storage for snapshots |

## Deployment sketch (no manifests)

```
┌──────────────────────────────────────────────────────┐
│ Kubernetes cluster                                   │
│                                                      │
│  quarry-server  (Deployment, 2–4 replicas)           │
│    FastAPI, no embedded worker                       │
│    → enqueues workflows via Temporal client          │
│                                                      │
│  quarry-worker-scan  (Deployment, scaled by KEDA)    │
│    task_queue="quarry-control"                       │
│    ThreadPoolExecutor, CPU-bound activities          │
│                                                      │
│  quarry-worker-model  (Deployment, scaled by KEDA)   │
│    task_queue="quarry-model"                         │
│    model invocations, validation, proof              │
│                                                      │
│  Temporal server  (StatefulSet or Temporal Cloud)    │
│  Postgres  (RDS / CloudSQL)                          │
│  MinIO / S3  (artifact storage)                      │
└──────────────────────────────────────────────────────┘
```

## What is not changing now

- No Kubernetes manifests in this repo.
- No Helm charts.
- No SSO or RBAC.
- No Postgres migration.
- SQLite remains the default for local development.
- `LocalArtifactStore` remains the default for local development.
