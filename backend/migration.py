from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable


def _database_url() -> str | None:
    """Return DATABASE_URL, or None when not configured."""
    return os.getenv("DATABASE_URL")


def _get_connection():
    """Return a psycopg connection (late-imported so tests without psycopg work)."""
    from db import get_connection as _conn
    return _conn()

# ---------------------------------------------------------------------------
# Migration framework: ordered, idempotent, restart-safe database migrations.
# ---------------------------------------------------------------------------
#
# Every migration is a numbered, idempotent step.  The framework tracks which
# steps have been applied in the ``schema_migrations`` table and applies any
# pending steps in order on every ``run_migrations()`` call, so the app stays
# current regardless of how many upgrades are skipped between deployments.
#
# Migration IDs are sequential integers starting at 1.  Once a migration is
# applied it is never re-executed, and its SQL must be safe to skip (i.e. no
# destructive DDL that references objects that may now be depended on).

MIGRATIONS_TABLE = "schema_migrations"


def _ensure_migrations_table() -> None:
    """Create the ``schema_migrations`` ledger table if it does not exist."""
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {MIGRATIONS_TABLE} (
                    id SERIAL PRIMARY KEY,
                    migration_id INTEGER NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    checksum TEXT NOT NULL
                );
                """
            )
        conn.commit()


def _applied_migration_records() -> dict[int, dict[str, Any]]:
    """Return recorded ledger rows keyed by migration id.

    Each row carries the ``name`` and ``checksum`` captured when the migration
    was applied, which is what startup verification replays against the
    in-code definitions.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT migration_id, name, checksum FROM {MIGRATIONS_TABLE} "
                "ORDER BY migration_id"
            )
            return {row["migration_id"]: dict(row) for row in cur.fetchall()}


def _applied_migrations() -> set[int]:
    """Return the set of migration IDs already recorded in the ledger."""
    return set(_applied_migration_records())


def _record_migration(migration_id: int, name: str, checksum: str) -> None:
    """Insert a ledger entry for a successfully applied migration."""
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO {MIGRATIONS_TABLE} (migration_id, name, checksum)
                VALUES (%s, %s, %s)
                ON CONFLICT (migration_id) DO NOTHING;
                """,
                (migration_id, name, checksum),
            )
        conn.commit()


def _compute_checksum(sql: str) -> str:
    """Return a SHA-256 hex digest of the canonical migration SQL."""
    import hashlib
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Migration checksum verification
# ---------------------------------------------------------------------------
#
# The ledger records the SHA-256 digest of every migration's SQL at the moment
# it is applied (see ``_record_migration``).  On each startup the recorded
# digests are replayed against the in-code definitions: an applied migration
# whose SQL changed afterwards is a trust-boundary violation, because the
# running schema no longer provably corresponds to the evidence the ledger
# attests to.  Verification is therefore fail-closed by default.
#
# Only migration ids, names, and digests are ever surfaced; SQL text is never
# included in errors or logs, so no operational secrets, media, witness values,
# or private keys can leak through this path.

CHECKSUM_ENFORCEMENT_ENV = "MIGRATION_CHECKSUM_ENFORCEMENT"
CHECKSUM_ENFORCEMENT_MODES = ("enforce", "warn")


@dataclass
class MigrationChecksumIssue:
    """A single recorded-vs-canonical checksum discrepancy.

    ``expected`` is the SHA-256 digest of the current in-code migration and
    ``recorded`` is the digest stored in the ledger when it was applied.  Both
    are digests only; no migration SQL is carried on the issue, so instances
    are safe to log or expose from operational tooling.
    """

    migration_id: int
    name: str
    issue: str  # "checksum_mismatch" | "missing_checksum" | "unknown_migration"
    expected: str | None
    recorded: str | None


class MigrationChecksumError(RuntimeError):
    """Raised at startup when applied migrations no longer match the ledger.

    The message deliberately carries only migration ids and issue kinds so that
    no SQL, media, secrets, witness values, or private keys are exposed.
    """

    def __init__(self, issues: list[MigrationChecksumIssue]) -> None:
        self.issues = list(issues)
        summary = ", ".join(
            f"{issue.issue}(migration_id={issue.migration_id})"
            for issue in self.issues
        )
        super().__init__(f"migration checksum verification failed: {summary}")


def _checksum_enforcement() -> str:
    """Return the configured startup enforcement mode.

    ``enforce`` (the default) aborts startup on any discrepancy so a drifted
    ledger can never silently serve traffic.  ``warn`` is the break-glass
    rollback switch for operators who need to boot while they reconcile a
    ledger; discrepancies are still reported.  Unknown values fall back to
    ``enforce``.
    """
    mode = (os.getenv(CHECKSUM_ENFORCEMENT_ENV) or "enforce").strip().lower()
    return mode if mode in CHECKSUM_ENFORCEMENT_MODES else "enforce"


def _verify_records(
    records: dict[int, dict[str, Any]],
) -> list[MigrationChecksumIssue]:
    """Compare applied ledger rows against the current migration definitions."""
    catalog = {migration.id: migration for migration in MIGRATIONS}
    issues: list[MigrationChecksumIssue] = []

    for migration_id in sorted(records):
        row = records[migration_id]
        migration = catalog.get(migration_id)
        recorded = str(row.get("checksum") or "").strip()

        if migration is None:
            # The ledger references a migration the code no longer defines.
            issues.append(
                MigrationChecksumIssue(
                    migration_id=migration_id,
                    name=str(row.get("name") or ""),
                    issue="unknown_migration",
                    expected=None,
                    recorded=recorded or None,
                )
            )
            continue

        expected = _compute_checksum(migration.sql)
        if not recorded:
            issues.append(
                MigrationChecksumIssue(
                    migration_id=migration_id,
                    name=migration.name,
                    issue="missing_checksum",
                    expected=expected,
                    recorded=None,
                )
            )
        elif recorded != expected:
            issues.append(
                MigrationChecksumIssue(
                    migration_id=migration_id,
                    name=migration.name,
                    issue="checksum_mismatch",
                    expected=expected,
                    recorded=recorded,
                )
            )

    return issues


def verify_migration_checksums() -> list[MigrationChecksumIssue]:
    """Verify that every applied migration still matches its recorded checksum.

    Returns an empty list when the database is unconfigured or every applied
    migration is intact.  A non-empty list means the ledger is out of sync with
    the code: a migration definition changed after it was applied
    (``checksum_mismatch``), a ledger row carries no digest
    (``missing_checksum``), or the code no longer defines an applied migration
    (``unknown_migration``).

    This never raises; startup enforcement is layered on top by
    :func:`run_migrations`.
    """
    if not _database_url():
        return []

    _ensure_migrations_table()
    return _verify_records(_applied_migration_records())


# ---------------------------------------------------------------------------
# Migration definition
# ---------------------------------------------------------------------------


@dataclass
class Migration:
    """A single ordered, idempotent database schema migration.

    Attributes:
        id:        Unique sequential identifier (must never be reused).
        name:      Human-readable short label for observability.
        sql:       DDL/DML to apply.  Must be safe to run inside a transaction.
        check:     Optional callable that returns True when the schema object
                   already exists (used for forward-drift detection).
    """

    id: int
    name: str
    sql: str
    check: Callable[[], bool] | None = None


# ---------------------------------------------------------------------------
# Migration definitions
# ---------------------------------------------------------------------------

MIGRATIONS: list[Migration] = [
    Migration(
        id=1,
        name="create proof_events table",
        sql="""
        CREATE TABLE IF NOT EXISTS proof_events (
            id BIGSERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            file_name TEXT,
            video_hash TEXT,
            metadata_hash TEXT,
            proof_id TEXT,
            tier TEXT,
            embedded_hash TEXT,
            metadata JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS proof_events_video_hash_idx
            ON proof_events (video_hash);
        CREATE INDEX IF NOT EXISTS proof_events_proof_id_idx
            ON proof_events (proof_id);
        """,
    ),
    Migration(
        id=2,
        name="create lineage_events table",
        sql="""
        CREATE TABLE IF NOT EXISTS lineage_events (
            id BIGSERIAL PRIMARY KEY,
            manifest_digest TEXT NOT NULL UNIQUE,
            manifest JSONB NOT NULL,
            actor_address TEXT NOT NULL,
            parent_proof_ids TEXT[] NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS lineage_events_actor_idx
            ON lineage_events (actor_address);
        """,
    ),
    Migration(
        id=3,
        name="add tx tracking columns to proof_events",
        sql="""
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS tx_hash TEXT;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS tx_status TEXT;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS source_address TEXT;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS contract_id TEXT;
        CREATE INDEX IF NOT EXISTS proof_events_tx_hash_idx
            ON proof_events (tx_hash);
        """,
    ),
    Migration(
        id=4,
        name="add idempotency key to proof_events",
        sql="""
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
        CREATE UNIQUE INDEX IF NOT EXISTS proof_events_idempotency_key_idx
            ON proof_events (idempotency_key)
            WHERE idempotency_key IS NOT NULL;
        """,
    ),
    Migration(
        id=5,
        name="create blobs and tenant_blob_refs tables",
        sql="""
        CREATE TABLE IF NOT EXISTS blobs (
            content_hash TEXT PRIMARY KEY,
            encrypted_dek TEXT NOT NULL,
            size_bytes BIGINT NOT NULL,
            storage_path TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS tenant_blob_refs (
            tenant_id TEXT NOT NULL,
            content_hash TEXT NOT NULL REFERENCES blobs(content_hash) ON DELETE CASCADE,
            ref_count INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, content_hash)
        );
        """,
    ),
    Migration(
        id=6,
        name="create webhook tables",
        sql="""
        CREATE TABLE IF NOT EXISTS webhook_subscriptions (
            id BIGSERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            secret_key TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id BIGSERIAL PRIMARY KEY,
            subscription_id BIGINT NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
            event_id BIGINT NOT NULL REFERENCES proof_events(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            retry_count INTEGER NOT NULL DEFAULT 0,
            next_retry_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            lease_expires_at TIMESTAMPTZ,
            last_response_code INTEGER,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS webhook_deliveries_status_idx
            ON webhook_deliveries (status, next_retry_at);
        """,
    ),
    Migration(
        id=7,
        name="create proof_history_events table",
        sql="""
        CREATE TABLE IF NOT EXISTS proof_history_events (
            id BIGSERIAL PRIMARY KEY,
            proof_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT,
            reason_code INTEGER NOT NULL,
            contract_id TEXT,
            tx_hash TEXT,
            tx_status TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS proof_history_events_proof_id_idx
            ON proof_history_events (proof_id);
        """,
    ),
    Migration(
        id=8,
        name="add time attestation columns to proof_events",
        sql="""
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS time_attestation JSONB;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS claimed_capture_time TIMESTAMPTZ;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS retention_class TEXT;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT false;
        CREATE INDEX IF NOT EXISTS proof_events_claimed_capture_time_idx
            ON proof_events (claimed_capture_time);
        """,
    ),
    Migration(
        id=9,
        name="create idempotency_records table",
        sql="""
        CREATE TABLE IF NOT EXISTS idempotency_records (
            id SERIAL PRIMARY KEY,
            request_digest TEXT NOT NULL,
            request_type TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),
            response_payload JSONB,
            error_payload JSONB,
            UNIQUE (request_digest, request_type)
        );
        """,
    ),
    Migration(
        id=10,
        name="add composite cursor index to proof_events",
        sql="""
        CREATE INDEX IF NOT EXISTS proof_events_cursor_idx
            ON proof_events (id DESC, created_at DESC);
        """,
    ),
    Migration(
        id=11,
        name="create proof event deletion receipts",
        sql="""
        CREATE TABLE IF NOT EXISTS deletion_receipts (
            id BIGSERIAL PRIMARY KEY,
            event_id BIGINT NOT NULL,
            proof_id TEXT,
            video_hash TEXT,
            metadata_hash TEXT,
            deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS deletion_receipts_event_id_idx
            ON deletion_receipts (event_id);
        """,
    ),
    Migration(
        id=12,
        name="add event_index to proof_events and create indexer_state",
        sql="""
        ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS event_index INTEGER;
        CREATE UNIQUE INDEX IF NOT EXISTS proof_events_tx_hash_event_index_idx
            ON proof_events (tx_hash, event_index)
            WHERE tx_hash IS NOT NULL AND event_index IS NOT NULL;
        CREATE TABLE IF NOT EXISTS indexer_state (
            id TEXT PRIMARY KEY,
            cursor TEXT NOT NULL,
            ledger BIGINT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """,
    ),
]


def run_migrations(*, enforce_checksums: bool | None = None) -> list[dict[str, Any]]:
    """Apply all pending migrations and return a report.

    Returns a list of dicts with keys ``migration_id``, ``name``,
    ``action`` (``"applied"`` or ``"skipped"``) and ``checksum_status``
    (``"verified"`` for intact rows, otherwise the discrepancy kind reported
    by :func:`verify_migration_checksums`).

    Before applying anything, the recorded checksums of already-applied
    migrations are replayed against the in-code definitions.  On any
    discrepancy startup is aborted with :class:`MigrationChecksumError` unless
    enforcement is disabled (``MIGRATION_CHECKSUM_ENFORCEMENT=warn`` or
    ``enforce_checksums=False``); the discrepancy is reported either way.

    Safe to call repeatedly (every app startup).  Already-applied migrations
    are skipped automatically via the ledger table.
    """
    if not _database_url():
        return []

    _ensure_migrations_table()
    records = _applied_migration_records()
    issues = _verify_records(records)
    issue_by_id = {issue.migration_id: issue for issue in issues}

    enforce = (
        _checksum_enforcement() == "enforce"
        if enforce_checksums is None
        else enforce_checksums
    )
    if issues and enforce:
        raise MigrationChecksumError(issues)

    applied = set(records)
    results: list[dict[str, Any]] = []

    for m in MIGRATIONS:
        entry = {"migration_id": m.id, "name": m.name}

        if m.id in applied:
            issue = issue_by_id.get(m.id)
            entry["action"] = "skipped"
            entry["checksum_status"] = issue.issue if issue else "verified"
            results.append(entry)
            continue

        checksum = _compute_checksum(m.sql)

        with _get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(m.sql)
            conn.commit()

        _record_migration(m.id, m.name, checksum)
        entry["action"] = "applied"
        entry["checksum_status"] = "verified"
        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

EXPECTED_TABLES: dict[str, list[dict[str, str]]] = {
    "proof_events": [
        {"column": "id", "type": "bigint"},
        {"column": "event_type", "type": "text"},
        {"column": "file_name", "type": "text"},
        {"column": "video_hash", "type": "text"},
        {"column": "metadata_hash", "type": "text"},
        {"column": "proof_id", "type": "text"},
        {"column": "tier", "type": "text"},
        {"column": "embedded_hash", "type": "text"},
        {"column": "metadata", "type": "jsonb"},
        {"column": "created_at", "type": "timestamp with time zone"},
        {"column": "tx_hash", "type": "text"},
        {"column": "tx_status", "type": "text"},
        {"column": "source_address", "type": "text"},
        {"column": "contract_id", "type": "text"},
        {"column": "idempotency_key", "type": "text"},
        {"column": "time_attestation", "type": "jsonb"},
        {"column": "claimed_capture_time", "type": "timestamp with time zone"},
        {"column": "retention_class", "type": "text"},
        {"column": "expires_at", "type": "timestamp with time zone"},
        {"column": "legal_hold", "type": "boolean"},
        {"column": "event_index", "type": "integer"},
    ],
    "lineage_events": [
        {"column": "id", "type": "bigint"},
        {"column": "manifest_digest", "type": "text"},
        {"column": "manifest", "type": "jsonb"},
        {"column": "actor_address", "type": "text"},
        {"column": "parent_proof_ids", "type": "text"},
        {"column": "created_at", "type": "timestamp with time zone"},
    ],
    "blobs": [
        {"column": "content_hash", "type": "text"},
        {"column": "encrypted_dek", "type": "text"},
        {"column": "size_bytes", "type": "bigint"},
        {"column": "storage_path", "type": "text"},
        {"column": "created_at", "type": "timestamp with time zone"},
    ],
    "tenant_blob_refs": [
        {"column": "tenant_id", "type": "text"},
        {"column": "content_hash", "type": "text"},
        {"column": "ref_count", "type": "integer"},
        {"column": "created_at", "type": "timestamp with time zone"},
        {"column": "updated_at", "type": "timestamp with time zone"},
    ],
    "webhook_subscriptions": [
        {"column": "id", "type": "bigint"},
        {"column": "url", "type": "text"},
        {"column": "secret_key", "type": "text"},
        {"column": "is_active", "type": "boolean"},
        {"column": "created_at", "type": "timestamp with time zone"},
    ],
    "webhook_deliveries": [
        {"column": "id", "type": "bigint"},
        {"column": "subscription_id", "type": "bigint"},
        {"column": "event_id", "type": "bigint"},
        {"column": "status", "type": "text"},
        {"column": "retry_count", "type": "integer"},
        {"column": "next_retry_at", "type": "timestamp with time zone"},
        {"column": "lease_expires_at", "type": "timestamp with time zone"},
        {"column": "last_response_code", "type": "integer"},
        {"column": "created_at", "type": "timestamp with time zone"},
        {"column": "updated_at", "type": "timestamp with time zone"},
    ],
    "proof_history_events": [
        {"column": "id", "type": "bigint"},
        {"column": "proof_id", "type": "text"},
        {"column": "action", "type": "text"},
        {"column": "actor", "type": "text"},
        {"column": "reason_code", "type": "integer"},
        {"column": "contract_id", "type": "text"},
        {"column": "tx_hash", "type": "text"},
        {"column": "tx_status", "type": "text"},
        {"column": "created_at", "type": "timestamp with time zone"},
    ],
    "idempotency_records": [
        {"column": "id", "type": "integer"},
        {"column": "request_digest", "type": "text"},
        {"column": "request_type", "type": "text"},
        {"column": "created_at", "type": "timestamp with time zone"},
        {"column": "expires_at", "type": "timestamp with time zone"},
        {"column": "status", "type": "text"},
        {"column": "response_payload", "type": "jsonb"},
        {"column": "error_payload", "type": "jsonb"},
    ],
    "schema_migrations": [
        {"column": "id", "type": "integer"},
        {"column": "migration_id", "type": "integer"},
        {"column": "name", "type": "text"},
        {"column": "applied_at", "type": "timestamp with time zone"},
        {"column": "checksum", "type": "text"},
    ],
    "deletion_receipts": [
        {"column": "id", "type": "bigint"},
        {"column": "event_id", "type": "bigint"},
        {"column": "proof_id", "type": "text"},
        {"column": "video_hash", "type": "text"},
        {"column": "metadata_hash", "type": "text"},
        {"column": "deleted_at", "type": "timestamp with time zone"},
    ],
    "indexer_state": [
        {"column": "id", "type": "text"},
        {"column": "cursor", "type": "text"},
        {"column": "ledger", "type": "bigint"},
        {"column": "updated_at", "type": "timestamp with time zone"},
    ],
}


@dataclass
class DriftEntry:
    table_name: str
    issue: str
    detail: str


def detect_drift() -> list[DriftEntry]:
    """Compare the live database schema against the expected schema.

    Returns a list of ``DriftEntry`` describing any missing tables,
    missing columns, or type mismatches.  An empty list means no drift.
    """
    if not _database_url():
        return []

    drifts: list[DriftEntry] = []

    with _get_connection() as conn:
        with conn.cursor() as cur:
            # Discover which tables actually exist.
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_type = 'BASE TABLE';
                """
            )
            present = {row["table_name"] for row in cur.fetchall()}

            for table_name, expected_cols in EXPECTED_TABLES.items():
                if table_name not in present:
                    drifts.append(
                        DriftEntry(
                            table_name=table_name,
                            issue="missing_table",
                            detail=f"Expected table '{table_name}' does not exist",
                        )
                    )
                    continue

                # Fetch actual columns for this table.
                cur.execute(
                    """
                    SELECT column_name, udt_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = %s;
                    """,
                    (table_name,),
                )
                actual_cols = {
                    row["column_name"]: row["udt_name"] for row in cur.fetchall()
                }

                for expected in expected_cols:
                    col = expected["column"]
                    if col not in actual_cols:
                        drifts.append(
                            DriftEntry(
                                table_name=table_name,
                                issue="missing_column",
                                detail=f"Expected column '{table_name}.{col}' does not exist",
                            )
                        )
                        continue

                    actual_type = actual_cols[col]
                    expected_type = expected["type"]
                    # Allow `int4` to match `integer` and `int8` to match `bigint`.
                    if not _types_match(actual_type, expected_type):
                        drifts.append(
                            DriftEntry(
                                table_name=table_name,
                                issue="type_mismatch",
                                detail=(
                                    f"Column '{table_name}.{col}' has type "
                                    f"'{actual_type}', expected '{expected_type}'"
                                ),
                            )
                        )

    return drifts


def _types_match(actual: str, expected: str) -> bool:
    """Compare PostgreSQL type names allowing common aliases."""
    alias = {
        "int4": "integer",
        "int8": "bigint",
        "bool": "boolean",
        "timestamp": "timestamp without time zone",
        "timestamptz": "timestamp with time zone",
        "varchar": "character varying",
    }
    return alias.get(actual, actual) == alias.get(expected, expected)
