"""Initial schema

Revision ID: f37be3ca7f56
Revises:
Create Date: 2026-01-26 22:00:16.681589

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f37be3ca7f56"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("""CREATE TABLE IF NOT EXISTS scans (
        id BIGSERIAL PRIMARY KEY,
        domain TEXT NOT NULL,
        mode TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL,
        finished_at TIMESTAMPTZ NOT NULL,
        duration_ms INTEGER NOT NULL,
        from_cache BOOLEAN NOT NULL DEFAULT FALSE,
        adaptive_timeout BOOLEAN NOT NULL DEFAULT FALSE,
        retries INTEGER NOT NULL DEFAULT 0,
        timeout_used INTEGER NOT NULL DEFAULT 0,
        tech_count INTEGER,
        versions_count INTEGER,
        technologies_json JSONB NOT NULL,
        categories_json JSONB NOT NULL,
        raw_json JSONB,
        payload_bytes BIGINT,
        error TEXT
    );""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain_time ON scans(domain, finished_at DESC);")
    op.execute("""CREATE TABLE IF NOT EXISTS domain_techs (
        id BIGSERIAL PRIMARY KEY,
        domain TEXT NOT NULL,
        tech_name TEXT NOT NULL,
        version TEXT,
        categories TEXT,
        first_seen TIMESTAMPTZ NOT NULL,
        last_seen TIMESTAMPTZ NOT NULL
    );""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_domain_techs_tech ON domain_techs(tech_name);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_domain_techs_last_seen ON domain_techs(last_seen DESC);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_domain_techs_first_seen ON domain_techs(first_seen);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_domain_techs_lower_name ON domain_techs(LOWER(tech_name));")
    op.execute("CREATE INDEX IF NOT EXISTS idx_domain_techs_dtv ON domain_techs(domain, tech_name, version);")
    op.execute("""CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        domains JSONB NOT NULL,
        options JSONB,
        progress INTEGER DEFAULT 0,
        total INTEGER DEFAULT 1,
        completed INTEGER DEFAULT 0,
        result JSONB,
        results JSONB,
        error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        finished_at TIMESTAMPTZ
    );""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at DESC);")
    op.execute("""CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        key_hash TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        rate_limit TEXT DEFAULT '1000 per hour',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used_at TIMESTAMPTZ,
        request_count BIGINT DEFAULT 0
    );""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE IF EXISTS api_keys CASCADE;")
    op.execute("DROP TABLE IF EXISTS scan_jobs CASCADE;")
    op.execute("DROP TABLE IF EXISTS domain_techs CASCADE;")
    op.execute("DROP TABLE IF EXISTS scans CASCADE;")
