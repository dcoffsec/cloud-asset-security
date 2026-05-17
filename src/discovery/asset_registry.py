"""
Asset registry — tracks discovered assets and scan state.

Uses SQLite for local/single-node deployments.
At scale, swap for DynamoDB or PostgreSQL (see design notes).

Design notes
------------
- SQLite is fine for < ~50k rows; swap backend via the AssetStore
  abstract interface without touching callers.
- For multi-node deployments: DynamoDB with a GSI on (scan_status, discovered_at)
  lets workers claim work atomically using conditional writes.
"""
import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import get_config
from ..models import Asset, AssetType, ScanStatus

logger = logging.getLogger(__name__)


class AssetRegistry:
    """
    Persistent store for discovered assets and their scan state.

    Schema
    ------
    assets(
        asset_id TEXT PRIMARY KEY,
        asset_type TEXT,
        hostname TEXT,
        ip_addresses TEXT,   -- JSON array
        region TEXT,
        account_id TEXT,
        resource_arn TEXT,
        tags TEXT,           -- JSON object
        discovered_at TEXT,
        discovered_via TEXT,
        scan_status TEXT,
        raw_event TEXT       -- JSON
    )
    """

    def __init__(self, db_path: Optional[str] = None):
        self.config = get_config()
        self.db_path = db_path or self.config.db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id     TEXT PRIMARY KEY,
                    asset_type   TEXT NOT NULL,
                    hostname     TEXT NOT NULL,
                    ip_addresses TEXT DEFAULT '[]',
                    region       TEXT DEFAULT 'us-east-1',
                    account_id   TEXT DEFAULT '',
                    resource_arn TEXT DEFAULT '',
                    tags         TEXT DEFAULT '{}',
                    discovered_at TEXT NOT NULL,
                    discovered_via TEXT DEFAULT 'cloudtrail',
                    scan_status  TEXT DEFAULT 'pending',
                    raw_event    TEXT DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_status
                ON assets(scan_status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hostname
                ON assets(hostname)
            """)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def register(self, asset: Asset) -> bool:
        """
        Register a new asset. Returns True if inserted, False if already exists.
        Idempotent — safe to call multiple times for the same hostname.
        """
        # Deduplicate by hostname to avoid re-scanning the same endpoint
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT asset_id FROM assets WHERE hostname = ?",
                (asset.hostname,)
            ).fetchone()

            if existing:
                logger.debug("Asset already registered: %s", asset.hostname)
                return False

            conn.execute("""
                INSERT INTO assets
                  (asset_id, asset_type, hostname, ip_addresses, region,
                   account_id, resource_arn, tags, discovered_at,
                   discovered_via, scan_status, raw_event)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                asset.asset_id,
                asset.asset_type.value,
                asset.hostname,
                json.dumps(asset.ip_addresses),
                asset.region,
                asset.account_id,
                asset.resource_arn,
                json.dumps(asset.tags),
                asset.discovered_at.isoformat(),
                asset.discovered_via,
                ScanStatus.PENDING.value,
                json.dumps(asset.raw_event),
            ))
            logger.info("Registered new asset: %s (%s)", asset.hostname, asset.asset_type.value)
            return True

    def update_status(self, asset_id: str, status: ScanStatus):
        with self._conn() as conn:
            conn.execute(
                "UPDATE assets SET scan_status = ? WHERE asset_id = ?",
                (status.value, asset_id)
            )

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_pending(self, limit: int = 10) -> list[Asset]:
        """Return up to `limit` assets awaiting scanning."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM assets WHERE scan_status = ? ORDER BY discovered_at LIMIT ?",
                (ScanStatus.PENDING.value, limit)
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_by_id(self, asset_id: str) -> Optional[Asset]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
        return self._row_to_asset(row) if row else None

    def list_all(self, limit: int = 100) -> list[Asset]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM assets ORDER BY discovered_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            by_status = dict(conn.execute(
                "SELECT scan_status, COUNT(*) FROM assets GROUP BY scan_status"
            ).fetchall())
            by_type = dict(conn.execute(
                "SELECT asset_type, COUNT(*) FROM assets GROUP BY asset_type"
            ).fetchall())
        return {"total": total, "by_status": by_status, "by_type": by_type}

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_asset(row: sqlite3.Row) -> Asset:
        return Asset(
            asset_id=row["asset_id"],
            asset_type=AssetType(row["asset_type"]),
            hostname=row["hostname"],
            ip_addresses=json.loads(row["ip_addresses"] or "[]"),
            region=row["region"],
            account_id=row["account_id"],
            resource_arn=row["resource_arn"],
            tags=json.loads(row["tags"] or "{}"),
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            discovered_via=row["discovered_via"],
            raw_event=json.loads(row["raw_event"] or "{}"),
        )
