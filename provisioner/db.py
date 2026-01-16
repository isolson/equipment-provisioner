"""SQLite database for provisioning history and logging."""

import asyncio
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List

import aiosqlite
from pydantic import BaseModel


class ProvisioningStatus(str, Enum):
    """Status of a provisioning job."""
    STARTED = "started"
    DETECTING = "detecting"
    CONFIGURING = "configuring"
    FIRMWARE_UPLOADING = "firmware_uploading"
    REBOOTING = "rebooting"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


class ProvisioningRecord(BaseModel):
    """Record of a provisioning job."""
    id: Optional[int] = None
    port_number: Optional[int] = None  # Port number (1-6) where device was detected
    device_type: str
    device_model: Optional[str] = None
    mac_address: str
    ip_address: str
    serial_number: Optional[str] = None
    old_firmware: Optional[str] = None
    new_firmware: Optional[str] = None
    config_applied: Optional[str] = None
    status: ProvisioningStatus
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None


class Database:
    """Async SQLite database manager."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Connect to the database and create tables if needed."""
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row

        await self._create_tables()

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None

    async def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        async with self._lock:
            await self._connection.execute("""
                CREATE TABLE IF NOT EXISTS provisioning_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port_number INTEGER,
                    device_type TEXT NOT NULL,
                    device_model TEXT,
                    mac_address TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    serial_number TEXT,
                    old_firmware TEXT,
                    new_firmware TEXT,
                    config_applied TEXT,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Migration: add port_number column if it doesn't exist
            try:
                await self._connection.execute(
                    "ALTER TABLE provisioning_jobs ADD COLUMN port_number INTEGER"
                )
            except Exception:
                pass  # Column already exists

            await self._connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_mac_address
                ON provisioning_jobs(mac_address)
            """)

            await self._connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_status
                ON provisioning_jobs(status)
            """)

            await self._connection.execute("""
                CREATE TABLE IF NOT EXISTS device_inventory (
                    mac_address TEXT PRIMARY KEY,
                    device_type TEXT NOT NULL,
                    device_model TEXT,
                    serial_number TEXT,
                    last_firmware TEXT,
                    last_config TEXT,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    provision_count INTEGER DEFAULT 1
                )
            """)

            await self._connection.commit()

    async def create_job(self, record: ProvisioningRecord) -> int:
        """Create a new provisioning job record."""
        async with self._lock:
            cursor = await self._connection.execute("""
                INSERT INTO provisioning_jobs
                (port_number, device_type, device_model, mac_address, ip_address, serial_number,
                 old_firmware, new_firmware, config_applied, status, error_message,
                 started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.port_number,
                record.device_type,
                record.device_model,
                record.mac_address,
                record.ip_address,
                record.serial_number,
                record.old_firmware,
                record.new_firmware,
                record.config_applied,
                record.status.value,
                record.error_message,
                record.started_at.isoformat(),
                record.completed_at.isoformat() if record.completed_at else None,
            ))
            await self._connection.commit()
            return cursor.lastrowid

    async def update_job(self, job_id: int, **kwargs) -> None:
        """Update a provisioning job record."""
        if not kwargs:
            return

        # Handle status enum
        if "status" in kwargs and isinstance(kwargs["status"], ProvisioningStatus):
            kwargs["status"] = kwargs["status"].value

        # Handle datetime
        if "completed_at" in kwargs and isinstance(kwargs["completed_at"], datetime):
            kwargs["completed_at"] = kwargs["completed_at"].isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [job_id]

        async with self._lock:
            await self._connection.execute(
                f"UPDATE provisioning_jobs SET {set_clause} WHERE id = ?",
                values
            )
            await self._connection.commit()

    async def get_job(self, job_id: int) -> Optional[ProvisioningRecord]:
        """Get a provisioning job by ID."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM provisioning_jobs WHERE id = ?",
                (job_id,)
            )
            row = await cursor.fetchone()

            if row:
                return self._row_to_record(row)
            return None

    async def get_recent_jobs(self, limit: int = 50) -> List[ProvisioningRecord]:
        """Get recent provisioning jobs."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM provisioning_jobs ORDER BY started_at DESC LIMIT ?",
                (limit,)
            )
            rows = await cursor.fetchall()
            return [self._row_to_record(row) for row in rows]

    async def get_jobs_by_mac(self, mac_address: str) -> List[ProvisioningRecord]:
        """Get all provisioning jobs for a MAC address."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM provisioning_jobs WHERE mac_address = ? ORDER BY started_at DESC",
                (mac_address,)
            )
            rows = await cursor.fetchall()
            return [self._row_to_record(row) for row in rows]

    async def update_inventory(
        self,
        mac_address: str,
        device_type: str,
        device_model: Optional[str] = None,
        serial_number: Optional[str] = None,
        firmware: Optional[str] = None,
        config: Optional[str] = None,
    ) -> None:
        """Update or insert device inventory record."""
        now = datetime.now().isoformat()

        async with self._lock:
            # Check if device exists
            cursor = await self._connection.execute(
                "SELECT mac_address FROM device_inventory WHERE mac_address = ?",
                (mac_address,)
            )
            exists = await cursor.fetchone()

            if exists:
                await self._connection.execute("""
                    UPDATE device_inventory SET
                        device_type = ?,
                        device_model = COALESCE(?, device_model),
                        serial_number = COALESCE(?, serial_number),
                        last_firmware = COALESCE(?, last_firmware),
                        last_config = COALESCE(?, last_config),
                        last_seen = ?,
                        provision_count = provision_count + 1
                    WHERE mac_address = ?
                """, (device_type, device_model, serial_number, firmware, config, now, mac_address))
            else:
                await self._connection.execute("""
                    INSERT INTO device_inventory
                    (mac_address, device_type, device_model, serial_number,
                     last_firmware, last_config, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (mac_address, device_type, device_model, serial_number,
                      firmware, config, now, now))

            await self._connection.commit()

    def _row_to_record(self, row: aiosqlite.Row) -> ProvisioningRecord:
        """Convert a database row to a ProvisioningRecord."""
        # Handle port_number which may not exist in old records
        port_number = None
        try:
            port_number = row["port_number"]
        except (KeyError, IndexError):
            pass

        return ProvisioningRecord(
            id=row["id"],
            port_number=port_number,
            device_type=row["device_type"],
            device_model=row["device_model"],
            mac_address=row["mac_address"],
            ip_address=row["ip_address"],
            serial_number=row["serial_number"],
            old_firmware=row["old_firmware"],
            new_firmware=row["new_firmware"],
            config_applied=row["config_applied"],
            status=ProvisioningStatus(row["status"]),
            error_message=row["error_message"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        )


# Global database instance
_db: Optional[Database] = None


async def get_db() -> Database:
    """Get the global database instance."""
    if _db is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _db


async def init_db(db_path: str) -> Database:
    """Initialize the global database instance."""
    global _db
    _db = Database(db_path)
    await _db.connect()
    return _db


async def close_db() -> None:
    """Close the global database connection."""
    global _db
    if _db:
        await _db.close()
        _db = None
