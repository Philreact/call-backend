from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from qapp_backend.storage.database import SCHEMA_VERSION


_TABLES_BY_SCHEMA_VERSION = {1: {"sessions"}}


@dataclass(frozen=True, slots=True)
class BackupReport:
    path: Path
    size_bytes: int
    sha256: str
    schema_version: int


def _read_only_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_connection(connection: sqlite3.Connection) -> int:
    rows = connection.execute("PRAGMA integrity_check").fetchall()
    if rows != [("ok",)]:
        details = "; ".join(str(row[0]) for row in rows[:10])
        raise RuntimeError(f"SQLite integrity check failed: {details}")
    foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_errors:
        details = "; ".join(str(row) for row in foreign_key_errors[:10])
        raise RuntimeError(f"SQLite foreign-key check failed: {details}")
    schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if not 1 <= schema_version <= SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported backend database schema {schema_version}; "
            f"supported range is 1..{SCHEMA_VERSION}"
        )
    expected_tables: set[str] = set()
    for introduced_in, tables in _TABLES_BY_SCHEMA_VERSION.items():
        if schema_version >= introduced_in:
            expected_tables.update(tables)
    actual_tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    missing_tables = expected_tables - actual_tables
    if missing_tables:
        raise RuntimeError(
            "backup is not a complete backend database; missing tables: "
            + ", ".join(sorted(missing_tables))
        )
    return schema_version


def verify_sqlite_backup(path: str | Path) -> BackupReport:
    backup_path = Path(path)
    if not backup_path.is_file():
        raise FileNotFoundError(f"backup file does not exist: {backup_path}")
    try:
        connection = sqlite3.connect(_read_only_uri(backup_path), uri=True)
    except sqlite3.Error as exc:
        raise RuntimeError(f"unable to open SQLite backup: {exc}") from exc
    try:
        connection.execute("PRAGMA query_only=ON")
        schema_version = _verify_connection(connection)
    except sqlite3.Error as exc:
        raise RuntimeError(f"unable to verify SQLite backup: {exc}") from exc
    finally:
        connection.close()
    return BackupReport(
        path=backup_path.resolve(),
        size_bytes=backup_path.stat().st_size,
        sha256=_sha256(backup_path),
        schema_version=schema_version,
    )


def _default_backup_name(now: datetime | None = None) -> str:
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S%fZ")
    return f"backend-{timestamp}-{secrets.token_hex(4)}.sqlite3"


def create_sqlite_backup(
    source_path: str | Path,
    output_directory: str | Path,
    *,
    filename: str | None = None,
) -> BackupReport:
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"backend database does not exist: {source}")

    output = Path(output_directory)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not output.is_dir():
        raise NotADirectoryError(f"backup output is not a directory: {output}")

    name = filename or _default_backup_name()
    if Path(name).name != name or name in {"", ".", ".."}:
        raise ValueError("backup filename must be a single file name")
    final_path = output / name
    if final_path.exists():
        raise FileExistsError(f"backup already exists: {final_path}")
    if final_path.resolve() == source.resolve():
        raise ValueError("backup destination must differ from the live database")

    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=output,
        prefix=".qapp-backup-",
        suffix=".sqlite3.tmp",
    )
    os.close(file_descriptor)
    temporary_path = Path(temporary_name)
    try:
        try:
            source_connection = sqlite3.connect(_read_only_uri(source), uri=True)
        except sqlite3.Error as exc:
            raise RuntimeError(f"unable to open backend database: {exc}") from exc
        try:
            source_connection.execute("PRAGMA busy_timeout=5000")
            destination_connection = sqlite3.connect(temporary_path)
            try:
                source_connection.backup(
                    destination_connection,
                    pages=256,
                    sleep=0.05,
                )
                destination_connection.execute("PRAGMA journal_mode=DELETE")
                destination_connection.commit()
            finally:
                destination_connection.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"unable to create SQLite backup: {exc}") from exc
        finally:
            source_connection.close()

        # Verify the completed snapshot before making it visible under its final
        # name. A hard link provides atomic, no-replace publication on the same
        # filesystem; unlike os.replace(), it cannot overwrite an existing file.
        report = verify_sqlite_backup(temporary_path)
        with temporary_path.open("rb") as stream:
            os.fsync(stream.fileno())
        os.link(temporary_path, final_path)
        temporary_path.unlink()
        directory_descriptor = os.open(output, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return BackupReport(
            path=final_path.resolve(),
            size_bytes=report.size_bytes,
            sha256=report.sha256,
            schema_version=report.schema_version,
        )
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
