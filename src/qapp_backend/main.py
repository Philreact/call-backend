from __future__ import annotations

import argparse
import sys

from qapp_backend import __version__
from qapp_backend.app import install_reference_service
from qapp_backend.auth import install_authentication_service
from qapp_backend.config import Config, load_config
from qapp_backend.deployment import require_deployment
from qapp_backend.readiness import check_readiness
from qapp_backend.instance_lock import (
    InstanceLockError,
    acquire_instance_lock,
)
from qapp_backend.logging import configure_logging
from qapp_backend.reticulum.server import QAppServer
from qapp_backend.storage.backup import (
    BackupReport,
    create_sqlite_backup,
    verify_sqlite_backup,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authenticated Q-App transport backend")
    parser.add_argument("--config", help="TOML configuration file")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check-config", action="store_true", help="validate configuration and exit")
    action.add_argument("--health", action="store_true", help="check running backend readiness")
    action.add_argument("--print-destination", action="store_true", help="initialize and print the public destination hash")
    action.add_argument(
        "--backup",
        nargs="?",
        const="",
        metavar="DIRECTORY",
        help=(
            "create and verify an online SQLite backup, then exit; "
            "omit DIRECTORY to use backup_path from configuration"
        ),
    )
    action.add_argument(
        "--verify-backup",
        metavar="FILE",
        help="verify an existing backend SQLite backup, then exit",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _print_backup_report(prefix: str, report: BackupReport) -> None:
    print(f"{prefix}: {report.path}")
    print(f"schema version: {report.schema_version}")
    print(f"size bytes: {report.size_bytes}")
    print(f"sha256: {report.sha256}")


def build_server(config: Config) -> QAppServer:
    server = QAppServer(config)
    install_authentication_service(server)
    install_reference_service(server)
    return server


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verify_backup:
        try:
            report = verify_sqlite_backup(args.verify_backup)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"backup verification failed: {exc}", file=sys.stderr)
            return 1
        _print_backup_report("backup valid", report)
        return 0
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check_config:
        print("configuration valid")
        return 0
    try:
        require_deployment(config, backup_only=args.backup is not None)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.health:
        try:
            check_readiness(config)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"backend not ready: {exc}", file=sys.stderr)
            return 1
        print("backend ready: startup checks passed")
        return 0
    if args.backup is not None:
        backup_path = args.backup or config.backup_path
        try:
            report = create_sqlite_backup(config.database_path, backup_path)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"backup failed: {exc}", file=sys.stderr)
            return 1
        _print_backup_report("backup created", report)
        return 0
    configure_logging(config.log_level)
    try:
        with acquire_instance_lock(config.instance_lock_path):
            server = build_server(config)
            if args.print_destination:
                try:
                    server.initialize()
                    print(server.destination_hash)
                finally:
                    server.shutdown()
                return 0
            server.run()
    except InstanceLockError as exc:
        print(f"backend startup failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
