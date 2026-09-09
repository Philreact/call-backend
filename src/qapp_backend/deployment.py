from pathlib import Path
import tomllib

from qapp_backend.config import Config


def _require_separate_local_storage(config: Config, *, backup_only: bool) -> None:
    # Read the installation's reservation independently of the selected config
    # and environment overrides. Omitting --config must not revive its old DB.
    fields = ("data_dir", "database_path", "identity_path", "rns_config_dir")
    # Backups never open the identity, Reticulum config, or data directory.
    selected_fields = ("database_path",) if backup_only else fields
    selected = [getattr(config, field).resolve() for field in selected_fields]
    roots = {Path.cwd(), *Path.cwd().parents}
    for path in selected:
        roots.update(path.parents)
    defaults = Config()
    for root in sorted(roots):
        reservation = root / "config.toml"
        if not reservation.is_file():
            continue
        with reservation.open("rb") as stream:
            document = tomllib.load(stream)
        section = document.get("backend", document)
        if not isinstance(section, dict) or section.get("production_deployment") != "docker":
            continue
        protected = [(root / section.get(field, getattr(defaults, field))).resolve()
                     for field in fields]
        if any(a == b or a in b.parents or b in a.parents
               for a in selected for b in protected):
            raise ValueError(
                f"Local storage overlaps the Docker installation reserved by {reservation}. "
                "Use separate development data and identity paths. "
                "Start production from the backend directory with: "
                "docker compose up -d --build --wait --wait-timeout 300"
            )


def require_deployment(
    config: Config, *, local_launcher: bool = False, backup_only: bool = False,
) -> None:
    if config.production_deployment != "docker":
        _require_separate_local_storage(config, backup_only=backup_only)
        return
    if local_launcher or not Path("/.dockerenv").is_file():
        raise ValueError(
            "This configuration uses Docker production storage. "
            "Start it from the backend directory with: docker compose up -d --build --wait"
        )
    if (
        config.database_path != Path("/data/backend/backend.sqlite3")
        or config.identity_path != Path("/data/backend/identity")
    ):
        raise ValueError("Docker production requires the configured Compose storage mounts")
