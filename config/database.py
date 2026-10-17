"""Small environment-driven Django database configuration helpers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


def database_config(environ: Mapping[str, str], sqlite_name: Path | str) -> dict:
    """Return PostgreSQL settings from a URL/env vars, or SQLite by default."""
    database_url = environ.get("DATABASE_URL", "").strip()
    if database_url:
        parsed = urlsplit(database_url)
        if parsed.scheme.lower() not in {"postgres", "postgresql", "postgresql+psycopg"}:
            raise ValueError("DATABASE_URL must use postgres or postgresql")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("DATABASE_URL contains an invalid port") from exc
        name = unquote(parsed.path.lstrip("/"))
        if not parsed.hostname or not name:
            raise ValueError("DATABASE_URL must include a host and database name")
        options = {key: values[-1] for key, values in parse_qs(parsed.query).items()
                   if key in {"sslmode", "connect_timeout", "application_name", "target_session_attrs"}}
        config = {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": name,
            "USER": unquote(parsed.username or ""),
            "PASSWORD": unquote(parsed.password or ""),
            "HOST": parsed.hostname,
            "PORT": str(port or 5432),
        }
        if options:
            config["OPTIONS"] = options
        return config

    postgres_keys = ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_SSLMODE")
    if any(environ.get(key) for key in postgres_keys):
        name = environ.get("POSTGRES_DB", "").strip()
        if not name:
            raise ValueError("POSTGRES_DB is required when PostgreSQL variables are configured")
        config = {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": name,
            "USER": environ.get("POSTGRES_USER", ""),
            "PASSWORD": environ.get("POSTGRES_PASSWORD", ""),
            "HOST": environ.get("POSTGRES_HOST", "localhost"),
            "PORT": environ.get("POSTGRES_PORT", "5432"),
        }
        sslmode = environ.get("POSTGRES_SSLMODE", "")
        if sslmode:
            config["OPTIONS"] = {"sslmode": sslmode}
        return config

    return {"ENGINE": "django.db.backends.sqlite3", "NAME": sqlite_name}
