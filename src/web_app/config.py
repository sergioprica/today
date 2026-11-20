"""Configuración leída exclusivamente de variables de entorno.

Ningún secreto (contraseña de PostgreSQL, clave de cifrado) vive en el repo.
"""

import base64
import os
import secrets

ENCRYPTION_KEY_BYTES = 32  # AES-256
DEFAULT_DB_SSLMODE = "require"
VALID_SSLMODES = frozenset(
    {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
)
DEFAULT_KEY_VERSION = 1


class ConfigError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Falta la variable de entorno {name}")
    return value


def db_conninfo() -> dict[str, str]:
    """Parámetros de conexión para psycopg.connect(**db_conninfo())."""
    sslmode = os.environ.get("DB_SSLMODE", DEFAULT_DB_SSLMODE).strip() or DEFAULT_DB_SSLMODE
    if sslmode not in VALID_SSLMODES:
        raise ConfigError(f"Valor inválido para DB_SSLMODE: {sslmode}")

    conninfo: dict[str, str] = {
        "host": _require("DB_HOST"),
        "port": os.environ.get("DB_PORT", "5432").strip() or "5432",
        "dbname": _require("DB_NAME"),
        "user": _require("DB_USER"),
        "password": _require("DB_PASSWORD"),
        "sslmode": sslmode,
    }
    sslrootcert = os.environ.get("DB_SSLROOTCERT", "").strip()
    if sslrootcert:
        conninfo["sslrootcert"] = sslrootcert
    return conninfo


def encryption_key() -> bytes:
    """Clave AES-256 (32 bytes) para cifrar TOTP, PHI y datos crediticios."""
    raw = _require("APP_ENCRYPTION_KEY")
    try:
        key = base64.urlsafe_b64decode(raw)
    except ValueError as exc:
        raise ConfigError("APP_ENCRYPTION_KEY no es base64 válido") from exc
    if len(key) != ENCRYPTION_KEY_BYTES:
        raise ConfigError(
            f"APP_ENCRYPTION_KEY debe decodificar a {ENCRYPTION_KEY_BYTES} bytes"
        )
    return key


def encryption_key_version() -> int:
    """Versión de llave criptográfica activa para rotación sin pérdida de datos."""
    raw = os.environ.get("APP_ENCRYPTION_KEY_VERSION", str(DEFAULT_KEY_VERSION)).strip()
    try:
        version = int(raw)
    except ValueError as exc:
        raise ConfigError("APP_ENCRYPTION_KEY_VERSION debe ser un entero positivo") from exc
    if version < 1:
        raise ConfigError("APP_ENCRYPTION_KEY_VERSION debe ser >= 1")
    return version


def generate_encryption_key() -> str:
    """Genera una clave criptográficamente segura en base64 url-safe."""
    return base64.urlsafe_b64encode(secrets.token_bytes(ENCRYPTION_KEY_BYTES)).decode()


def main() -> None:
    print(generate_encryption_key())


if __name__ == "__main__":
    main()
