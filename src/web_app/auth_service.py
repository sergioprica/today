import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

import psycopg

from web_app import security
from web_app.database import get_connection


TOTP_PERIOD = 30
TOTP_DIGITS = 6
ISSUER = "Today"
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15


def create_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(email: str, secret: str) -> str:
    label = quote(f"{ISSUER}:{email}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": ISSUER,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def _totp_for_counter(secret: str, counter: int) -> str:
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False
    counter = (timestamp if timestamp is not None else int(time.time())) // TOTP_PERIOD
    return any(
        hmac.compare_digest(_totp_for_counter(secret, counter + offset), code)
        for offset in (-1, 0, 1)
    )


def hash_password(password: str) -> str:
    return security.hash_password(password)


def create_user(
    name: str, email: str, password_hash: str, totp_secret: str
) -> int | None:
    """Crea el usuario y devuelve su user_id, o None si el correo ya existe."""
    normalized_email = email.strip().lower()
    ciphertext, nonce = security.encrypt_totp_secret(totp_secret, normalized_email)
    try:
        with get_connection() as connection:
            row = connection.execute(
                """
                INSERT INTO users (
                    email,
                    full_name,
                    password_hash,
                    totp_secret_ciphertext,
                    totp_secret_nonce
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING user_id
                """,
                (normalized_email, name.strip(), password_hash, ciphertext, nonce),
            ).fetchone()
    except psycopg.errors.UniqueViolation:
        return None
    return row["user_id"]


def authenticate(email: str, password: str, otp_code: str) -> dict | None:
    """Devuelve el perfil si correo + contraseña + OTP son correctos.

    Tras MAX_FAILED_LOGINS fallos seguidos la cuenta queda bloqueada
    LOCKOUT_MINUTES minutos. El mensaje al usuario es siempre el mismo para no
    revelar si la cuenta existe o está bloqueada.
    """
    normalized_email = email.strip().lower()
    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT user_id, email, full_name, password_hash,
                   totp_secret_ciphertext, totp_secret_nonce,
                   locked_until IS NOT NULL
                       AND locked_until > CURRENT_TIMESTAMP AS is_locked
            FROM users
            WHERE email = %s
            """,
            (normalized_email,),
        ).fetchone()

        # Se verifica la contraseña aunque el usuario no exista o esté bloqueado,
        # para que el tiempo de respuesta sea el mismo.
        password_ok = security.verify_password(
            password, user["password_hash"] if user else None
        )
        if user is None or user["is_locked"]:
            return None

        login_ok = (
            password_ok
            and user["totp_secret_ciphertext"] is not None
            and verify_totp(
                security.decrypt_totp_secret(
                    user["totp_secret_ciphertext"],
                    user["totp_secret_nonce"],
                    user["email"],
                ),
                otp_code,
            )
        )

        if not login_ok:
            connection.execute(
                """
                UPDATE users SET
                    failed_login_attempts = CASE
                        WHEN failed_login_attempts + 1 >= %(max)s THEN 0
                        ELSE failed_login_attempts + 1 END,
                    locked_until = CASE
                        WHEN failed_login_attempts + 1 >= %(max)s
                            THEN CURRENT_TIMESTAMP + make_interval(mins => %(mins)s)
                        ELSE locked_until END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %(id)s
                """,
                {"max": MAX_FAILED_LOGINS, "mins": LOCKOUT_MINUTES, "id": user["user_id"]},
            )
            return None

        connection.execute(
            """
            UPDATE users SET failed_login_attempts = 0, locked_until = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = %s
              AND (failed_login_attempts <> 0 OR locked_until IS NOT NULL)
            """,
            (user["user_id"],),
        )
    return {"user_id": user["user_id"], "name": user["full_name"], "email": user["email"]}
