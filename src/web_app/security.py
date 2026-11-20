"""Primitivas de seguridad: política de contraseñas, Argon2id, AEAD AES-256-GCM y PCI-DSS."""

from datetime import date
import os
import re
from uuid import UUID

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from web_app import config

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
PASSWORD_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16

# Argon2id conforme al SRS (>= 64 MiB de memoria, >= 3 iteraciones, >= 1 hilo).
password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Hash de referencia para igualar el tiempo de respuesta cuando el correo no existe.
_DUMMY_HASH = password_hasher.hash("dummy-password-for-timing")

# Contraseñas comunes y secuencias triviales que se rechazan aunque cumplan longitud.
_WEAK_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "12345678901234",
        "qwertyuiopas",
        "qwerty123456",
        "password1234",
        "password12345",
        "passwordpassword",
        "contraseña123",
        "contraseña1234",
        "contrasena123",
        "contrasena1234",
        "aaaaaaaaaaaa",
        "abcdefghijkl",
        "abc123abc123",
        "iloveyou1234",
        "administrador",
        "admin1234567",
        "bienvenido123",
        "holamundo123",
        "today1234567",
    }
)

_TRIVIAL_SEQUENCES = (
    "123456",
    "654321",
    "qwerty",
    "password",
    "contraseña",
    "contrasena",
    "abc123",
    "admin123",
    "000000",
    "111111",
)

_EXP_DATE_RE = re.compile(r"^(0[1-9]|1[0-2])/([0-9]{2})$")


# --- Contraseñas (RF-02.A y RF-02.B) ---------------------------------------


def password_policy_error(password: str, email: str = "", name: str = "") -> str | None:
    """Devuelve un mensaje de error si la contraseña incumple la política, o None."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"La contraseña debe tener al menos {PASSWORD_MIN_LENGTH} caracteres."
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"La contraseña no puede superar {PASSWORD_MAX_LENGTH} caracteres."

    if not any("A" <= ch <= "Z" for ch in password):
        return "La contraseña debe incluir al menos una letra mayúscula."
    if not any("a" <= ch <= "z" for ch in password):
        return "La contraseña debe incluir al menos una letra minúscula."
    if not any("0" <= ch <= "9" for ch in password):
        return "La contraseña debe incluir al menos un dígito."
    if not any(ch in PASSWORD_SPECIAL_CHARS for ch in password):
        return "La contraseña debe incluir al menos un carácter especial."

    lowered = password.lower()
    if lowered in _WEAK_PASSWORDS or len(set(lowered)) <= 3:
        return "Esa contraseña es demasiado común. Elige otra."
    if any(seq in lowered for seq in _TRIVIAL_SEQUENCES):
        return "La contraseña no puede contener secuencias triviales o palabras comunes."

    normalized_email = email.strip().lower()
    personal_parts = [normalized_email]
    if "@" in normalized_email:
        personal_parts.append(normalized_email.split("@", 1)[0])
    stripped_name = name.strip().lower()
    if stripped_name:
        personal_parts.append(stripped_name)
        personal_parts.extend(stripped_name.split())

    if any(len(part) >= 3 and part in lowered for part in personal_parts):
        return "La contraseña no puede contener tu nombre ni tu correo."
    return None


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verifica la contraseña. Con password_hash=None hace el mismo trabajo y falla."""
    try:
        password_hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


# --- Cifrado AEAD AES-256-GCM en columna única BYTEA (Sección 3.1) ----------
#
# Formato almacenado: nonce (12 bytes) || ciphertext || auth_tag (16 bytes).
# "context" actúa como AAD para ligar el texto cifrado a su tabla, columna y dueño.


def field_context(table: str, column: str, owner: str | UUID) -> str:
    """Construye el contexto AAD determinista para un campo cifrado."""
    return f"{table}.{column}:{owner}"


def encrypt_field(value: str, context: str) -> bytes:
    """Cifra una cadena UTF-8 y devuelve nonce (12B) || ciphertext || tag (16B)."""
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ct_and_tag = AESGCM(config.encryption_key()).encrypt(
        nonce, value.encode("utf-8"), context.encode("utf-8")
    )
    return nonce + ct_and_tag


def decrypt_field(token: bytes | memoryview, context: str) -> str:
    """Descifra un paquete BYTEA (nonce || ciphertext || tag) validando el AAD."""
    raw = bytes(token)
    if len(raw) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES:
        raise ValueError("Dato cifrado inválido o truncado.")
    nonce, ct_and_tag = raw[:AES_GCM_NONCE_BYTES], raw[AES_GCM_NONCE_BYTES:]
    plaintext = AESGCM(config.encryption_key()).decrypt(
        nonce, ct_and_tag, context.encode("utf-8")
    )
    return plaintext.decode("utf-8")


def encrypt_optional(value: str | None, context: str) -> bytes | None:
    """Cifra un campo opcional; None o vacío/espacios se guarda como NULL."""
    if value is None or not value.strip():
        return None
    return encrypt_field(value.strip(), context)


def decrypt_optional(token: bytes | memoryview | None, context: str) -> str | None:
    """Descifra un campo opcional; devuelve None si es NULL en BD."""
    if token is None:
        return None
    return decrypt_field(token, context)


def encrypt_totp_secret(secret: str, user_id: str | UUID) -> bytes:
    """Cifra el secreto TOTP ligado al UUID inmutable del usuario."""
    return encrypt_field(secret, field_context("app_sec.users", "totp_secret_enc", user_id))


def decrypt_totp_secret(token: bytes | memoryview, user_id: str | UUID) -> str:
    """Descifra el secreto TOTP ligado al UUID del usuario."""
    return decrypt_field(token, field_context("app_sec.users", "totp_secret_enc", user_id))


# --- Validación y enmascaramiento crediticio (RF-01.4, sin CVV/CVC) ---------


def is_valid_luhn(pan: str) -> bool:
    """Verifica el dígito de control de un PAN numérico mediante el algoritmo de Luhn."""
    if not pan or not pan.isascii() or not pan.isdigit():
        return False
    total = 0
    for idx, ch in enumerate(reversed(pan)):
        digit = ord(ch) - 48
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def validate_pan(raw_pan: str) -> str:
    """Normaliza un PAN (sin espacios/guiones) y valida longitud y algoritmo de Luhn."""
    digits = raw_pan.replace(" ", "").replace("-", "").strip()
    if not (13 <= len(digits) <= 19) or not digits.isascii() or not digits.isdigit():
        raise ValueError("El número de tarjeta debe tener entre 13 y 19 dígitos.")
    if not is_valid_luhn(digits):
        raise ValueError("El número de tarjeta no supera la validación de Luhn.")
    return digits


def detect_card_brand(pan: str) -> str:
    """Identifica la franquicia principal a partir del BIN del PAN."""
    if pan.startswith("4"):
        return "Visa"
    if len(pan) >= 2 and 51 <= int(pan[:2]) <= 55:
        return "Mastercard"
    if len(pan) >= 4 and 2221 <= int(pan[:4]) <= 2720:
        return "Mastercard"
    if pan.startswith(("34", "37")):
        return "Amex"
    if pan.startswith(("6011", "65")):
        return "Discover"
    if pan.startswith(("36", "38")) or (len(pan) >= 3 and 300 <= int(pan[:3]) <= 305):
        return "Diners Club"
    return "Otra"


def validate_exp_date(exp_date: str, *, check_not_expired: bool = True) -> str:
    """Valida el formato MM/AA y opcionalmente que la tarjeta no esté vencida."""
    cleaned = exp_date.strip()
    match = _EXP_DATE_RE.fullmatch(cleaned)
    if match is None:
        raise ValueError("La fecha de expiración debe tener formato MM/AA.")
    if check_not_expired:
        month = int(match.group(1))
        year = 2000 + int(match.group(2))
        today = date.today()
        if (year, month) < (today.year, today.month):
            raise ValueError("La tarjeta está vencida.")
    return cleaned


def mask_pan(card_last4: str) -> str:
    """Devuelve el PAN enmascarado con los últimos 4 dígitos visibles."""
    return f"**** **** **** {card_last4}"


# --- Protección anti CSV Injection (RF-06.5) --------------------------------

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: object) -> str:
    """Prefija con apóstrofe cualquier texto que inicie con caracteres de fórmula."""
    if value is None:
        return ""
    text = str(value)
    if text and (
        text[0] in CSV_FORMULA_PREFIXES
        or text.lstrip(" ").startswith(CSV_FORMULA_PREFIXES)
    ):
        return "'" + text
    return text
