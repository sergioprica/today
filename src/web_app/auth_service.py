"""Servicios de registro, autenticación 2FA (pyotp) y lectura segura de perfil."""

from dataclasses import dataclass
from datetime import date
import ipaddress
import json
import re
import time
import uuid
from uuid import UUID

import psycopg
import pyotp

from web_app import config, security
from web_app.database import get_connection

TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_VALID_WINDOW = 1
ISSUER = "Today"

MAX_FAILED_LOGINS = 5
LOCKOUT_SCHEDULE_MINUTES = (15, 30, 60)
IP_RATE_LIMIT_MAX_ATTEMPTS = 10
IP_RATE_LIMIT_WINDOW_MINUTES = 15

VALID_DOC_TYPES = frozenset({"CC", "CE", "PASAPORTE", "TI", "NIT"})
DEFAULT_UNKNOWN_IP = "0.0.0.0"
GENERIC_LOGIN_ERROR = "Credenciales o código de verificación inválidos."

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class RegistrationError(ValueError):
    """Error de validación o integridad durante el registro de usuario."""


class DuplicateAccountError(RegistrationError):
    """Conflicto por correo electrónico o documento de identidad ya registrado."""


@dataclass(frozen=True)
class PiiInput:
    full_name: str
    doc_type: str
    doc_number: str
    birth_date: date
    phone: str
    address: str


@dataclass(frozen=True)
class PhiInput:
    blood_type: str
    insurance_provider: str
    consent_accepted: bool
    allergies: str | None = None
    medical_conditions: str | None = None


@dataclass(frozen=True)
class CreditInfoInput:
    cardholder_name: str
    pan: str
    exp_date: str
    card_brand: str | None = None


def create_totp_secret() -> str:
    """Genera una semilla Base32 de 32 caracteres (160 bits de entropía)."""
    return pyotp.random_base32(length=32)


def provisioning_uri(email: str, secret: str) -> str:
    """Construye la URI otpauth://totp/... estándar para apps autenticadoras."""
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD)
    return totp.provisioning_uri(name=email.strip().lower(), issuer_name=ISSUER)


def match_totp_timestep(
    secret: str,
    code: str,
    *,
    timestamp: int | None = None,
    valid_window: int = TOTP_VALID_WINDOW,
) -> int | None:
    """Valida el OTP en tiempo constante vía pyotp y devuelve el bloque de 30s."""
    cleaned = code.strip()
    if len(cleaned) != TOTP_DIGITS or not cleaned.isascii() or not cleaned.isdigit():
        return None
    now = int(time.time()) if timestamp is None else int(timestamp)
    base_timestep = now // TOTP_PERIOD
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD)

    matched: int | None = None
    for offset in range(-valid_window, valid_window + 1):
        candidate = base_timestep + offset
        if candidate < 0:
            continue
        if totp.verify(cleaned, for_time=candidate * TOTP_PERIOD, valid_window=0):
            if matched is None:
                matched = candidate
    return matched


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    """Indica si el código TOTP es válido dentro de la ventana permitida."""
    return match_totp_timestep(secret, code, timestamp=timestamp) is not None


def hash_password(password: str, *, email: str = "", name: str = "") -> str:
    """Valida la política de contraseñas en backend antes de hashear con Argon2id."""
    if err := security.password_policy_error(password, email=email, name=name):
        raise RegistrationError(err)
    return security.hash_password(password)


def validate_login_inputs(email: str, password: str, otp_code: str) -> str | None:
    """Valida formato básico del formulario de acceso antes de consultar la BD."""
    normalized_email = email.strip().lower()
    cleaned_otp = otp_code.strip()
    if (
        not _EMAIL_RE.fullmatch(normalized_email)
        or not password
        or len(cleaned_otp) != TOTP_DIGITS
        or not cleaned_otp.isascii()
        or not cleaned_otp.isdigit()
    ):
        return "Complete todos los campos con el formato requerido."
    return None


def _sanitize_ip(source_ip: str | None) -> str:
    if not source_ip:
        return DEFAULT_UNKNOWN_IP
    try:
        return str(ipaddress.ip_address(source_ip.strip()))
    except ValueError:
        return DEFAULT_UNKNOWN_IP


def _insert_auth_attempt(
    conn: psycopg.Connection,
    email_attempted: str,
    user_id: UUID | None,
    source_ip: str,
    result_code: str,
) -> None:
    conn.execute(
        """
        INSERT INTO app_sec.auth_attempts (email_attempted, user_id, source_ip, result_code)
        VALUES (%s, %s, %s::inet, %s)
        """,
        (email_attempted, user_id, source_ip, result_code),
    )


def _insert_audit_log(
    conn: psycopg.Connection,
    actor_user_id: UUID | None,
    target_user_id: UUID | None,
    event_type: str,
    source_ip: str,
    metadata: dict | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO app_sec.audit_logs (
            actor_user_id, target_user_id, event_type, source_ip, metadata
        )
        VALUES (%s, %s, %s, %s::inet, %s::jsonb)
        """,
        (
            actor_user_id,
            target_user_id,
            event_type,
            source_ip,
            json.dumps(metadata or {}),
        ),
    )


def _record_failed_attempt(
    conn: psycopg.Connection,
    user_id: UUID,
    current_failures: int,
    email_attempted: str,
    source_ip: str,
    result_code: str,
) -> None:
    new_attempts = current_failures + 1
    if new_attempts >= MAX_FAILED_LOGINS:
        idx = min(new_attempts - MAX_FAILED_LOGINS, len(LOCKOUT_SCHEDULE_MINUTES) - 1)
        lock_minutes = LOCKOUT_SCHEDULE_MINUTES[idx]
        conn.execute(
            """
            UPDATE app_sec.users
            SET failed_login_attempts = %s,
                locked_until = NOW() + make_interval(mins => %s),
                updated_at = NOW()
            WHERE id = %s
            """,
            (new_attempts, lock_minutes, user_id),
        )
        _insert_audit_log(
            conn,
            user_id,
            user_id,
            "ACCOUNT_LOCKED",
            source_ip,
            {"failed_attempts": new_attempts, "lockout_minutes": lock_minutes},
        )
    else:
        conn.execute(
            """
            UPDATE app_sec.users
            SET failed_login_attempts = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (new_attempts, user_id),
        )

    _insert_auth_attempt(conn, email_attempted, user_id, source_ip, result_code)


def _validate_registration_payload(
    *,
    email: str,
    password_hash: str,
    totp_secret: str,
    otp_code: str,
    pii: PiiInput,
    phi: PhiInput,
    credit: CreditInfoInput,
    timestamp: int | None,
) -> tuple[str, int, PiiInput, PhiInput, str, str, str, str, str]:
    normalized_email = email.strip().lower()
    if not _EMAIL_RE.fullmatch(normalized_email):
        raise RegistrationError("El correo electrónico no tiene un formato válido.")
    if not password_hash:
        raise RegistrationError("El hash de contraseña es obligatorio.")

    full_name = pii.full_name.strip()
    doc_type = pii.doc_type.strip().upper()
    doc_number = pii.doc_number.strip()
    phone = pii.phone.strip()
    address = pii.address.strip()
    if not all([full_name, doc_number, phone, address]):
        raise RegistrationError("Todos los campos personales (PII) son obligatorios.")
    if doc_type not in VALID_DOC_TYPES:
        raise RegistrationError("Tipo de documento no permitido.")
    if not isinstance(pii.birth_date, date) or pii.birth_date > date.today():
        raise RegistrationError("La fecha de nacimiento no es válida.")

    blood_type = phi.blood_type.strip()
    insurance_provider = phi.insurance_provider.strip()
    if not phi.consent_accepted:
        raise RegistrationError(
            "Debes aceptar el consentimiento informado para el tratamiento de datos de salud."
        )
    if not blood_type or not insurance_provider:
        raise RegistrationError(
            "El grupo sanguíneo y la entidad de salud son obligatorios."
        )

    cardholder_name = credit.cardholder_name.strip()
    if not cardholder_name:
        raise RegistrationError("El nombre del titular de la tarjeta es obligatorio.")
    try:
        normalized_pan = security.validate_pan(credit.pan)
        exp_date = security.validate_exp_date(credit.exp_date)
    except ValueError as exc:
        raise RegistrationError(str(exc)) from None

    card_last4 = normalized_pan[-4:]
    card_brand = (credit.card_brand or "").strip() or security.detect_card_brand(
        normalized_pan
    )

    matched_timestep = match_totp_timestep(
        totp_secret, otp_code.strip(), timestamp=timestamp
    )
    if matched_timestep is None:
        raise RegistrationError("El código de verificación 2FA inicial no es válido.")

    clean_pii = PiiInput(
        full_name=full_name,
        doc_type=doc_type,
        doc_number=doc_number,
        birth_date=pii.birth_date,
        phone=phone,
        address=address,
    )
    clean_phi = PhiInput(
        blood_type=blood_type,
        insurance_provider=insurance_provider,
        consent_accepted=True,
        allergies=phi.allergies,
        medical_conditions=phi.medical_conditions,
    )
    return (
        normalized_email,
        matched_timestep,
        clean_pii,
        clean_phi,
        cardholder_name,
        normalized_pan,
        exp_date,
        card_last4,
        card_brand,
    )


def register_user(
    *,
    email: str,
    password_hash: str,
    totp_secret: str,
    otp_code: str,
    pii: PiiInput,
    phi: PhiInput,
    credit: CreditInfoInput,
    source_ip: str | None = None,
    timestamp: int | None = None,
) -> UUID:
    """Registra usuario, PII, PHI cifrado, tarjeta cifrada y auditoría en una transacción."""
    (
        normalized_email,
        matched_timestep,
        clean_pii,
        clean_phi,
        cardholder_name,
        normalized_pan,
        exp_date,
        card_last4,
        card_brand,
    ) = _validate_registration_payload(
        email=email,
        password_hash=password_hash,
        totp_secret=totp_secret,
        otp_code=otp_code,
        pii=pii,
        phi=phi,
        credit=credit,
        timestamp=timestamp,
    )

    user_id = uuid.uuid4()
    credit_id = uuid.uuid4()
    key_version = config.encryption_key_version()
    safe_ip = _sanitize_ip(source_ip)

    totp_secret_enc = security.encrypt_totp_secret(totp_secret, user_id)

    blood_type_enc = security.encrypt_field(
        clean_phi.blood_type,
        security.field_context("app_sec.user_phi", "blood_type_enc", user_id),
    )
    allergies_enc = security.encrypt_optional(
        clean_phi.allergies,
        security.field_context("app_sec.user_phi", "allergies_enc", user_id),
    )
    medical_conditions_enc = security.encrypt_optional(
        clean_phi.medical_conditions,
        security.field_context("app_sec.user_phi", "medical_conditions_enc", user_id),
    )
    insurance_provider_enc = security.encrypt_field(
        clean_phi.insurance_provider,
        security.field_context("app_sec.user_phi", "insurance_provider_enc", user_id),
    )

    credit_owner = f"{user_id}:{credit_id}"
    cardholder_name_enc = security.encrypt_field(
        cardholder_name,
        security.field_context("app_sec.user_credit_info", "cardholder_name_enc", credit_owner),
    )
    pan_enc = security.encrypt_field(
        normalized_pan,
        security.field_context("app_sec.user_credit_info", "pan_enc", credit_owner),
    )
    exp_date_enc = security.encrypt_field(
        exp_date,
        security.field_context("app_sec.user_credit_info", "exp_date_enc", credit_owner),
    )

    try:
        with get_connection() as conn, conn.transaction():
            conn.execute(
                """
                INSERT INTO app_sec.users (
                    id, email, password_hash, role, totp_secret_enc,
                    totp_key_version, is_2fa_enabled, last_totp_timestep, is_active
                )
                VALUES (%s, %s, %s, 'user', %s, %s, TRUE, %s, TRUE)
                """,
                (
                    user_id,
                    normalized_email,
                    password_hash,
                    totp_secret_enc,
                    key_version,
                    matched_timestep,
                ),
            )
            conn.execute(
                """
                INSERT INTO app_sec.user_pii (
                    user_id, full_name, doc_type, doc_number, birth_date, phone, address
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    clean_pii.full_name,
                    clean_pii.doc_type,
                    clean_pii.doc_number,
                    clean_pii.birth_date,
                    clean_pii.phone,
                    clean_pii.address,
                ),
            )
            conn.execute(
                """
                INSERT INTO app_sec.user_phi (
                    user_id, blood_type_enc, allergies_enc, medical_conditions_enc,
                    insurance_provider_enc, key_version, consent_accepted
                )
                VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                """,
                (
                    user_id,
                    blood_type_enc,
                    allergies_enc,
                    medical_conditions_enc,
                    insurance_provider_enc,
                    key_version,
                ),
            )
            conn.execute(
                """
                INSERT INTO app_sec.user_credit_info (
                    id, user_id, cardholder_name_enc, pan_enc, exp_date_enc,
                    card_last4, card_brand, key_version
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    credit_id,
                    user_id,
                    cardholder_name_enc,
                    pan_enc,
                    exp_date_enc,
                    card_last4,
                    card_brand,
                    key_version,
                ),
            )
            _insert_audit_log(conn, user_id, user_id, "USER_REGISTERED", safe_ip)
            _insert_audit_log(conn, user_id, user_id, "2FA_ENROLLED", safe_ip)
    except psycopg.errors.UniqueViolation as exc:
        constraint = getattr(getattr(exc, "diag", None), "constraint_name", None)
        if constraint == "uq_pii_document":
            raise DuplicateAccountError(
                "Ya existe una cuenta registrada con ese documento de identidad."
            ) from None
        raise DuplicateAccountError(
            "Ya existe una cuenta registrada con ese correo electrónico."
        ) from None
    except psycopg.errors.CheckViolation:
        raise RegistrationError(
            "Los datos enviados no cumplen las restricciones requeridas."
        ) from None

    return user_id


def authenticate(
    email: str,
    password: str,
    otp_code: str,
    *,
    source_ip: str | None = None,
    timestamp: int | None = None,
) -> dict | None:
    """Autentica las 3 variables (U, P, O) con anti-replay, rate limiting y bloqueo."""
    if validate_login_inputs(email, password, otp_code) is not None:
        return None

    normalized_email = email.strip().lower()
    cleaned_otp = otp_code.strip()
    safe_ip = _sanitize_ip(source_ip)

    with get_connection() as conn, conn.transaction():
        rate_row = conn.execute(
            """
            SELECT COUNT(*) AS recent_failures
            FROM app_sec.auth_attempts
            WHERE source_ip = %s::inet
              AND result_code <> 'LOGIN_SUCCESS'
              AND created_at >= NOW() - make_interval(mins => %s)
            """,
            (safe_ip, IP_RATE_LIMIT_WINDOW_MINUTES),
        ).fetchone()
        if rate_row["recent_failures"] >= IP_RATE_LIMIT_MAX_ATTEMPTS:
            security.verify_password(password, None)
            _insert_auth_attempt(
                conn, normalized_email, None, safe_ip, "LOGIN_BLOCKED_RATE_LIMIT"
            )
            return None

        user = conn.execute(
            """
            SELECT u.id, u.email, u.password_hash, u.role,
                   u.totp_secret_enc, u.is_2fa_enabled, u.last_totp_timestep,
                   u.failed_login_attempts,
                   (u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked,
                   u.is_active,
                   p.full_name
            FROM app_sec.users u
            LEFT JOIN app_sec.user_pii p ON p.user_id = u.id
            WHERE u.email = %s
            FOR UPDATE OF u
            """,
            (normalized_email,),
        ).fetchone()

        if user is None:
            security.verify_password(password, None)
            _insert_auth_attempt(
                conn, normalized_email, None, safe_ip, "FAIL_USER_NOT_FOUND"
            )
            return None

        if user["is_locked"]:
            _insert_auth_attempt(
                conn, normalized_email, user["id"], safe_ip, "LOGIN_BLOCKED_RATE_LIMIT"
            )
            return None

        if not user["is_active"] or not user["is_2fa_enabled"]:
            security.verify_password(password, None)
            _insert_auth_attempt(
                conn, normalized_email, user["id"], safe_ip, "FAIL_ACCOUNT_INACTIVE"
            )
            return None

        password_ok = security.verify_password(password, user["password_hash"])
        totp_secret = security.decrypt_totp_secret(user["totp_secret_enc"], user["id"])
        matched_timestep = match_totp_timestep(
            totp_secret, cleaned_otp, timestamp=timestamp
        )

        if password_ok and matched_timestep is not None:
            if matched_timestep <= user["last_totp_timestep"]:
                _record_failed_attempt(
                    conn,
                    user["id"],
                    user["failed_login_attempts"],
                    normalized_email,
                    safe_ip,
                    "FAIL_OTP_REPLAY",
                )
                return None

            conn.execute(
                """
                UPDATE app_sec.users
                SET last_totp_timestep = %s,
                    failed_login_attempts = 0,
                    locked_until = NULL,
                    last_login_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (matched_timestep, user["id"]),
            )
            _insert_auth_attempt(
                conn, normalized_email, user["id"], safe_ip, "LOGIN_SUCCESS"
            )
            _insert_audit_log(
                conn, user["id"], user["id"], "LOGIN_SUCCESS", safe_ip
            )
            return {
                "user_id": str(user["id"]),
                "name": user["full_name"] or user["email"],
                "email": user["email"],
                "role": user["role"],
            }

        if password_ok:
            result_code = "FAIL_INVALID_OTP"
        elif matched_timestep is not None:
            result_code = "FAIL_INVALID_PASSWORD"
        else:
            result_code = "FAIL_INVALID_PASSWORD_AND_OTP"

        _record_failed_attempt(
            conn,
            user["id"],
            user["failed_login_attempts"],
            normalized_email,
            safe_ip,
            result_code,
        )
        return None


def get_user_profile(user_id: str | UUID) -> dict | None:
    """Devuelve el perfil propio del usuario descifrando PHI y enmascarando tarjetas."""
    uid = user_id if isinstance(user_id, UUID) else UUID(str(user_id))
    with get_connection() as conn:
        user = conn.execute(
            """
            SELECT id, email, role, is_2fa_enabled, is_active, last_login_at, created_at
            FROM app_sec.users
            WHERE id = %s
            """,
            (uid,),
        ).fetchone()
        if user is None:
            return None

        pii_row = conn.execute(
            """
            SELECT full_name, doc_type, doc_number, birth_date, phone, address
            FROM app_sec.user_pii
            WHERE user_id = %s
            """,
            (uid,),
        ).fetchone()

        phi_row = conn.execute(
            """
            SELECT blood_type_enc, allergies_enc, medical_conditions_enc,
                   insurance_provider_enc, consent_accepted, consent_accepted_at
            FROM app_sec.user_phi
            WHERE user_id = %s
            """,
            (uid,),
        ).fetchone()

        credit_rows = conn.execute(
            """
            SELECT id, card_brand, card_last4, created_at
            FROM app_sec.user_credit_info
            WHERE user_id = %s
            ORDER BY created_at DESC
            """,
            (uid,),
        ).fetchall()

    phi_data: dict | None = None
    if phi_row is not None:
        phi_data = {
            "blood_type": security.decrypt_field(
                phi_row["blood_type_enc"],
                security.field_context("app_sec.user_phi", "blood_type_enc", uid),
            ),
            "allergies": security.decrypt_optional(
                phi_row["allergies_enc"],
                security.field_context("app_sec.user_phi", "allergies_enc", uid),
            ),
            "medical_conditions": security.decrypt_optional(
                phi_row["medical_conditions_enc"],
                security.field_context(
                    "app_sec.user_phi", "medical_conditions_enc", uid
                ),
            ),
            "insurance_provider": security.decrypt_field(
                phi_row["insurance_provider_enc"],
                security.field_context(
                    "app_sec.user_phi", "insurance_provider_enc", uid
                ),
            ),
            "consent_accepted": phi_row["consent_accepted"],
            "consent_accepted_at": phi_row["consent_accepted_at"],
        }

    credit_cards = [
        {
            "id": str(row["id"]),
            "card_brand": row["card_brand"],
            "card_last4": row["card_last4"],
            "masked_pan": security.mask_pan(row["card_last4"]),
            "created_at": row["created_at"],
        }
        for row in credit_rows
    ]

    return {
        "user_id": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "is_2fa_enabled": user["is_2fa_enabled"],
        "is_active": user["is_active"],
        "last_login_at": user["last_login_at"],
        "created_at": user["created_at"],
        "pii": dict(pii_row) if pii_row is not None else None,
        "phi": phi_data,
        "credit_cards": credit_cards,
    }
