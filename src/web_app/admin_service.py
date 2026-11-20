"""Servicios administrativos RBAC (RF-05), aprovisionamiento CLI y exportación CSV (RF-06)."""

import csv
from datetime import date, datetime, timezone
import io
import ipaddress
import json
from uuid import UUID

import psycopg

from web_app import security
from web_app.database import get_connection

PASSWORD_STATUS_LABEL = "Protegida - Argon2id"
TOTP_ACTIVE_LABEL = "Activo"
TOTP_PENDING_LABEL = "Pendiente"
DEFAULT_UNKNOWN_IP = "0.0.0.0"

CSV_EXPORT_COLUMNS = (
    "user_id",
    "email",
    "role",
    "full_name",
    "doc_type",
    "doc_number",
    "birth_date",
    "phone",
    "address",
    "blood_type",
    "allergies",
    "medical_conditions",
    "insurance_provider",
    "card_brand",
    "card_last4",
    "is_2fa_enabled",
    "created_at",
)


def _sanitize_ip(source_ip: str | None) -> str:
    if not source_ip:
        return DEFAULT_UNKNOWN_IP
    try:
        return str(ipaddress.ip_address(source_ip.strip()))
    except ValueError:
        return DEFAULT_UNKNOWN_IP


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


def require_admin(conn: psycopg.Connection, actor_user_id: str | UUID) -> UUID:
    """Verifica en PostgreSQL que el actor exista, esté activo, tenga 2FA y rol 'admin'."""
    try:
        uid = (
            actor_user_id
            if isinstance(actor_user_id, UUID)
            else UUID(str(actor_user_id))
        )
    except (ValueError, TypeError) as exc:
        raise PermissionError(
            "Acceso denegado: se requiere rol de administrador verificado con 2FA."
        ) from exc

    row = conn.execute(
        """
        SELECT id, role, is_active, is_2fa_enabled
        FROM app_sec.users
        WHERE id = %s
        """,
        (uid,),
    ).fetchone()
    if (
        row is None
        or row["role"] != "admin"
        or row["is_active"] is not True
        or row["is_2fa_enabled"] is not True
    ):
        raise PermissionError(
            "Acceso denegado: se requiere rol de administrador verificado con 2FA."
        )
    return row["id"]


def is_verified_admin(actor_user_id: str | UUID) -> bool:
    """Indica si el usuario posee rol 'admin' activo y 2FA confirmado en la BD."""
    try:
        with get_connection() as conn:
            require_admin(conn, actor_user_id)
        return True
    except PermissionError:
        return False


def _fetch_global_user_records(conn: psycopg.Connection) -> list[dict]:
    """Consulta usuarios sin secretos (sin password_hash, totp_secret_enc ni pan_enc)."""
    rows = conn.execute(
        """
        SELECT
            u.id,
            u.email,
            u.role,
            u.is_2fa_enabled,
            u.is_active,
            u.failed_login_attempts,
            u.locked_until,
            (u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked,
            u.created_at,
            p.full_name,
            p.doc_type,
            p.doc_number,
            p.birth_date,
            p.phone,
            p.address,
            h.blood_type_enc,
            h.allergies_enc,
            h.medical_conditions_enc,
            h.insurance_provider_enc,
            c.card_brand,
            c.card_last4
        FROM app_sec.users u
        LEFT JOIN app_sec.user_pii p ON p.user_id = u.id
        LEFT JOIN app_sec.user_phi h ON h.user_id = u.id
        LEFT JOIN LATERAL (
            SELECT ci.card_brand, ci.card_last4
            FROM app_sec.user_credit_info ci
            WHERE ci.user_id = u.id
            ORDER BY ci.created_at DESC
            LIMIT 1
        ) c ON TRUE
        ORDER BY u.created_at DESC
        """
    ).fetchall()

    records: list[dict] = []
    for row in rows:
        uid = row["id"]
        blood_type = None
        allergies = None
        medical_conditions = None
        insurance_provider = None
        if row["blood_type_enc"] is not None:
            blood_type = security.decrypt_field(
                row["blood_type_enc"],
                security.field_context("app_sec.user_phi", "blood_type_enc", uid),
            )
            allergies = security.decrypt_optional(
                row["allergies_enc"],
                security.field_context("app_sec.user_phi", "allergies_enc", uid),
            )
            medical_conditions = security.decrypt_optional(
                row["medical_conditions_enc"],
                security.field_context(
                    "app_sec.user_phi", "medical_conditions_enc", uid
                ),
            )
            insurance_provider = security.decrypt_field(
                row["insurance_provider_enc"],
                security.field_context(
                    "app_sec.user_phi", "insurance_provider_enc", uid
                ),
            )

        card_last4 = row["card_last4"]
        records.append(
            {
                "user_id": str(uid),
                "email": row["email"],
                "role": row["role"],
                "password_status": PASSWORD_STATUS_LABEL,
                "two_fa_status": (
                    TOTP_ACTIVE_LABEL if row["is_2fa_enabled"] else TOTP_PENDING_LABEL
                ),
                "is_2fa_enabled": row["is_2fa_enabled"],
                "is_active": row["is_active"],
                "lock_status": "Bloqueada" if row["is_locked"] else "Normal",
                "failed_login_attempts": row["failed_login_attempts"],
                "locked_until": row["locked_until"],
                "full_name": row["full_name"],
                "doc_type": row["doc_type"],
                "doc_number": row["doc_number"],
                "birth_date": row["birth_date"],
                "phone": row["phone"],
                "address": row["address"],
                "blood_type": blood_type,
                "allergies": allergies,
                "medical_conditions": medical_conditions,
                "insurance_provider": insurance_provider,
                "card_brand": row["card_brand"],
                "card_last4": card_last4,
                "masked_pan": security.mask_pan(card_last4) if card_last4 else "",
                "created_at": row["created_at"],
            }
        )
    return records


def list_users_for_admin(
    actor_user_id: str | UUID, *, source_ip: str | None = None
) -> list[dict]:
    """Devuelve el listado global seguro de usuarios y audita la consulta administrativa."""
    safe_ip = _sanitize_ip(source_ip)
    with get_connection() as conn, conn.transaction():
        admin_id = require_admin(conn, actor_user_id)
        records = _fetch_global_user_records(conn)
        _insert_audit_log(
            conn,
            admin_id,
            None,
            "ADMIN_VIEW_USERS",
            safe_ip,
            {"viewed_rows": len(records)},
        )
    return records


def build_csv_filename() -> str:
    """Genera el nombre dinámico requerido para el archivo CSV exportado."""
    return f"usuarios_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"


def _format_csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (date, datetime)):
        return security.sanitize_csv_cell(value.isoformat())
    return security.sanitize_csv_cell(value)


def export_users_csv_for_admin(
    actor_user_id: str | UUID, *, source_ip: str | None = None
) -> tuple[bytes, str, int]:
    """Genera CSV en memoria (utf-8-sig, anti CSV Injection) y registra CSV_EXPORT."""
    safe_ip = _sanitize_ip(source_ip)
    with get_connection() as conn, conn.transaction():
        admin_id = require_admin(conn, actor_user_id)
        records = _fetch_global_user_records(conn)

        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\r\n")
        writer.writerow(CSV_EXPORT_COLUMNS)
        for record in records:
            writer.writerow(
                [_format_csv_cell(record.get(col)) for col in CSV_EXPORT_COLUMNS]
            )

        csv_bytes = buf.getvalue().encode("utf-8-sig")
        filename = build_csv_filename()
        _insert_audit_log(
            conn,
            admin_id,
            None,
            "CSV_EXPORT",
            safe_ip,
            {"exported_rows": len(records)},
        )
    return csv_bytes, filename, len(records)


def _set_user_role(
    email: str, target_role: str, *, source_ip: str | None = None
) -> UUID:
    normalized_email = email.strip().lower()
    if not normalized_email:
        raise ValueError("El correo electrónico es obligatorio.")

    safe_ip = _sanitize_ip(source_ip)
    event_type = (
        "ADMIN_ROLE_GRANTED" if target_role == "admin" else "ADMIN_ROLE_REVOKED"
    )
    with get_connection() as conn, conn.transaction():
        row = conn.execute(
            """
            SELECT id, role, is_active, is_2fa_enabled
            FROM app_sec.users
            WHERE email = %s
            FOR UPDATE
            """,
            (normalized_email,),
        ).fetchone()
        if row is None:
            raise LookupError(f"No existe usuario con correo {normalized_email}.")
        if target_role == "admin":
            if row["is_active"] is not True:
                raise ValueError("La cuenta debe estar activa para asignarle rol admin.")
            if row["is_2fa_enabled"] is not True:
                raise ValueError(
                    "El usuario debe tener 2FA activado para ser administrador."
                )

        conn.execute(
            """
            UPDATE app_sec.users
            SET role = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (target_role, row["id"]),
        )
        _insert_audit_log(
            conn,
            None,
            row["id"],
            event_type,
            safe_ip,
            {"channel": "cli"},
        )
    return row["id"]


def promote_user_to_admin(email: str, *, source_ip: str | None = None) -> UUID:
    """Asigna rol 'admin' a una cuenta existente activa y con 2FA (solo vía CLI)."""
    return _set_user_role(email, "admin", source_ip=source_ip)


def demote_admin_to_user(email: str, *, source_ip: str | None = None) -> UUID:
    """Revoca rol 'admin' devolviendo la cuenta a 'user' (solo vía CLI)."""
    return _set_user_role(email, "user", source_ip=source_ip)
