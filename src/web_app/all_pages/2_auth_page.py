from datetime import date
import io
import re
import time

import psycopg
import qrcode
import streamlit as st

from web_app import admin_service, auth_service, config, security

SESSION_TIMEOUT_SECONDS = 20 * 60
DOC_TYPES = ("CC", "CE", "PASAPORTE", "TI", "NIT")
BLOOD_TYPES = ("O+", "O-", "A+", "A-", "B+", "B-", "AB+", "AB-")
CARD_BRAND_OPTIONS = (
    "Detectar automáticamente",
    "Visa",
    "Mastercard",
    "Amex",
    "Discover",
    "Diners Club",
    "Otra",
)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _client_source_ip() -> str | None:
    """Obtiene la IP del cliente desde cabeceras de proxy o contexto de Streamlit."""
    try:
        headers = st.context.headers
        if headers:
            lowered = {k.lower(): v for k, v in headers.items()}
            if real_ip := lowered.get("x-real-ip", "").strip():
                return real_ip
            if forwarded := lowered.get("x-forwarded-for", "").strip():
                first_ip = forwarded.split(",", 1)[0].strip()
                if first_ip:
                    return first_ip
        ctx_ip = getattr(st.context, "ip_address", None)
        return str(ctx_ip).strip() if ctx_ip else None
    except Exception:
        return None


def _validate_registration_form(
    *,
    email: str,
    password: str,
    password_confirmation: str,
    full_name: str,
    doc_type: str,
    doc_number: str,
    birth_date: date | None,
    phone: str,
    address: str,
    blood_type: str,
    insurance_provider: str,
    allergies: str,
    medical_conditions: str,
    consent_accepted: bool,
    cardholder_name: str,
    pan: str,
    exp_date: str,
    selected_brand: str,
) -> tuple[
    str | None,
    auth_service.PiiInput | None,
    auth_service.PhiInput | None,
    auth_service.CreditInfoInput | None,
]:
    normalized_email = email.strip().lower()
    if not _EMAIL_RE.fullmatch(normalized_email):
        return "Escribe un correo electrónico válido.", None, None, None

    clean_name = full_name.strip()
    if not clean_name:
        return "Escribe tu nombre completo.", None, None, None

    if policy_error := security.password_policy_error(
        password, normalized_email, clean_name
    ):
        return policy_error, None, None, None

    if password != password_confirmation:
        return "Las contraseñas no coinciden.", None, None, None

    doc_type_norm = doc_type.strip().upper()
    clean_doc_number = doc_number.strip()
    clean_phone = phone.strip()
    clean_address = address.strip()
    if doc_type_norm not in DOC_TYPES or not all(
        [clean_doc_number, clean_phone, clean_address]
    ):
        return (
            "Completa todos los campos de datos personales (PII).",
            None,
            None,
            None,
        )
    if not isinstance(birth_date, date) or birth_date > date.today():
        return "Selecciona una fecha de nacimiento válida.", None, None, None

    clean_blood = blood_type.strip()
    clean_insurance = insurance_provider.strip()
    if not clean_blood or not clean_insurance:
        return (
            "Indica tu grupo sanguíneo y tu entidad de salud.",
            None,
            None,
            None,
        )
    if not consent_accepted:
        return (
            "Debes aceptar el consentimiento informado para el tratamiento de datos de salud (PHI).",
            None,
            None,
            None,
        )

    clean_holder = cardholder_name.strip()
    if not clean_holder:
        return "Escribe el nombre del titular de la tarjeta.", None, None, None

    try:
        security.validate_pan(pan)
        security.validate_exp_date(exp_date)
    except ValueError as exc:
        return str(exc), None, None, None

    card_brand = None if selected_brand == "Detectar automáticamente" else selected_brand
    pii = auth_service.PiiInput(
        full_name=clean_name,
        doc_type=doc_type_norm,
        doc_number=clean_doc_number,
        birth_date=birth_date,
        phone=clean_phone,
        address=clean_address,
    )
    phi = auth_service.PhiInput(
        blood_type=clean_blood,
        insurance_provider=clean_insurance,
        consent_accepted=True,
        allergies=allergies.strip() or None,
        medical_conditions=medical_conditions.strip() or None,
    )
    credit = auth_service.CreditInfoInput(
        cardholder_name=clean_holder,
        pan=pan,
        exp_date=exp_date,
        card_brand=card_brand,
    )
    return None, pii, phi, credit


_ADMIN_TABLE_COLUMNS = (
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
    "masked_pan",
    "password_status",
    "two_fa_status",
    "lock_status",
    "created_at",
)


def _render_user_profile_details(profile: dict) -> None:
    """Muestra únicamente el perfil propio del usuario (PII, PHI y tarjeta enmascarada)."""
    pii = profile["pii"] or {}
    phi = profile["phi"] or {}

    st.markdown("### Cuenta y seguridad")
    st.write(f"**Correo electrónico:** {profile['email']}")
    st.write(f"**Rol:** {profile['role']}")
    st.write("**Verificación en dos pasos:** Activo (TOTP)")

    if pii:
        st.markdown("### Datos personales (PII)")
        st.write(f"**Nombre completo:** {pii['full_name']}")
        st.write(f"**Documento:** {pii['doc_type']} {pii['doc_number']}")
        st.write(f"**Fecha de nacimiento:** {pii['birth_date']}")
        st.write(f"**Teléfono:** {pii['phone']}")
        st.write(f"**Dirección:** {pii['address']}")

    if phi:
        st.markdown("### Información de salud (PHI)")
        st.write(f"**Grupo sanguíneo:** {phi['blood_type']}")
        st.write(f"**Entidad de salud / Aseguradora:** {phi['insurance_provider']}")
        st.write(f"**Alergias:** {phi['allergies'] or 'Ninguna reportada'}")
        st.write(
            f"**Condiciones médicas:** {phi['medical_conditions'] or 'Ninguna reportada'}"
        )
        st.write("**Consentimiento informado:** Aceptado")

    st.markdown("### Datos crediticios")
    if profile["credit_cards"]:
        for card in profile["credit_cards"]:
            st.write(f"**{card['card_brand']}:** `{card['masked_pan']}`")
    else:
        st.write("Sin tarjetas registradas.")


def _render_admin_panel(user_session: dict) -> None:
    """Renderiza el panel global de usuarios y exportación CSV solo para admins."""
    st.markdown("### Listado global de usuarios")
    try:
        records = admin_service.list_users_for_admin(
            user_session["user_id"],
            source_ip=_client_source_ip(),
        )
    except PermissionError:
        st.error("Acceso denegado.")
        return
    except (config.ConfigError, psycopg.Error):
        st.error("No fue posible consultar el listado administrativo en este momento.")
        return

    table_rows = [
        {col: row.get(col) for col in _ADMIN_TABLE_COLUMNS} for row in records
    ]
    st.dataframe(table_rows, hide_index=True)

    def _deferred_csv_bytes() -> bytes:
        csv_bytes, _filename, _count = admin_service.export_users_csv_for_admin(
            user_session["user_id"],
            source_ip=_client_source_ip(),
        )
        return csv_bytes

    st.download_button(
        "Exportar usuarios a CSV",
        data=_deferred_csv_bytes,
        file_name=admin_service.build_csv_filename(),
        mime="text/csv",
        key="admin_csv_download",
    )


def _render_authenticated_portal(user_session: dict) -> None:
    """Muestra el portal de usuario o administrador según validación RBAC en BD."""
    try:
        profile = auth_service.get_user_profile(user_session["user_id"])
    except (config.ConfigError, psycopg.Error):
        st.error("No fue posible cargar tu perfil en este momento.")
        if st.button("Cerrar sesión", key="logout_btn"):
            st.session_state.clear()
            st.rerun()
        return

    if profile is None:
        st.session_state.clear()
        st.warning("La sesión ya no es válida. Inicia sesión nuevamente.")
        st.rerun()

    pii = profile["pii"] or {}
    display_name = pii.get("full_name") or user_session.get("name") or profile["email"]

    st.subheader(f"Hola, {display_name}")
    st.success("Sesión iniciada correctamente")

    try:
        is_admin = admin_service.is_verified_admin(user_session["user_id"])
    except (config.ConfigError, psycopg.Error):
        is_admin = False

    if is_admin:
        profile_tab, admin_tab = st.tabs(["Mi perfil", "Panel de administración"])
        with profile_tab:
            _render_user_profile_details(profile)
        with admin_tab:
            _render_admin_panel(user_session)
    else:
        _render_user_profile_details(profile)

    if st.button("Cerrar sesión", key="logout_btn"):
        st.session_state.clear()
        st.rerun()


def _render_pending_registration(pending: dict) -> None:
    """Muestra el QR TOTP y exige confirmar el primer OTP antes de crear la cuenta."""
    st.subheader("Configura tu autenticación en dos pasos (2FA)")
    st.write(
        "Escanea el código QR con Google Authenticator, Authy o Microsoft Authenticator "
        "y confirma la activación con el código de 6 dígitos."
    )
    qr_image = qrcode.make(
        auth_service.provisioning_uri(pending["email"], pending["totp_secret"])
    )
    qr_buffer = io.BytesIO()
    qr_image.save(qr_buffer, format="PNG")
    st.image(qr_buffer.getvalue(), caption="QR de configuración TOTP", width=240)

    with st.form("confirmar-otp"):
        otp_code = st.text_input(
            "Código de 6 dígitos", max_chars=6, key="confirm_otp_code"
        )
        confirm_setup = st.form_submit_button("Activar cuenta y continuar")

    if confirm_setup:
        try:
            user_id = auth_service.register_user(
                email=pending["email"],
                password_hash=pending["password_hash"],
                totp_secret=pending["totp_secret"],
                otp_code=otp_code,
                pii=pending["pii"],
                phi=pending["phi"],
                credit=pending["credit"],
                source_ip=_client_source_ip(),
            )
        except (auth_service.DuplicateAccountError, auth_service.RegistrationError) as exc:
            st.error(str(exc))
        except config.ConfigError:
            st.error("El servicio de autenticación no está configurado correctamente.")
        except psycopg.Error:
            st.error(
                "No fue posible completar el registro en este momento. Intenta de nuevo."
            )
        else:
            st.session_state["authenticated_user"] = {
                "user_id": str(user_id),
                "name": pending["pii"].full_name,
                "email": pending["email"],
                "role": "user",
            }
            st.session_state["last_activity_ts"] = time.time()
            del st.session_state["pending_registration"]
            st.rerun()

    if st.button("Cancelar registro", key="cancel_registration_btn"):
        del st.session_state["pending_registration"]
        st.rerun()


def _render_auth_tabs() -> None:
    """Renderiza las pestañas de registro completo (RF-01) y acceso 2FA (RF-04)."""
    register_tab, login_tab = st.tabs(["Crear cuenta", "Iniciar sesión"])

    with register_tab:
        with st.form("registro"):
            st.markdown("#### 1. Credenciales de acceso")
            email = st.text_input("Correo electrónico", key="reg_email")
            password = st.text_input("Contraseña", type="password", key="reg_password")
            password_confirmation = st.text_input(
                "Confirmar contraseña",
                type="password",
                key="reg_password_confirm",
            )
            st.caption(
                "Mínimo 12 caracteres (máximo 128), con mayúscula, minúscula, dígito "
                "y carácter especial. No incluyas tu nombre, correo ni secuencias triviales."
            )

            st.markdown("#### 2. Datos personales (PII)")
            full_name = st.text_input(
                "Nombre completo", max_chars=150, key="reg_full_name"
            )
            doc_type = st.selectbox("Tipo de documento", DOC_TYPES, key="reg_doc_type")
            doc_number = st.text_input(
                "Número de documento", max_chars=50, key="reg_doc_number"
            )
            birth_date = st.date_input(
                "Fecha de nacimiento",
                value=date(2000, 1, 1),
                min_value=date(1900, 1, 1),
                max_value=date.today(),
                key="reg_birth_date",
            )
            phone = st.text_input(
                "Teléfono de contacto", max_chars=30, key="reg_phone"
            )
            address = st.text_input(
                "Dirección de residencia", max_chars=255, key="reg_address"
            )

            st.markdown("#### 3. Datos de salud (PHI)")
            blood_type = st.selectbox(
                "Grupo sanguíneo y factor RH", BLOOD_TYPES, key="reg_blood_type"
            )
            insurance_provider = st.text_input(
                "Entidad de salud / Aseguradora", max_chars=120, key="reg_insurance"
            )
            allergies = st.text_input(
                "Alergias conocidas (opcional)", max_chars=255, key="reg_allergies"
            )
            medical_conditions = st.text_input(
                "Condiciones médicas crónicas relevantes (opcional)",
                max_chars=255,
                key="reg_conditions",
            )
            consent_accepted = st.checkbox(
                "Autorizo de forma explícita e informada el tratamiento cifrado de mis datos sensibles de salud (PHI).",
                key="reg_consent",
            )

            st.markdown("#### 4. Datos crediticios")
            cardholder_name = st.text_input(
                "Nombre del titular de la tarjeta",
                max_chars=120,
                key="reg_cardholder",
            )
            pan = st.text_input(
                "Número de tarjeta (PAN)",
                max_chars=23,
                placeholder="XXXX XXXX XXXX XXXX",
                key="reg_pan",
            )
            exp_date = st.text_input(
                "Fecha de expiración (MM/AA)",
                max_chars=5,
                placeholder="MM/AA",
                key="reg_exp_date",
            )
            selected_brand = st.selectbox(
                "Franquicia", CARD_BRAND_OPTIONS, key="reg_card_brand"
            )
            st.caption(
                "Por seguridad (PCI-DSS), nunca solicitamos ni almacenamos el código de seguridad de la tarjeta."
            )

            register = st.form_submit_button("Continuar con la configuración 2FA")

        if register:
            err, pii, phi, credit = _validate_registration_form(
                email=email,
                password=password,
                password_confirmation=password_confirmation,
                full_name=full_name,
                doc_type=doc_type,
                doc_number=doc_number,
                birth_date=birth_date,
                phone=phone,
                address=address,
                blood_type=blood_type,
                insurance_provider=insurance_provider,
                allergies=allergies,
                medical_conditions=medical_conditions,
                consent_accepted=consent_accepted,
                cardholder_name=cardholder_name,
                pan=pan,
                exp_date=exp_date,
                selected_brand=selected_brand,
            )
            if err is not None:
                st.error(err)
            else:
                st.session_state["pending_registration"] = {
                    "email": email.strip().lower(),
                    "password_hash": auth_service.hash_password(
                        password,
                        email=email.strip().lower(),
                        name=pii.full_name,
                    ),
                    "totp_secret": auth_service.create_totp_secret(),
                    "pii": pii,
                    "phi": phi,
                    "credit": credit,
                }
                st.rerun()

    with login_tab:
        with st.form("inicio-sesion"):
            login_email = st.text_input("Correo electrónico", key="login_email")
            login_password = st.text_input(
                "Contraseña", type="password", key="login_password"
            )
            login_otp = st.text_input(
                "Código OTP de 6 dígitos", max_chars=6, key="login_otp"
            )
            login = st.form_submit_button("Iniciar sesión")

        if login:
            if form_err := auth_service.validate_login_inputs(
                login_email, login_password, login_otp
            ):
                st.error(form_err)
            else:
                try:
                    user_profile = auth_service.authenticate(
                        login_email,
                        login_password,
                        login_otp,
                        source_ip=_client_source_ip(),
                    )
                except (config.ConfigError, psycopg.Error):
                    st.error(
                        "No fue posible validar el acceso en este momento. Intenta de nuevo."
                    )
                else:
                    if user_profile is None:
                        st.error(auth_service.GENERIC_LOGIN_ERROR)
                    else:
                        st.session_state["authenticated_user"] = user_profile
                        st.session_state["last_activity_ts"] = time.time()
                        st.rerun()


st.set_page_config(page_title="Acceso seguro", page_icon="🔐", layout="centered")
st.title("Acceso seguro")

if "authenticated_user" in st.session_state:
    user_session = st.session_state["authenticated_user"]
    if not isinstance(user_session, dict) or not user_session.get("user_id"):
        st.session_state.clear()
        st.info("La sesión anterior caducó. Inicia sesión nuevamente.")
    else:
        last_activity = st.session_state.get("last_activity_ts")
        if (
            not isinstance(last_activity, (int, float))
            or time.time() - last_activity > SESSION_TIMEOUT_SECONDS
        ):
            st.session_state.clear()
            st.warning("Tu sesión expiró por inactividad. Inicia sesión nuevamente.")
        else:
            st.session_state["last_activity_ts"] = time.time()
            _render_authenticated_portal(user_session)
            st.stop()

pending_registration = st.session_state.get("pending_registration")
if pending_registration:
    _render_pending_registration(pending_registration)
else:
    _render_auth_tabs()

st.markdown("---")
st.caption("© 2025 Nuu | Todos los derechos reservados")
