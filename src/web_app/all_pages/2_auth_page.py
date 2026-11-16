import io
import qrcode
import streamlit as st
from web_app.security import authenticate_user, register_user

st.set_page_config(page_title="Autenticación Segura • 2FA", page_icon="🔐", layout="centered")
st.title("🔐 Sistema de Registro y Autenticación MFA")

tab_login, tab_register, tab_policy = st.tabs([
    "Iniciar Sesión (3 Variables)",
    "Registro de Usuario (PII / PHI / PCI)",
    "Política de Seguridad",
])

# ==================== PESTAÑA 1: LOGIN (3 VARIABLES) ====================
with tab_login:
    st.subheader("Acceso con Doble Factor (2FA)")
    st.caption("Ingrese su usuario o correo, su contraseña y el código temporal de 6 dígitos.")

    if "authenticated_user" in st.session_state and st.session_state.authenticated_user:
        user = st.session_state.authenticated_user
        st.success(f"Sesión activa como **{user['full_name']}** (`{user['username']}`)")
        st.json({
            "Correo": user["email"],
            "Tipo de Sangre (PHI descifrado)": user["blood_type"],
            "Tarjeta registrada (PCI)": f"**** **** **** {user['card_last4']}",
        })
        if st.button("Cerrar Sesión"):
            st.session_state.authenticated_user = None
            st.rerun()
    else:
        with st.form("login_form"):
            identifier = st.text_input("Usuario o Correo electrónico")
            password = st.text_input("Contraseña", type="password")
            otp_code = st.text_input("Código OTP (6 dígitos)", max_chars=6, placeholder="123456")
            submitted_login = st.form_submit_button("Ingresar")

        if submitted_login:
            ok, message, user_data = authenticate_user(identifier, password, otp_code)
            if ok:
                st.session_state.authenticated_user = user_data
                st.success(message)
                st.rerun()
            else:
                st.error(message)

# ==================== PESTAÑA 2: REGISTRO DE USUARIOS ====================
with tab_register:
    st.subheader("Crear Nueva Cuenta")
    st.info(
        "Política de contraseña: mínimo 12 caracteres, incluir mayúsculas, minúsculas, "
        "números y símbolos (!@#$%)."
    )

    with st.form("register_form"):
        st.markdown("#### 1. Credenciales de Acceso")
        col1, col2 = st.columns(2)
        with col1:
            reg_username = st.text_input("Nombre de usuario *")
            reg_password = st.text_input("Contraseña *", type="password")
        with col2:
            reg_email = st.text_input("Correo electrónico *")
            reg_password_confirm = st.text_input("Confirmar contraseña *", type="password")

        st.markdown("#### 2. Información Personal (PII)")
        col3, col4 = st.columns(2)
        with col3:
            reg_fullname = st.text_input("Nombre completo *")
            reg_phone = st.text_input("Teléfono celular *")
        with col4:
            reg_doc_id = st.text_input("Número de documento / Cédula *")

        st.markdown("#### 3. Información Médica (PHI)")
        col5, col6 = st.columns(2)
        with col5:
            reg_blood = st.selectbox("Grupo sanguíneo y RH *", ["O+", "O-", "A+", "A-", "B+", "B-", "AB+", "AB-"])
        with col6:
            reg_conditions = st.text_input("Alergias o condiciones médicas *", value="Ninguna")

        st.markdown("#### 4. Datos Crediticios (PCI)")
        col7, col8 = st.columns(2)
        with col7:
            reg_card = st.text_input("Número de tarjeta de crédito *", max_chars=19, placeholder="4532015112830366")
        with col8:
            reg_expiry = st.text_input("Fecha de expiración (MM/AA) *", max_chars=5, placeholder="08/29")

        submitted_reg = st.form_submit_button("Registrar y Generar 2FA")

    if submitted_reg:
        if not all([reg_username, reg_email, reg_password, reg_fullname, reg_doc_id, reg_phone, reg_card, reg_expiry]):
            st.warning("Por favor complete todos los campos obligatorios (*).")
        elif reg_password != reg_password_confirm:
            st.error("Las contraseñas no coinciden.")
        else:
            ok, msg, uri = register_user(
                username=reg_username,
                email=reg_email,
                password=reg_password,
                full_name=reg_fullname,
                document_id=reg_doc_id,
                phone=reg_phone,
                blood_type=reg_blood,
                medical_conditions=reg_conditions,
                card_number=reg_card,
                card_expiry=reg_expiry,
            )
            if ok and uri:
                st.success(msg)
                st.warning("⚠️ Escanee este código QR ahora con Google Authenticator, Authy o Microsoft Authenticator. No volverá a mostrarse.")
                qr = qrcode.QRCode(
                    version=1,
                    box_size=8,
                    border=4,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                )
                qr.add_data(uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                st.image(buf.getvalue(), caption="Escanea este QR en tu app autenticadora")
            else:
                st.error(msg)

# ==================== PESTAÑA 3: DOCUMENTACIÓN DE POLÍTICAS ====================
with tab_policy:
    st.subheader("Arquitectura de Protección de Datos y Secretos")
    st.markdown("""
    * **Almacenamiento de Contraseñas:** Hashing lento resistente a GPU mediante **Argon2id** con sal aleatoria por usuario.
    * **Clasificación y Cifrado en Reposo (Fernet / AES-128-CBC + HMAC):**
      * **PII** (Nombre, documento, teléfono): Cifrado simétrico en base de datos.
      * **PHI** (Tipo de sangre, condiciones médicas): Cifrado simétrico en base de datos.
      * **PCI** (Número de tarjeta y expiración): Cifrado simétrico; solo se conservan los últimos 4 dígitos en claro para enmascaramiento visual. Nunca se almacena el CVV.
      * **Secreto TOTP (`pyotp`):** Almacenado cifrado en columna `BYTEA`; la llave maestra reside exclusivamente en variables de entorno (`.env`).
    * **Mitigación de Ataques en 2FA (`pyotp`):**
      * **Retry Attacks:** Se almacena el contador temporal (`ultimo_paso_otp`) del último código validado para impedir su reutilización dentro de la misma ventana de 30 segundos.
      * **Rate Limiting:** Bloqueo automático de 5 minutos tras 5 intentos fallidos consecutivos.
      * **Prevención de Enumeración:** Mensajes de error unificados ante fallos en cualquiera de las 3 variables (usuario, contraseña u OTP).
    """)

st.markdown("---")
st.markdown(
    "<p style='text-align: center;'>© 2026 Taller Ciberseguridad • Implementación MFA con PyOTP</p>",
    unsafe_allow_html=True,
)

