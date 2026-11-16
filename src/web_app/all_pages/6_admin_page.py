from datetime import datetime
import streamlit as st
from web_app.security import (
    authenticate_admin,
    export_users_to_csv,
    verify_admin_stepup_otp,
)

st.set_page_config(page_title="Panel Administrador • Exportar CSV", page_icon="🛡️", layout="centered")
st.title("🛡️ Panel de Administración")
st.caption("Acceso restringido contra tabla aislada de administradores con MFA.")

if "admin_user" not in st.session_state:
    st.session_state.admin_user = None
if "decrypted_csv_ready" not in st.session_state:
    st.session_state.decrypted_csv_ready = None

if not st.session_state.admin_user:
    with st.form("admin_login_form"):
        admin_id = st.text_input("Usuario o Correo de Administrador")
        admin_pwd = st.text_input("Contraseña", type="password")
        admin_otp = st.text_input("Código OTP (6 dígitos)", max_chars=6, placeholder="123456")
        submit_admin = st.form_submit_button("Ingresar al Panel")

    if submit_admin:
        ok, msg, admin_username = authenticate_admin(admin_id, admin_pwd, admin_otp)
        if ok:
            st.session_state.admin_user = admin_username
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)
else:
    st.success(f"Sesión administrativa activa: **{st.session_state.admin_user}**")

    # ==================== OPCIÓN 1: CSV CIFRADO / ENMASCARADO ====================
    st.subheader("1. Reporte Estándar (Datos Cifrados / Enmascarados)")
    st.write("Descarga inmediata con valores PII/PHI cifrados en hexadecimal.")

    ok_enc, msg_enc, csv_encrypted = export_users_to_csv(decrypt_sensitive=False)
    if ok_enc and csv_encrypted:
        file_enc = f"usuarios_cifrados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        st.download_button(
            label="📥 Descargar CSV Cifrado (Estándar)",
            data=csv_encrypted.encode("utf-8-sig"),
            file_name=file_enc,
            mime="text/csv",
        )
    else:
        st.error(msg_enc)

    st.markdown("---")

    # ==================== OPCIÓN 2: CSV DESCIFRADO (EXIGE NUEVO OTP) ====================
    st.subheader("2. Reporte de Auditoría (Datos PII y PHI Descifrados)")
    st.warning("⚠️ Por política de seguridad, exportar datos personales y médicos en texto claro requiere validar un nuevo código OTP.")

    with st.form("stepup_otp_form"):
        stepup_otp = st.text_input("Nuevo código OTP de 6 dígitos (espere el cambio de 30s)", max_chars=6, placeholder="123456")
        verify_stepup = st.form_submit_button("Validar Nuevo OTP y Preparar CSV Descifrado")

    if verify_stepup:
        ok_otp, msg_otp = verify_admin_stepup_otp(st.session_state.admin_user, stepup_otp)
        if ok_otp:
            ok_dec, msg_dec, csv_decrypted = export_users_to_csv(decrypt_sensitive=True)
            if ok_dec and csv_decrypted:
                st.session_state.decrypted_csv_ready = csv_decrypted
                st.success("Nuevo OTP validado. El archivo CSV descifrado está listo.")
            else:
                st.error(msg_dec)
        else:
            st.session_state.decrypted_csv_ready = None
            st.error(msg_otp)

    if st.session_state.decrypted_csv_ready:
        file_dec = f"usuarios_auditoria_descifrado_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        st.download_button(
            label="🔓 Descargar CSV Descifrado (PII / PHI)",
            data=st.session_state.decrypted_csv_ready.encode("utf-8-sig"),
            file_name=file_dec,
            mime="text/csv",
            type="primary",
        )

    st.markdown("---")
    if st.button("Cerrar Sesión de Administrador"):
        st.session_state.admin_user = None
        st.session_state.decrypted_csv_ready = None
        st.rerun()
