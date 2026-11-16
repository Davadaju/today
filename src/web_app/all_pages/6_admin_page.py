from datetime import datetime
import streamlit as st
from web_app.security import export_users_to_csv, verify_admin_password

st.set_page_config(page_title="Panel Administrador • Exportar CSV", page_icon="🛡️", layout="centered")
st.title("🛡️ Panel de Administración")
st.caption("Acceso restringido para auditoría y exportación de usuarios registrados.")

if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

if not st.session_state.is_admin:
    with st.form("admin_login_form"):
        admin_pwd = st.text_input("Contraseña de Administrador", type="password")
        submit_admin = st.form_submit_button("Ingresar al Panel")

    if submit_admin:
        if verify_admin_password(admin_pwd):
            st.session_state.is_admin = True
            st.success("Acceso administrativo concedido.")
            st.rerun()
        else:
            st.error("Contraseña de administrador inválida.")
else:
    st.success("Sesión administrativa activa.")

    decrypt_option = st.checkbox(
        "Descifrar datos PII y PHI en el CSV (requiere autorización de auditoría)",
        value=True,
    )

    ok, msg, csv_data = export_users_to_csv(decrypt_sensitive=decrypt_option)

    if ok and csv_data:
        filename = f"usuarios_registrados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        st.download_button(
            label="📥 Descargar Usuarios en CSV",
            data=csv_data.encode("utf-8-sig"),
            file_name=filename,
            mime="text/csv",
            type="primary",
        )
    else:
        st.error(msg)

    st.markdown("---")
    if st.button("Cerrar Sesión de Administrador"):
        st.session_state.is_admin = False
        st.rerun()
