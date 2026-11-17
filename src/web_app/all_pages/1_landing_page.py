import streamlit as st

st.set_page_config(
    page_title="App Ciber | Inicio",
    page_icon="🛡️",
    layout="centered",
)

INTEGRANTES = [
    "Daniel Vallejo Vecil",
    "Juliana Muñoz Gonzalez",
    "Lizeth Otalora",
    "Santiago Toro",
]

# ==================== ENCABEZADO ====================
st.title("🛡️ App Ciber")
st.subheader("Registro y autenticación segura con doble factor")
st.write(
    "Proyecto final de ciberseguridad: una aplicación web desplegada en AWS que protege "
    "datos personales (PII), de salud (PHI) y de tarjetas (PCI) con cifrado, "
    "contraseñas robustas y autenticación multifactor."
)

col_login, col_admin = st.columns(2)
with col_login:
    if st.button("🔐 Registrarse / Iniciar sesión", type="primary", use_container_width=True):
        st.switch_page("all_pages/2_auth_page.py")
with col_admin:
    if st.button("📊 Panel de administración", use_container_width=True):
        st.switch_page("all_pages/6_admin_page.py")

st.markdown("---")

# ==================== CONTROLES DE SEGURIDAD ====================
st.subheader("Cómo protegemos tu información")
c1, c2 = st.columns(2)
with c1:
    with st.container(border=True):
        st.markdown("**🔑 Contraseñas con Argon2id**")
        st.caption("Mínimo 12 caracteres con mayúsculas, minúsculas, números y símbolos. Nunca se guardan en texto plano.")
    with st.container(border=True):
        st.markdown("**📱 Doble factor (TOTP)**")
        st.caption("Cada ingreso pide un código de 6 dígitos de tu app autenticadora; un código no se puede reutilizar.")
with c2:
    with st.container(border=True):
        st.markdown("**🔒 Datos cifrados con Fernet**")
        st.caption("Nombre, documento, teléfono, datos médicos y tarjeta se guardan cifrados en la base de datos.")
    with st.container(border=True):
        st.markdown("**⏱️ Bloqueo ante ataques**")
        st.caption("Tras 5 intentos fallidos la cuenta se bloquea 5 minutos para frenar ataques de fuerza bruta.")

st.markdown("---")

# ==================== EQUIPO ====================
st.subheader("Integrantes del equipo")
cols = st.columns(len(INTEGRANTES))
for col, nombre in zip(cols, INTEGRANTES):
    iniciales = "".join(p[0] for p in nombre.split()[:2]).upper()
    with col:
        with st.container(border=True):
            st.markdown(f"<div style='text-align:center;font-size:1.6rem;font-weight:600'>{iniciales}</div>", unsafe_allow_html=True)
            st.markdown(f"<div style='text-align:center'>{nombre}</div>", unsafe_allow_html=True)

# ==================== PIE ====================
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: gray;'>© 2026 App Ciber · Proyecto final de ciberseguridad · "
    "Infraestructura en AWS (us-east-2)</p>",
    unsafe_allow_html=True,
)
