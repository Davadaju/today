from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
from web_app.security import (
    authenticate_admin,
    export_users_to_csv,
    get_users_dashboard_stats,
    verify_admin_stepup_otp,
)

TZ = ZoneInfo("America/Bogota")

st.set_page_config(page_title="Panel Administrador", page_icon="🛡️", layout="wide")
st.title("🛡️ Panel de Administración")
st.caption("Acceso restringido contra tabla aislada de administradores con MFA.")

if "admin_user" not in st.session_state:
    st.session_state.admin_user = None
if "decrypted_csv_ready" not in st.session_state:
    st.session_state.decrypted_csv_ready = None


def _fmt(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return dt.astimezone(TZ).strftime(fmt) if dt else "—"


def render_dashboard() -> None:
    top_left, top_right = st.columns([4, 1])
    with top_right:
        if st.button("🔄 Actualizar", use_container_width=True):
            st.rerun()

    ok, msg, s = get_users_dashboard_stats()
    if not ok:
        st.error(msg)
        return

    with top_left:
        st.caption(f"Datos agregados de la tabla `usuarios` · actualizado {datetime.now(TZ):%Y-%m-%d %H:%M} (hora Colombia). "
                   "El dashboard no descifra datos PII, PHI ni PCI.")

    if s["total"] == 0:
        st.info("Todavía no hay usuarios registrados.")
        return

    # ---------- Indicadores ----------
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Usuarios registrados", s["total"], delta=f"+{s['nuevos_7d']} en 7 días", delta_color="off")
    c2.metric("Nuevos en 24 h", s["nuevos_24h"])
    c3.metric("Activos últimos 7 días", s["activos_7d"], help="Usuarios con un ingreso exitoso con 2FA en los últimos 7 días.")
    c4.metric("Nunca han ingresado", s["total"] - s["con_ingreso"], help="Registrados que aún no completan un ingreso con OTP.")

    c5, c6, c7, _ = st.columns(4)
    c5.metric("Cuentas bloqueadas ahora", s["bloqueados"], help="Bloqueo temporal tras 5 intentos fallidos.")
    c6.metric("Con intentos fallidos", s["con_fallos"])
    tasa = round(100 * s["con_ingreso"] / s["total"]) if s["total"] else 0
    c7.metric("Adopción de 2FA", f"{tasa} %", help="Porcentaje de usuarios que ya ingresaron al menos una vez con OTP.")

    st.markdown("---")

    # ---------- Gráficas ----------
    g1, g2 = st.columns([3, 2])
    with g1:
        st.subheader("Registros por día (últimos 30 días)")
        df_dias = pd.DataFrame(s["registros_por_dia"], columns=["Día", "Registros"])
        st.bar_chart(df_dias, x="Día", y="Registros", height=280)
    with g2:
        st.subheader("Intentos fallidos por usuario")
        df_int = pd.DataFrame(s["intentos"], columns=["Intentos", "Usuarios"])
        st.bar_chart(df_int, x="Intentos", y="Usuarios", height=280)

    g3, g4 = st.columns([2, 3])
    with g3:
        st.subheader("Dominios de correo")
        df_dom = pd.DataFrame(s["dominios"], columns=["Dominio", "Usuarios"])
        st.bar_chart(df_dom, x="Dominio", y="Usuarios", horizontal=True, height=280)
    with g4:
        st.subheader("Cuentas con actividad sospechosa")
        if s["en_riesgo"]:
            now = datetime.now(TZ)
            df_riesgo = pd.DataFrame(
                [
                    (
                        usuario,
                        intentos,
                        f"Bloqueada hasta {_fmt(hasta, '%H:%M')}" if hasta and hasta > now else "Activa",
                    )
                    for usuario, intentos, hasta in s["en_riesgo"]
                ],
                columns=["Usuario", "Intentos fallidos", "Estado"],
            )
            st.dataframe(df_riesgo, hide_index=True, use_container_width=True)
        else:
            st.success("Ningún usuario tiene intentos fallidos ni bloqueos.")

    st.subheader("Registros recientes")
    df_rec = pd.DataFrame(
        [(u, _fmt(creado), _fmt(ultimo)) for u, creado, ultimo in s["recientes"]],
        columns=["Usuario", "Fecha de registro", "Último ingreso con 2FA"],
    )
    st.dataframe(df_rec, hide_index=True, use_container_width=True)


def render_exports() -> None:
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


if not st.session_state.admin_user:
    _, center, _ = st.columns([1, 2, 1])
    with center:
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
    head, logout = st.columns([4, 1])
    head.success(f"Sesión administrativa activa: **{st.session_state.admin_user}**")
    if logout.button("Cerrar Sesión de Administrador", use_container_width=True):
        st.session_state.admin_user = None
        st.session_state.decrypted_csv_ready = None
        st.rerun()

    tab_dash, tab_export = st.tabs(["📊 Dashboard de usuarios", "📥 Exportar datos"])
    with tab_dash:
        render_dashboard()
    with tab_export:
        render_exports()