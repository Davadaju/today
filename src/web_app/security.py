import csv
import io
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import psycopg
import pyotp
from psycopg import sql
from pyotp.exceptions import OTPVerificationError  # requiere pyotp >= 2.11.0
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ph = PasswordHasher()  # Usa Argon2id por defecto
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise ValueError("Falta la variable de entorno FERNET_KEY en el archivo .env")
cipher = Fernet(FERNET_KEY.encode())

# Parámetros de seguridad
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
TOTP_INTERVAL = 30

# Hash señuelo: se verifica cuando el usuario no existe para que el tiempo de
# respuesta sea igual y no se pueda saber qué usuarios están registrados.
_DUMMY_HASH = ph.hash("usuario-inexistente-señuelo")

_TABLAS_PERMITIDAS = {"usuarios", "administradores"}


def get_db_connection():
    required_vars = ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Faltan variables de entorno de base de datos: {', '.join(missing)}")

    return psycopg.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )


def validate_password_policy(password: str) -> tuple[bool, str]:
    """
    Política de contraseñas:
    - Mínimo 12 caracteres
    - Al menos una mayúscula, una minúscula, un dígito y un carácter especial
    """
    if len(password) < 12:
        return False, "La contraseña debe tener al menos 12 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe incluir al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "La contraseña debe incluir al menos una letra minúscula."
    if not re.search(r"\d", password):
        return False, "La contraseña debe incluir al menos un número."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]", password):
        return False, "La contraseña debe incluir al menos un carácter especial."
    return True, "Contraseña válida."


def encrypt_data(plain_text: str) -> bytes:
    return cipher.encrypt(plain_text.encode("utf-8"))


def decrypt_data(cipher_bytes: bytes) -> str:
    return cipher.decrypt(bytes(cipher_bytes)).decode("utf-8")


def _register_failure(cur, conn, tabla: str, row_id: int, now: datetime) -> None:
    """
    Suma un intento fallido de forma atómica en PostgreSQL (sin leer-modificar-escribir
    en Python) y bloquea la cuenta al llegar al máximo. Si un bloqueo anterior ya
    venció, el contador vuelve a empezar en 1.
    """
    if tabla not in _TABLAS_PERMITIDAS:
        raise ValueError("Tabla no permitida")

    cur.execute(
        sql.SQL(
            """
            UPDATE {tabla}
            SET intentos_fallidos = CASE
                    WHEN bloqueado_hasta IS NOT NULL AND bloqueado_hasta <= %s THEN 1
                    ELSE intentos_fallidos + 1
                END
            WHERE id = %s
            RETURNING intentos_fallidos
            """
        ).format(tabla=sql.Identifier(tabla)),
        (now, row_id),
    )
    attempts = cur.fetchone()[0]
    new_lock = now + timedelta(minutes=LOCKOUT_MINUTES) if attempts >= MAX_FAILED_ATTEMPTS else None
    cur.execute(
        sql.SQL("UPDATE {tabla} SET bloqueado_hasta = %s WHERE id = %s").format(
            tabla=sql.Identifier(tabla)
        ),
        (new_lock, row_id),
    )
    conn.commit()


def _verify_totp_step(totp_secret_enc: bytes, otp_code: str) -> int | None:
    """Devuelve el paso (timecode) que coincidió o None si el código no es válido."""
    totp = pyotp.TOTP(decrypt_data(totp_secret_enc), interval=TOTP_INTERVAL)
    try:
        return totp.verify_and_get_timecode(otp_code, valid_window=1)
    except OTPVerificationError:
        return None


def register_user(
    username: str,
    email: str,
    password: str,
    full_name: str,
    document_id: str,
    phone: str,
    blood_type: str,
    medical_conditions: str,
    card_number: str,
    card_expiry: str,
) -> tuple[bool, str, str | None]:
    """Registra un usuario cifrando PII/PHI/PCI y generando su secreto TOTP."""
    is_valid, msg = validate_password_policy(password)
    if not is_valid:
        return False, msg, None

    clean_card = re.sub(r"\D", "", card_number)
    if len(clean_card) < 13 or len(clean_card) > 19:
        return False, "El número de tarjeta debe tener entre 13 y 19 dígitos.", None

    password_hash = ph.hash(password)
    totp_secret = pyotp.random_base32()

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO usuarios (
                        usuario, correo, contrasena_hash,
                        nombre_completo_cifrado, documento_identidad_cifrado, telefono_cifrado,
                        tipo_sangre_cifrado, condiciones_medicas_cifrado,
                        numero_tarjeta_cifrado, expiracion_tarjeta_cifrado, ultimos_4_tarjeta,
                        secreto_totp_cifrado
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        username.strip().lower(),
                        email.strip().lower(),
                        password_hash,
                        encrypt_data(full_name.strip()),
                        encrypt_data(document_id.strip()),
                        encrypt_data(phone.strip()),
                        encrypt_data(blood_type.strip()),
                        encrypt_data(medical_conditions.strip()),
                        encrypt_data(clean_card),
                        encrypt_data(card_expiry.strip()),
                        clean_card[-4:],
                        encrypt_data(totp_secret),
                    ),
                )
            conn.commit()

        provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=email.strip().lower(),
            issuer_name="TallerCiber-App",
        )
        return True, "Usuario registrado exitosamente.", provisioning_uri

    except psycopg.errors.UniqueViolation:
        return False, "El usuario o correo ya se encuentra registrado.", None
    except Exception:
        logger.exception("Error interno durante el registro de usuario")
        return False, "No fue posible procesar el registro en este momento. Intente más tarde.", None


def authenticate_user(identifier: str, password: str, otp_code: str) -> tuple[bool, str, dict | None]:
    """
    Evalúa las 3 variables (Usuario/Correo, Contraseña, OTP) aplicando:
    - Rate Limiting (bloqueo tras intentos fallidos)
    - Verificación nativa verify_and_get_timecode() de PyOTP
    - Actualización atómica en PostgreSQL para evitar Replay Attacks y Race Conditions
    """
    clean_id = identifier.strip().lower()
    clean_otp = otp_code.strip()

    if not clean_id or not password or not clean_otp:
        return False, "Todos los campos (usuario, contraseña y OTP) son obligatorios.", None

    generic_error = "Credenciales o código OTP inválidos."

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, usuario, correo, contrasena_hash, secreto_totp_cifrado,
                           bloqueado_hasta,
                           nombre_completo_cifrado, tipo_sangre_cifrado, ultimos_4_tarjeta
                    FROM usuarios
                    WHERE usuario = %s OR correo = %s
                    """,
                    (clean_id, clean_id),
                )
                row = cur.fetchone()

                if not row:
                    try:
                        ph.verify(_DUMMY_HASH, password)
                    except VerifyMismatchError:
                        pass
                    return False, generic_error, None

                (
                    user_id, username, email, password_hash, totp_secret_enc,
                    locked_until,
                    full_name_enc, blood_type_enc, card_last4
                ) = row

                now = datetime.now(timezone.utc)

                if locked_until and locked_until > now:
                    remaining = int((locked_until - now).total_seconds() // 60) + 1
                    return False, f"Cuenta bloqueada temporalmente por seguridad. Intente en {remaining} min.", None

                try:
                    ph.verify(password_hash, password)
                except VerifyMismatchError:
                    _register_failure(cur, conn, "usuarios", user_id, now)
                    return False, generic_error, None

                if not re.fullmatch(r"\d{6}", clean_otp):
                    _register_failure(cur, conn, "usuarios", user_id, now)
                    return False, generic_error, None

                matched_step = _verify_totp_step(totp_secret_enc, clean_otp)
                if matched_step is None:
                    _register_failure(cur, conn, "usuarios", user_id, now)
                    return False, generic_error, None

                # Actualización atómica recomendada por PyOTP contra Replay Attacks
                cur.execute(
                    """
                    UPDATE usuarios
                    SET intentos_fallidos = 0, bloqueado_hasta = NULL, ultimo_paso_otp = %s
                    WHERE id = %s AND (ultimo_paso_otp IS NULL OR ultimo_paso_otp < %s)
                    """,
                    (matched_step, user_id, matched_step),
                )
                if cur.rowcount != 1:
                    _register_failure(cur, conn, "usuarios", user_id, now)
                    return False, "Este código OTP ya fue utilizado. Espere el siguiente código de 30 segundos.", None

                conn.commit()

                user_profile = {
                    "username": username,
                    "email": email,
                    "full_name": decrypt_data(full_name_enc),
                    "blood_type": decrypt_data(blood_type_enc),
                    "card_last4": card_last4,
                }
                return True, "Autenticación multifactor exitosa.", user_profile

    except Exception:
        logger.exception("Error interno durante la autenticación de usuario")
        return False, "Servicio de autenticación temporalmente no disponible. Intente más tarde.", None


def export_users_to_csv(decrypt_sensitive: bool = False) -> tuple[bool, str, str | None]:
    """Genera un string en formato CSV con los usuarios registrados en la base de datos."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, usuario, correo,
                           nombre_completo_cifrado, documento_identidad_cifrado, telefono_cifrado,
                           tipo_sangre_cifrado, condiciones_medicas_cifrado,
                           ultimos_4_tarjeta, intentos_fallidos, bloqueado_hasta, fecha_creacion
                    FROM usuarios
                    ORDER BY id ASC
                    """
                )
                rows = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)

        if decrypt_sensitive:
            writer.writerow([
                "ID", "Usuario", "Correo", "Nombre Completo (PII)", "Documento (PII)",
                "Teléfono (PII)", "Tipo Sangre (PHI)", "Condiciones Médicas (PHI)",
                "Tarjeta Enmascarada (PCI)", "Intentos Fallidos", "Bloqueado Hasta", "Fecha Creación"
            ])
            for r in rows:
                writer.writerow([
                    r[0], r[1], r[2],
                    decrypt_data(r[3]), decrypt_data(r[4]), decrypt_data(r[5]),
                    decrypt_data(r[6]), decrypt_data(r[7]),
                    f"**** **** **** {r[8]}", r[9],
                    r[10].isoformat() if r[10] else "Activo",
                    r[11].isoformat() if r[11] else "",
                ])
        else:
            writer.writerow([
                "ID", "Usuario", "Correo", "Nombre Completo (Cifrado)", "Documento (Cifrado)",
                "Teléfono (Cifrado)", "Tipo Sangre (Cifrado)", "Condiciones Médicas (Cifrado)",
                "Últimos 4 Tarjeta", "Intentos Fallidos", "Bloqueado Hasta", "Fecha Creación"
            ])
            for r in rows:
                writer.writerow([
                    r[0], r[1], r[2],
                    bytes(r[3]).hex()[:24] + "...", bytes(r[4]).hex()[:24] + "...", bytes(r[5]).hex()[:24] + "...",
                    bytes(r[6]).hex()[:24] + "...", bytes(r[7]).hex()[:24] + "...",
                    f"**** {r[8]}", r[9],
                    r[10].isoformat() if r[10] else "Activo",
                    r[11].isoformat() if r[11] else "",
                ])

        return True, "Reporte CSV generado correctamente.", output.getvalue()

    except Exception:
        logger.exception("Error interno al exportar usuarios a CSV")
        return False, "No fue posible generar el archivo CSV en este momento.", None


def authenticate_admin(identifier: str, password: str, otp_code: str) -> tuple[bool, str, str | None]:
    """Autentica a un administrador contra la tabla aislada administradores con PyOTP atómico."""
    clean_id = identifier.strip().lower()
    clean_otp = otp_code.strip()

    if not clean_id or not password or not clean_otp:
        return False, "Todos los campos son obligatorios.", None

    generic_error = "Credenciales administrativas o código OTP inválidos."

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, usuario, contrasena_hash, secreto_totp_cifrado,
                           bloqueado_hasta, activo
                    FROM administradores
                    WHERE usuario = %s OR correo = %s
                    """,
                    (clean_id, clean_id),
                )
                row = cur.fetchone()

                if not row:
                    try:
                        ph.verify(_DUMMY_HASH, password)
                    except VerifyMismatchError:
                        pass
                    return False, generic_error, None

                admin_id, username, password_hash, totp_secret_enc, locked_until, activo = row

                now = datetime.now(timezone.utc)

                if locked_until and locked_until > now:
                    remaining = int((locked_until - now).total_seconds() // 60) + 1
                    return False, f"Cuenta bloqueada por seguridad. Intente en {remaining} min.", None

                try:
                    ph.verify(password_hash, password)
                except VerifyMismatchError:
                    _register_failure(cur, conn, "administradores", admin_id, now)
                    return False, generic_error, None

                # Se revisa después de la contraseña para no revelar a un tercero
                # qué cuentas administrativas existen.
                if not activo:
                    return False, "Cuenta administrativa deshabilitada.", None

                if not re.fullmatch(r"\d{6}", clean_otp):
                    _register_failure(cur, conn, "administradores", admin_id, now)
                    return False, generic_error, None

                matched_step = _verify_totp_step(totp_secret_enc, clean_otp)
                if matched_step is None:
                    _register_failure(cur, conn, "administradores", admin_id, now)
                    return False, generic_error, None

                cur.execute(
                    """
                    UPDATE administradores
                    SET intentos_fallidos = 0, bloqueado_hasta = NULL, ultimo_paso_otp = %s
                    WHERE id = %s AND (ultimo_paso_otp IS NULL OR ultimo_paso_otp < %s)
                    """,
                    (matched_step, admin_id, matched_step),
                )
                if cur.rowcount != 1:
                    _register_failure(cur, conn, "administradores", admin_id, now)
                    return False, "Este código OTP ya fue utilizado. Espere el siguiente código de 30 segundos.", None

                conn.commit()
                return True, "Acceso administrativo concedido.", username

    except Exception:
        logger.exception("Error interno en authenticate_admin")
        return False, "Error de autenticación administrativa.", None


def verify_admin_stepup_otp(admin_username: str, otp_code: str) -> tuple[bool, str]:
    """Re-autenticación atómica con nuevo código OTP para exportar CSV descifrado."""
    clean_otp = otp_code.strip()
    if not admin_username or not re.fullmatch(r"\d{6}", clean_otp):
        return False, "Ingrese un código OTP válido de 6 dígitos."

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, secreto_totp_cifrado, bloqueado_hasta
                    FROM administradores
                    WHERE usuario = %s AND activo = TRUE
                    """,
                    (admin_username,),
                )
                row = cur.fetchone()

                if not row:
                    return False, "Administrador no válido."

                admin_id, totp_secret_enc, locked_until = row
                now = datetime.now(timezone.utc)

                if locked_until and locked_until > now:
                    return False, "Cuenta bloqueada por seguridad. Intente más tarde."

                matched_step = _verify_totp_step(totp_secret_enc, clean_otp)
                if matched_step is None:
                    _register_failure(cur, conn, "administradores", admin_id, now)
                    return False, "Código OTP inválido o expirado."

                cur.execute(
                    """
                    UPDATE administradores
                    SET ultimo_paso_otp = %s
                    WHERE id = %s AND (ultimo_paso_otp IS NULL OR ultimo_paso_otp < %s)
                    """,
                    (matched_step, admin_id, matched_step),
                )
                if cur.rowcount != 1:
                    return False, "Este código OTP ya fue utilizado. Espere 30 segundos para el siguiente código."

                conn.commit()
                return True, "Identidad verificada para exportación descifrada."

    except Exception:
        logger.exception("Error interno en verify_admin_stepup_otp")
        return False, "No fue posible verificar el código OTP."