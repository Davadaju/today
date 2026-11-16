import os
import re
import time
from datetime import datetime, timedelta, timezone
import psycopg
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

ph = PasswordHasher()  # Usa Argon2id por defecto
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise ValueError("Falta la variable de entorno FERNET_KEY en el archivo .env")
cipher = Fernet(FERNET_KEY.encode())

# Parámetros de seguridad
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
TOTP_INTERVAL = 30


def get_db_connection():
    return psycopg.connect(
        host=os.getenv("DB_HOST", "10.10.101.29"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "ciber"),
        user=os.getenv("DB_USER", "analyst"),
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
    except Exception as e:
        return False, f"Error interno al registrar: {e}", None


def authenticate_user(identifier: str, password: str, otp_code: str) -> tuple[bool, str, dict | None]:
    """
    Evalúa las 3 variables (Usuario/Correo, Contraseña, OTP) considerando:
    1. Usuario no existe
    2. Cuenta bloqueada por Rate Limiting
    3. Contraseña incorrecta
    4. Código OTP inválido
    5. Retry Attack (código OTP ya usado en la misma ventana de 30s)
    6. Acceso exitoso
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
                           ultimo_paso_otp, intentos_fallidos, bloqueado_hasta,
                           nombre_completo_cifrado, tipo_sangre_cifrado, ultimos_4_tarjeta
                    FROM usuarios
                    WHERE usuario = %s OR correo = %s
                    """,
                    (clean_id, clean_id),
                )
                row = cur.fetchone()

                # Caso 1: Usuario no existe
                if not row:
                    return False, generic_error, None

                (
                    user_id, username, email, password_hash, totp_secret_enc,
                    last_otp_step, failed_attempts, locked_until,
                    full_name_enc, blood_type_enc, card_last4
                ) = row

                now = datetime.now(timezone.utc)

                # Caso 2: Rate Limiting (bloqueo temporal)
                if locked_until and locked_until > now:
                    remaining = int((locked_until - now).total_seconds() // 60) + 1
                    return False, f"Cuenta bloqueada temporalmente por seguridad. Intente en {remaining} min.", None

                def register_failure():
                    new_attempts = failed_attempts + 1
                    new_lock = now + timedelta(minutes=LOCKOUT_MINUTES) if new_attempts >= MAX_FAILED_ATTEMPTS else None
                    cur.execute(
                        "UPDATE usuarios SET intentos_fallidos = %s, bloqueado_hasta = %s WHERE id = %s",
                        (new_attempts, new_lock, user_id),
                    )
                    conn.commit()

                # Caso 3: Verificar contraseña con Argon2
                try:
                    ph.verify(password_hash, password)
                except VerifyMismatchError:
                    register_failure()
                    return False, generic_error, None

                # Caso 4 y 5: Verificar OTP y prevenir Retry Attacks
                if not re.fullmatch(r"\d{6}", clean_otp):
                    register_failure()
                    return False, generic_error, None

                totp_secret = decrypt_data(totp_secret_enc)
                totp = pyotp.TOTP(totp_secret, interval=TOTP_INTERVAL)
                current_step = int(time.time()) // TOTP_INTERVAL

                matched_step = None
                for offset in (-1, 0, 1):
                    candidate_time = (current_step + offset) * TOTP_INTERVAL
                    if totp.verify(clean_otp, for_time=candidate_time, valid_window=0):
                        matched_step = current_step + offset
                        break

                if matched_step is None:
                    register_failure()
                    return False, generic_error, None

                if matched_step <= (last_otp_step or 0):
                    register_failure()
                    return False, "Este código OTP ya fue utilizado. Espere el siguiente código de 30 segundos.", None

                # Caso 6: Acceso exitoso
                cur.execute(
                    """
                    UPDATE usuarios
                    SET intentos_fallidos = 0, bloqueado_hasta = NULL, ultimo_paso_otp = %s
                    WHERE id = %s
                    """,
                    (matched_step, user_id),
                )
                conn.commit()

                user_profile = {
                    "username": username,
                    "email": email,
                    "full_name": decrypt_data(full_name_enc),
                    "blood_type": decrypt_data(blood_type_enc),
                    "card_last4": card_last4,
                }
                return True, "Autenticación multifactor exitosa.", user_profile

    except Exception as e:
        return False, f"Error de conexión con el servidor de autenticación: {e}", None
