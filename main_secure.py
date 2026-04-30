"""
AuthX - Versiunea SECURIZATA (v2)
Toate vulnerabilitatile din v1 (main.py) au fost remediate conform baremului.

Fix-uri aplicate:
  FIX 4.1 - Password Policy: minim 8 caractere, litera mare/mica, cifra, caracter special
  FIX 4.2 - Stocare parola: bcrypt cu salt automat (in loc de MD5)
  FIX 4.3 - Rate Limiting: blocare cont 15 min dupa 5 incercari esuate, logare tentative
  FIX 4.4 - User Enumeration: mesaj unic "Credentiale invalide" indiferent de motiv
  FIX 4.5 - Sesiuni securizate: HttpOnly, SameSite=Strict, expirare scurta,
             rotatie token la login, invalidare la logout
  FIX 4.6 - Reset parola: token random (secrets), expirare 1 ora, stergere dupa utilizare
"""

import re
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response, Cookie
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sqlite3

app = FastAPI()

#  Constante 
MAX_LOGIN_ATTEMPTS = 5          # FIX 4.3
LOCKOUT_MINUTES    = 15         # FIX 4.3
SESSION_HOURS      = 8          # FIX 4.5 - scurtam durata sesiunii fata de 24h din v1
RESET_TOKEN_HOURS  = 1          # FIX 4.6

#  Modele Pydantic 
class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ResetRequest(BaseModel):
    email: str

class PasswordChange(BaseModel):
    token: str
    new_password: str

#  DB helper 
def get_db_connection():
    conn = sqlite3.connect('./db/database.db')
    conn.row_factory = sqlite3.Row
    return conn

#  FIX 4.1 - Validare politica parola 
def validate_password_strength(password: str) -> bool:
    """
    Parola valida daca:
    - minim 8 caractere
    - cel putin o litera mare
    - cel putin o litera mica
    - cel putin o cifra
    - cel putin un caracter special
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', password):
        return False
    return True

#  FIX 4.2 - Hash bcrypt 
def hash_password(password: str) -> str:
    """Genereaza un hash bcrypt cu salt automat."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, stored_hash: str) -> bool:
    """Compara parola in clar cu hash-ul bcrypt din DB."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

#  FIX 4.3 - Rate limiting / blocare cont 
def get_lockout_until(email: str, conn) -> Optional[datetime]:
    """Returneaza data/ora deblocarii daca contul este blocat, altfel None."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT locked, lockout_until FROM users WHERE email = ?", (email,)
    )
    row = cursor.fetchone()
    if not row or not row['locked']:
        return None
    if row['lockout_until'] is None:
        return None
    lockout_until = datetime.fromisoformat(row['lockout_until'])
    if datetime.now() < lockout_until:
        return lockout_until
    # Blocarea a expirat -> deblocare automata
    cursor.execute(
        "UPDATE users SET locked = 0, failed_attempts = 0, lockout_until = NULL WHERE email = ?",
        (email,)
    )
    conn.commit()
    return None


def record_failed_attempt(email: str, conn):
    """Incrementeaza contorul de esecuri si blocheaza dupa MAX_LOGIN_ATTEMPTS."""
    cursor = conn.cursor()
    cursor.execute("SELECT failed_attempts FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    if not row:
        return
    new_count = row['failed_attempts'] + 1
    if new_count >= MAX_LOGIN_ATTEMPTS:
        lockout_until = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
        cursor.execute(
            "UPDATE users SET failed_attempts = ?, locked = 1, lockout_until = ? WHERE email = ?",
            (new_count, lockout_until.isoformat(), email)
        )
    else:
        cursor.execute(
            "UPDATE users SET failed_attempts = ? WHERE email = ?",
            (new_count, email)
        )
    conn.commit()
    # FIX 4.3 - Logam tentativa esuata
    cursor.execute(
        "INSERT INTO audit_logs (user_id, action, resource, ip_address) "
        "SELECT id, 'FAILED_LOGIN', 'auth', NULL FROM users WHERE email = ?",
        (email,)
    )
    conn.commit()


def reset_failed_attempts(email: str, conn):
    """Reseteaza contorul de esecuri dupa un login reusit."""
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, locked = 0, lockout_until = NULL WHERE email = ?",
        (email,)
    )
    conn.commit()

#  FIX 4.5 - Gestionare sesiuni securizate 
def create_session(user_id: int, ip_address=None, user_agent=None) -> str:
    """Creeaza sesiune cu token criptografic securizat."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # FIX 4.5: token random, nu user_id predictibil
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=SESSION_HOURS)
    cursor.execute(
        "INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, session_token, expires_at.isoformat(), ip_address, user_agent)
    )
    conn.commit()
    conn.close()
    return session_token


def validate_session(session_token: str) -> Optional[int]:
    """Returneaza user_id daca sesiunea e valida si neexpirata."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > datetime('now')",
        (session_token,)
    )
    result = cursor.fetchone()
    conn.close()
    return result['user_id'] if result else None


def invalidate_session(session_token: str):
    """Sterge sesiunea din DB (logout / rotatie token)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()


def rotate_session(old_token: str, ip_address=None, user_agent=None) -> Optional[str]:
    """Rotatie token: invalideaza vechea sesiune si creeaza una noua."""
    user_id = validate_session(old_token)
    if user_id:
        invalidate_session(old_token)
        return create_session(user_id, ip_address, user_agent)
    return None

#  Rute 

@app.get("/")
def root():
    return FileResponse("./html/login_secure.html", media_type="text/html")


#  FIX complet: 4.2 + 4.3 + 4.4 + 4.5 
@app.post("/login")
def login(user: UserLogin, request: Request, response: Response):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    db_user = cursor.fetchone()

    # FIX 4.4 - mesaj generic, indiferent daca userul lipseste sau parola e gresita
    INVALID = "Credentiale invalide"

    if not db_user:
        conn.close()
        raise HTTPException(status_code=401, detail=INVALID)

    # FIX 4.3 - verifica blocare cont
    lockout_until = get_lockout_until(user.email, conn)
    if lockout_until:
        conn.close()
        raise HTTPException(
            status_code=429,
            detail=f"Cont blocat pana la {lockout_until.strftime('%H:%M:%S')}. "
                   f"Prea multe incercari esuate."
        )

    # FIX 4.2 - verificare cu bcrypt
    if not verify_password(user.password, db_user['password_hash']):
        record_failed_attempt(user.email, conn)
        conn.close()
        raise HTTPException(status_code=401, detail=INVALID)

    # Login reusit
    reset_failed_attempts(user.email, conn)
    conn.close()

    # FIX 4.5 - cookie securizat: HttpOnly, SameSite=Strict, expirare scurta
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    session_token = create_session(db_user['id'], ip, ua)

    response.set_cookie(
        key="session_id",
        value=session_token,
        httponly=True,           # FIX 4.5 - inaccesibil din JavaScript (anti-XSS)
        samesite="strict",       # FIX 4.5 - protectie CSRF
        secure=False,            # Pune True in productie (HTTPS)
        max_age=SESSION_HOURS * 3600
    )
    return {"message": "Login reusit!"}


@app.get("/register")
def register_page():
    return FileResponse("./html/register_secure.html", media_type="text/html")


#  FIX 4.1 + 4.2 
@app.post("/register")
def register(user: UserRegister):
    # FIX 4.1 - validare politica parola
    if not validate_password_strength(user.password):
        raise HTTPException(
            status_code=400,
            detail="Parola trebuie sa aiba minim 8 caractere, cel putin o litera mare, "
                   "o litera mica, o cifra si un caracter special."
        )

    conn = get_db_connection()
    db = conn.cursor()
    db.execute("SELECT id FROM users WHERE email = ?", (user.email,))
    if db.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email deja inregistrat")

    # FIX 4.2 - stocam hash bcrypt, nu MD5
    password_hash = hash_password(user.password)
    db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (user.email, password_hash)
    )
    conn.commit()
    conn.close()
    return {"message": "Utilizator inregistrat cu succes!"}


@app.get("/dashboard")
def dashboard():
    return FileResponse("./html/dashboard.html", media_type="text/html")


#  FIX 4.5 - Logout cu invalidare sesiune 
@app.post("/logout")
def logout(response: Response, session_id: Optional[str] = Cookie(default=None)):
    if session_id:
        invalidate_session(session_id)   # FIX 4.5 - sesiunea nu mai poate fi reutilizata
    response.delete_cookie("session_id")
    return {"message": "Logout reusit!"}


@app.get("/reset-password")
def reset_password_page():
    return FileResponse("./html/reset_password.html", media_type="text/html")


#  FIX 4.6 - Reset token random + expirare + one-time 
@app.post("/request-reset")
def request_password_reset(data: ResetRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (data.email,))
    user = cursor.fetchone()

    if user:
        # FIX 4.6 - token criptografic random (nu Base64 de email)
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=RESET_TOKEN_HOURS)

        # FIX 4.6 - stergem orice token vechi pentru acelasi email
        cursor.execute("DELETE FROM reset_tokens WHERE email = ?", (data.email,))
        cursor.execute(
            "INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)",
            (data.email, token, expires_at.isoformat())
        )
        conn.commit()
        conn.close()
        # In productie se trimite prin email, nu in raspuns!
        return {
            "message": "Daca emailul exista, s-a trimis un link de resetare.",
            "link": f"http://127.0.0.1:8001/reset-password?token={token}"
        }

    conn.close()
    # Anti-enumerare: acelasi mesaj indiferent daca emailul exista
    return {"message": "Daca emailul exista, s-a trimis un link de resetare."}


@app.post("/reset-password")
def reset_password(data: PasswordChange):
    # FIX 4.1 - validam parola noua
    if not validate_password_strength(data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Parola trebuie sa aiba minim 8 caractere, cel putin o litera mare, "
                   "o litera mica, o cifra si un caracter special."
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    # FIX 4.6 - verificam si expirarea tokenului
    cursor.execute(
        "SELECT email FROM reset_tokens WHERE token = ? AND expires_at > datetime('now')",
        (data.token,)
    )
    result = cursor.fetchone()

    if not result:
        conn.close()
        raise HTTPException(status_code=400, detail="Token invalid sau expirat")

    email = result[0]
    new_hash = hash_password(data.new_password)   # FIX 4.2
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (new_hash, email)
    )
    # FIX 4.6 - token one-time: stergem dupa utilizare
    cursor.execute("DELETE FROM reset_tokens WHERE token = ?", (data.token,))
    conn.commit()
    conn.close()
    return {"message": "Parola a fost resetata cu succes!"}
