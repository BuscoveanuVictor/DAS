import base64

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta

app = FastAPI()

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str
    new_password: str

# Funcție helper pentru conectarea la baza de date
def get_db_connection():
    conn = sqlite3.connect('./db/database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Funcții helper pentru gestionarea sesiunilor securizate
def generate_secure_token():
    """Generează un token de sesiune securizat"""
    return secrets.token_urlsafe(32)

def create_session(user_id, ip_address=None, user_agent=None):
    """Creează o nouă sesiune în baza de date"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    session_token = generate_secure_token()
    expires_at = datetime.now() + timedelta(hours=24)  # Sesiune expiră în 24 ore
    
    cursor.execute('''
        INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, session_token, expires_at, ip_address, user_agent))
    
    conn.commit()
    conn.close()
    return session_token

def validate_session(session_token):
    """Validează un token de sesiune și returnează user_id dacă e valid"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_id FROM sessions 
        WHERE session_token = ? AND expires_at > datetime('now')
    ''', (session_token,))
    
    result = cursor.fetchone()
    conn.close()
    
    return result['user_id'] if result else None

def invalidate_session(session_token):
    """Invalidează o sesiune (logout)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
    conn.commit()
    conn.close()

def rotate_session(session_token, ip_address=None, user_agent=None):
    """Rotește token-ul de sesiune pentru securitate suplimentară"""
    user_id = validate_session(session_token)
    if user_id:
        invalidate_session(session_token)
        return create_session(user_id, ip_address, user_agent)
    return None


@app.get("/")
def login():
    return FileResponse("./html/login.html", media_type="text/html")

@app.post("/login")
def login(user: UserLogin, response: Response):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    db_user = cursor.fetchone()
    
    if not db_user:
        conn.close()
        raise HTTPException(status_code=404, detail="User inexistent")
    
    password_hash = hashlib.md5(user.password.encode()).hexdigest()
    
    if db_user['password_hash'] != password_hash:
        conn.close()
        raise HTTPException(status_code=401, detail="Parolă greșită")
    
    conn.close()
    
    # Lipseste HttpOnly, Secure si SameSite
    session_token = f"{db_user['id']}" 
    response.set_cookie(key="session_id", value=session_token)
    
    return {"message": "Login reușit!"}


@app.get("/register")
def register():
    return FileResponse("./html/register.html", media_type="text/html")

@app.post("/register")
def register(user: UserRegister):
    print("salut")
    conn = get_db_connection()
    db = conn.cursor()

    db.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    if db.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="User deja existent")

    password_hash = hashlib.md5(user.password.encode()).hexdigest()
    
    db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)", 
        (user.email, password_hash)
    )

    conn.commit()
    conn.close()
    
    return {"message": "Utilizator înregistrat cu succes!"}


@app.get("/dashboard")
def dashboard():
    return FileResponse("./html/dashboard.html", media_type="text/html")


@app.get("/reset-password")
def reset_password_page():
    return FileResponse("./html/reset_password.html", media_type="text/html")

# Modele Pydantic pentru request-uri
class ResetRequest(BaseModel):
    email: str

class PasswordChange(BaseModel):
    token: str
    new_password: str

@app.post("/request-reset")
def request_password_reset(data: ResetRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (data.email,))
    user = cursor.fetchone()

    if user:
        # ⚠️ VULNERABILITATEA 1: Token predictibil (ușor de ghicit)
        # Transformăm pur și simplu adresa de email în Base64. 
        # Nu există nicio sursă de "entropie" (aleatoriu).
        token = base64.urlsafe_b64encode(data.email.encode('utf-8')).decode('utf-8').rstrip('=')
        
        # Salvăm token-ul. 
        # ⚠️ VULNERABILITATEA 2: Nu asociem nicio dată de expirare (timestamp).
        cursor.execute("INSERT INTO reset_tokens (email, token) VALUES (?, ?)", (data.email, token))
        conn.commit()
        conn.close()
        
        # Simulăm trimiterea unui email
        return {"message": "Link trimis!", "link": f"http://127.0.0.1:8000/reset-password?token={token}"}
        
    # Păstrăm totuși protecția anti-enumerare despre care am vorbit anterior
    conn.close()
    return {"message": "Dacă emailul există, s-a trimis un link."}

@app.post("/reset-password")
def reset_password(data: PasswordChange):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificăm dacă tokenul există în baza de date
    normalized_token = data.token.rstrip('=')
    cursor.execute("SELECT email FROM reset_tokens WHERE token = ? OR rtrim(token, '=') = ?", (data.token, normalized_token))
    result = cursor.fetchone()
    
    # ⚠️ VULNERABILITATEA 2 (Continuare): Acceptăm tokenul oricând, 
    # chiar și după 5 ani de la generare.
    if not result:
        conn.close()
        raise HTTPException(status_code=400, detail="Token invalid")
    
    # Resetăm efectiv parola
    email = result[0]
    cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashlib.md5(data.new_password.encode()).hexdigest(), email))
    conn.commit()
    conn.close()
    
    # ⚠️ VULNERABILITATEA 3: Token reutilizabil.
    # Intenționat "uităm" să ștergem tokenul din dicționar după folosire.
    # În mod normal, ar trebui să facem: del reset_tokens[token]
    
    return {"message": f"Parola pentru {email} a fost resetată cu succes!"}