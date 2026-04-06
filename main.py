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
def menu():
    return FileResponse("./html/menu.html", media_type="text/html")

@app.get("/vulnerable/register")
def vulnerable_register():
    return FileResponse("./html/vuln/register.html", media_type="text/html")

@app.post("/vulnerable/register")
def vulnerable_register(user: UserRegister):
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



@app.get("/vulnerable/login")
def vulnerable_login():
    return FileResponse("./html/login.html", media_type="text/html")

@app.post("/vulnerable/login")
def vulnerable_login(user: UserLogin, response: Response):
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
    
    # VULNERABILITATE 4.5: Gestionare nesigură a sesiunilor - Setăm un cookie super simplu, fără securitate
    # Lipsește HttpOnly, Secure și SameSite.
    session_token = f"session_for_{db_user['id']}" # Token extrem de predictibil
    response.set_cookie(key="session_id", value=session_token)
    
    return {"message": "Login reușit!"}


