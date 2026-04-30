import base64

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sqlite3
import hashlib

app = FastAPI()

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

def get_db_connection():
    conn = sqlite3.connect('./db/database.db')
    conn.row_factory = sqlite3.Row
    return conn


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
        raise HTTPException(status_code=401, detail="Parola gresita")
    
    conn.close()
    
    # Lipseste HttpOnly, Secure si SameSite
    session_token = f"{db_user['id']}" 
    response.set_cookie(key="session_id", value=session_token)
    
    return {"message": "Login reusit!"}


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
    
    return {"message": "Utilizator inregistrat cu succes!"}


@app.get("/dashboard")
def dashboard():
    return FileResponse("./html/dashboard.html", media_type="text/html")


@app.get("/reset-password")
def reset_password_page():
    return FileResponse("./html/reset_password.html", media_type="text/html")



@app.post("/request-reset")
def request_password_reset(data: ResetRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (data.email,))
    user = cursor.fetchone()

    if user:
        # VULNERABILITATEA 1: Token predictibil (usor de ghicit)
        # Transformam pur si simplu adresa de email in Base64. 
        # Nu exista nicio sursa de "entropie" (aleatoriu).
        token = base64.urlsafe_b64encode(data.email.encode('utf-8')).decode('utf-8').rstrip('=')
        
        # Salvam token-ul. 
        # VULNERABILITATEA 2: Nu asociem nicio data de expirare (timestamp).
        cursor.execute("INSERT INTO reset_tokens (email, token) VALUES (?, ?)", (data.email, token))
        conn.commit()
        conn.close()
        
        # Simulam trimiterea unui email
        return {"message": "Link trimis!", "link": f"http://127.0.0.1:8000/reset-password?token={token}"}
        
    # Pastram totusi protectia anti-enumerare despre care am vorbit anterior
    conn.close()
    return {"message": "Daca emailul exista, s-a trimis un link."}

@app.post("/reset-password")
def reset_password(data: PasswordChange):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificam daca tokenul exista in baza de date
    normalized_token = data.token.rstrip('=')
    cursor.execute("SELECT email FROM reset_tokens WHERE token = ? OR rtrim(token, '=') = ?", (data.token, normalized_token))
    result = cursor.fetchone()
    
    # VULNERABILITATEA 2 : Acceptam tokenul oricand, 
    # chiar si dupa 5 ani de la generare.
    if not result:
        conn.close()
        raise HTTPException(status_code=400, detail="Token invalid")
    
    # Resetam efectiv parola
    email = result[0]
    cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashlib.md5(data.new_password.encode()).hexdigest(), email))
    conn.commit()
    conn.close()
    
    # VULNERABILITATEA 3: Token reutilizabil.
    # Intentionat "uitam" sa stergem tokenul din dictionar dupa folosire.
    # In mod normal, ar trebui sa facem: del reset_tokens[token]
    
    return {"message": f"Parola pentru {email} a fost resetata cu succes!"}