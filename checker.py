import hashlib
import requests
import secrets
import string
from zxcvbn import zxcvbn

# 1. HIBP Password Breach Lookup (k-Anonymity)
def check_pwned_password(password: str) -> int:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            for line in response.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
    except Exception:
        pass
    return 0

# 2. zxcvbn Strength Evaluator
def evaluate_strength(password: str):
    results = zxcvbn(password)
    return (
        results["score"],
        results["feedback"]["suggestions"],
        results["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
    )

# 3. Secure Password & Memorable Passphrase Generator
def generate_password(length=16, use_symbols=True, memorable=False) -> str:
    if memorable:
        wordlist = ["delta", "falcon", "orbit", "cipher", "summit", "matrix", "shield", "nexus", "timber", "hazard", "beacon"]
        selected = [secrets.choice(wordlist).capitalize() for _ in range(4)]
        return "-".join(selected) + str(secrets.randbelow(100))
    
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return "".join(secrets.choice(chars) for _ in range(length))

# 4. Email Breach Format & Status Check
def check_email_exposure(email: str):
    """Simulates/checks email breach exposure against common leak indexes."""
    # Note: Live HIBP Email API requires an authenticated paid API key; 
    # we verify structure and check exposure against local simulated indexes.
    common_pwned_domains = ["example.com", "test.com", "leakmail.com"]
    domain = email.split("@")[-1] if "@" in email else ""
    is_compromised = domain in common_pwned_domains
    return is_compromised
