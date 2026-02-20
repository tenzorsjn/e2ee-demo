import os
import json
import base64
import getpass
import hashlib

USERS_FILE = "users.json"
DEFAULT_ITERATIONS = 200_000

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def load_db() -> dict:
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_db(db: dict):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

def derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32
    )

def add_or_update_user(db: dict, username: str, password: str, iterations: int = DEFAULT_ITERATIONS):
    salt = os.urandom(16)
    h = derive(password, salt, iterations)

    db.setdefault("users", {})[username] = {
        "salt_b64": b64e(salt),
        "iterations": int(iterations),
        "hash_b64": b64e(h),
    }

def main():
    print("== users.json generator (PBKDF2-HMAC-SHA256) ==")
    print(f"Output file: {USERS_FILE}")
    print(f"Default iterations: {DEFAULT_ITERATIONS}")
    print("Tip: 输入用户名为空则结束。\n")

    db = load_db()
    users = db.setdefault("users", {})

    while True:
        username = input("Username: ").strip()
        if not username:
            break

        if username in users:
            ans = input(f"User '{username}' already exists. Overwrite? [y/N]: ").strip().lower()
            if ans != "y":
                print("Skip.\n")
                continue

        pwd1 = getpass.getpass("Password: ")
        pwd2 = getpass.getpass("Confirm : ")
        if pwd1 != pwd2:
            print("Passwords do not match. Try again.\n")
            continue
        if not pwd1:
            print("Empty password not allowed.\n")
            continue

        it_str = input(f"Iterations (enter to use {DEFAULT_ITERATIONS}): ").strip()
        iterations = DEFAULT_ITERATIONS if not it_str else int(it_str)

        add_or_update_user(db, username, pwd1, iterations)
        print(f"Added/updated user '{username}' with PBKDF2 iterations={iterations}.\n")

    save_db(db)
    print(f"Saved -> {USERS_FILE}")
    print(f"Total users: {len(db.get('users', {}))}")

if __name__ == "__main__":
    main()
