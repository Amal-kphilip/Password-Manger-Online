import sqlite3
from cryptography.fernet import Fernet
import os
from werkzeug.security import generate_password_hash

DB_NAME = 'passwords.db'
KEY_FILE = 'secret.key'

# --- Key Management (Unchanged) ---
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    return open(KEY_FILE, "rb").read()

key = load_key()
cipher_suite = Fernet(key)

# --- Database Initialization (Updated) ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # CHANGED: Added a 'name' column and renamed 'website' to 'url' for clarity
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# --- User Management (Unchanged) ---
def create_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, generate_password_hash(password)))
        conn.commit()
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
    return True

def get_user_by_username(username):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# --- Password Functions (Updated & New) ---
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# CHANGED: Now handles 'name' and 'url'
def add_password(name, url, username, password, user_id):
    encrypted = encrypt_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO passwords (name, url, username, encrypted_password, user_id) VALUES (?, ?, ?, ?, ?)",
        (name, url, username, encrypted, user_id)
    )
    conn.commit()
    conn.close()

# CHANGED: Now fetches 'name' and 'url'
def get_all_passwords(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, url, username, encrypted_password FROM passwords WHERE user_id = ?", (user_id,))
    entries = []
    for row in cursor.fetchall():
        try:
            decrypted_password = decrypt_password(row[4])
            entries.append({
                'id': row[0], 'name': row[1], 'url': row[2],
                'username': row[3], 'password': decrypted_password
            })
        except Exception:
            # Handle decryption error
            pass
    conn.close()
    return entries

def delete_password(entry_id, user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (entry_id, user_id))
    conn.commit()
    conn.close()

# NEW: Function to get a single password entry for editing
def get_password_by_id(entry_id, user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE id = ? AND user_id = ?", (entry_id, user_id))
    entry = cursor.fetchone()
    if entry:
        decrypted_password = decrypt_password(entry['encrypted_password'])
        return {
            'id': entry['id'], 'name': entry['name'], 'url': entry['url'],
            'username': entry['username'], 'password': decrypted_password
        }
    conn.close()
    return None

# NEW: Function to update an existing password entry
def update_password(entry_id, name, url, username, password, user_id):
    encrypted = encrypt_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        '''UPDATE passwords SET name = ?, url = ?, username = ?, encrypted_password = ?
           WHERE id = ? AND user_id = ?''',
        (name, url, username, encrypted, entry_id, user_id)
    )
    conn.commit()
    conn.close()