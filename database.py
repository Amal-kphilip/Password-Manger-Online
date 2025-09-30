import os
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

# Use an environment variable for the database URL, fallback to local SQLite
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///passwords.db')

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Encryption Key Management ---
# For production, set ENCRYPTION_KEY as an environment variable
key_str = os.environ.get('ENCRYPTION_KEY')
if not key_str:
    # Fallback for local dev: generate/load from file (NOT FOR PRODUCTION)
    if os.path.exists('secret.key'):
        with open('secret.key', 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open('secret.key', 'wb') as f:
            f.write(key)
else:
    key = key_str.encode()

cipher_suite = Fernet(key)

# --- SQLAlchemy Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    passwords = relationship("PasswordEntry", back_populates="owner", cascade="all, delete-orphan")

class PasswordEntry(Base):
    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    username = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    owner = relationship("User", back_populates="passwords")

# --- Database Functions ---
def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()