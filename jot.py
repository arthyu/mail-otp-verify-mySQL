from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jose import jwt, JWTError
from datetime import datetime, timedelta
import hashlib
import hmac
import random
from dotenv import load_dotenv
import os

load_dotenv()  
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")


# ─── DATABASE ─────────────────────────────
DATABASE_URL = "mysql+pymysql://root:1234@localhost:3306/usersdb"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ─── JWT CONFIG ───────────────────────────
SECRET_KEY = "your-super-secret-jwt-key"
ALGORITHM  = "HS256"

def create_token(user_id: int, email: str) -> str:
    payload = {
        "sub":   str(user_id),
        "email": email,
        "exp":   datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ─── AUTH DEPENDENCY ──────────────────────
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token   = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token — please login again")
    return payload

# ─── PASSWORD HASHING ─────────────────────
SECRET = "your-secret-key-here"

def hash_password(password: str) -> str:
    return hmac.new(SECRET.encode(), password.encode(), hashlib.sha256).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed

# ─── MODELS ───────────────────────────────
class User(Base):
    __tablename__ = "users"
    user_id  = Column(Integer, primary_key=True, index=True)
    name     = Column(String(100))
    email    = Column(String(100), unique=True)
    password = Column(String(255))
    verified = Column(Integer, default=0)

class OTPStore(Base):
    __tablename__ = "otps"
    id    = Column(Integer, primary_key=True, index=True)
    email = Column(String(100))
    otp   = Column(String(10))

Base.metadata.create_all(bind=engine)

# ─── EMAIL CONFIG ─────────────────────────
conf = ConnectionConfig(
    MAIL_USERNAME   = MAIL_USERNAME,    # ← your gmail
    MAIL_PASSWORD   = MAIL_PASSWORD,        # ← gmail app password
    MAIL_FROM       = MAIL_USERNAME,     # ← your gmail
    MAIL_PORT       = 587,
    MAIL_SERVER     = "smtp.gmail.com",
    MAIL_STARTTLS   = True,
    MAIL_SSL_TLS    = False,
    USE_CREDENTIALS = True
)
# ─── APP ──────────────────────────────────
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════
#  PUBLIC ROUTES — no token needed
# ═══════════════════════════════════════════

# STEP 1 — Register: save user and send OTP
@app.post("/register")
async def register(data: dict):
    db = SessionLocal()

    name     = data.get("name")
    email    = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        raise HTTPException(status_code=400, detail="All fields required")

    existing = db.query(User).filter(User.email == email).first()
    if existing and existing.verified == 1:
        raise HTTPException(status_code=400, detail="Email already registered")

    otp = str(random.randint(100000, 999999))

    if existing:
        existing.name     = name
        existing.password = hash_password(password)
        existing.verified = 0
        db.commit()
    else:
        db.add(User(name=name, email=email, password=hash_password(password), verified=0))
        db.commit()

    old_otp = db.query(OTPStore).filter(OTPStore.email == email).first()
    if old_otp:
        db.delete(old_otp)
        db.commit()

    db.add(OTPStore(email=email, otp=otp))
    db.commit()

    message = MessageSchema(
        subject    = "Your OTP Code — UserBase",
        recipients = [email],
        body       = f"""
        <h2>Welcome to UserBase, {name}!</h2>
        <p>Your OTP verification code is:</p>
        <h1 style="letter-spacing:8px; color:#2563eb;">{otp}</h1>
        <p>Enter this code to complete your registration.</p>
        """,
        subtype = "html"
    )
    await FastMail(conf).send_message(message)
    return {"message": "OTP sent to your email"}


# STEP 2 — Verify OTP
@app.post("/verify-otp")
def verify_otp(data: dict):
    db = SessionLocal()

    email = data.get("email")
    otp   = data.get("otp")

    if not email or not otp:
        raise HTTPException(status_code=400, detail="Email and OTP required")

    stored = db.query(OTPStore).filter(OTPStore.email == email).first()

    if not stored:
        raise HTTPException(status_code=404, detail="OTP not found — register first")

    if stored.otp != str(otp):
        raise HTTPException(status_code=401, detail="Incorrect OTP")

    user          = db.query(User).filter(User.email == email).first()
    user.verified = 1
    db.commit()

    db.delete(stored)
    db.commit()

    return {
        "message": "Registration successful!",
        "user_id": user.user_id,
        "name":    user.name,
        "email":   user.email
    }


# STEP 3 — Login → returns JWT token
@app.post("/login")
def login(data: dict):
    db = SessionLocal()

    email    = data.get("email")
    password = data.get("password")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.verified == 0:
        raise HTTPException(status_code=401, detail="Email not verified — check your OTP")

    if not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    # create JWT token
    token = create_token(user.user_id, user.email)

    return {
        "message":  "Login successful",
        "token":    token,          # ← frontend stores this
        "user_id":  user.user_id,
        "name":     user.name,
        "email":    user.email
    }


# ═══════════════════════════════════════════
#  PROTECTED ROUTES — token required
# ═══════════════════════════════════════════

# GET my profile — only logged in user
@app.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    db      = SessionLocal()
    user_id = int(current_user["sub"])
    user    = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user_id": user.user_id,
        "name":    user.name,
        "email":   user.email
    }


# GET all users — protected
@app.get("/users")
def get_users(current_user: dict = Depends(get_current_user)):
    db    = SessionLocal()
    users = db.query(User).all()
    return [
        {
            "user_id":  u.user_id,
            "name":     u.name,
            "email":    u.email,
            "verified": u.verified
        }
        for u in users
    ]


# DELETE user — protected
@app.delete("/users/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    db   = SessionLocal()
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User removed successfully"}