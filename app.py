from fastapi import FastAPI, Form, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import random
import re
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

# SMTP credentials
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# FastAPI Application
app = FastAPI(title="SilentFocus", version="1.0.0", root_path="/Payrano")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Configuration
DATABASE_URL = "sqlite:///aitravel_db.sqlite3"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your_jwt_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Model - User
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility Functions
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def validate_email(email: str) -> bool:
    email_regex = r"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)"
    return re.match(email_regex, email) is not None

# Email sender function
def send_otp_email(to_email: str, otp: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = 'Your OTP for Payrano'
        body = f"Your OTP is: {otp}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending OTP email: {str(e)}")

# In-memory stores
pending_signups = {}      # For signup OTPs
pending_resets = {}       # For forgot-password OTPs

# Routes

@app.get("/")
def index():
    return {"status": "1", "message": "✅ Payrano is Live"}

@app.post("/signup")
async def signup(
    email: str = Form(...),
    password: str = Form(...),
):
    if not validate_email(email):
        return {"status": "0", "message": "Invalid email format."}

    if pending_signups.get(email):
        return {"status": "0", "message": "Pending OTP verification already initiated."}

    otp = str(random.randint(100000, 999999))
    password_hash = get_password_hash(password)

    pending_signups[email] = {
        "email": email,
        "password_hash": password_hash,
        "otp": otp,
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }

    send_otp_email(email, otp)

    return {
        "status": "1",
        "message": "OTP sent to email",
        "result": {"email": email}
    }


@app.post("/verify-otp")
async def verify_otp(
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    pending = pending_signups.get(email)
    if not pending:
        return {"status": "0", "message": "No OTP found for this email."}

    if pending["otp"] != otp:
        return {"status": "0", "message": "Incorrect OTP."}

    if datetime.utcnow() > pending["expires_at"]:
        del pending_signups[email]
        return {"status": "0", "message": "OTP expired."}

    if db.query(User).filter(User.email == email).first():
        del pending_signups[email]
        return {"status": "0", "message": "Email already registered."}

    user = User(
        email=pending["email"],
        password_hash=pending["password_hash"]
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    del pending_signups[email]

    return {
        "status": "1",
        "message": "OTP verified. User created",
        "result": {"user_id": user.id}
    }

@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.password_hash):
        return {
            "status": "0",
            "message": "Invalid credentials."
        }

    token = create_access_token({"sub": user.email})
    return {
        "status": "1",
        "message": "Login successful",
        "result": {
            "access_token": token,
            "token_type": "bearer",
            "user_id": user.id
        }
    }

@app.post("/resend-otp")
async def resend_otp(email: str = Form(...)):
    try:
        pending = pending_signups.get(email)
        if not pending:
            return {
                "status": "0",
                "message": "No pending signup found for this email."
            }

        new_otp = str(random.randint(100000, 999999))
        pending["otp"] = new_otp
        pending["expires_at"] = datetime.utcnow() + timedelta(minutes=10)

        send_otp_email(email, new_otp)

        return {
            "status": "1",
            "message": "OTP resent to email",
            "result": {"email": email}
        }
    except Exception as e:
        return {
            "status": "0",
            "message": f"An error occurred while resending OTP: {str(e)}"
        }

@app.post("/forgot-password")
async def forgot_password(
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    if not validate_email(email):
        return {"status": "0", "message": "Invalid email format."}

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"status": "0", "message": "User not found."}

    otp = str(random.randint(100000, 999999))
    pending_resets[email] = {
        "otp": otp,
        "verified": False,
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }

    send_otp_email(email, otp)
    return {
        "status": "1",
        "message": "OTP sent to email for password reset",
        "result": {"email": email}
    }

@app.post("/reset-password")
async def reset_password(
    email: str = Form(...),
    otp: str = Form(...),
):
    pending = pending_resets.get(email)

    if not pending or pending["otp"] != otp:
        return {"status": "0", "message": "Invalid or expired OTP."}

    if datetime.utcnow() > pending["expires_at"]:
        del pending_resets[email]
        return {"status": "0", "message": "OTP expired."}

    pending["verified"] = True

    return {"status": "1", "message": "OTP verified. You can now create a new password."}

@app.post("/create-new-password")
async def create_new_password(
    email: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    pending = pending_resets.get(email)
    if not pending or not pending.get("verified"):
        return {
            "status": "0",
            "message": "OTP verification required before creating new password."
        }

    if new_password != confirm_password:
        return {"status": "0", "message": "Passwords do not match."}

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"status": "0", "message": "User not found."}

    user.password_hash = get_password_hash(new_password)
    db.commit()

    return {"status": "1", "message": "Password reset successfully"}
