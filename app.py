from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from datetime import datetime, timedelta
from typing import List, Optional
from passlib.context import CryptContext
from jose import jwt
from dotenv import load_dotenv
import random
import re
import smtplib
import os
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

# SMTP credentials
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your_jwt_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# FastAPI app setup
app = FastAPI(title="SilentFocus", version="1.0.0", root_path="/SilentFocus")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_URL = "sqlite:///aitravel_db.sqlite3"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    phone_number = Column(String, nullable=True)  # NEW FIELD
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    silent_status = relationship("SilentModeStatus", back_populates="user", uselist=False)
    schedules = relationship("SilentModeSchedule", back_populates="user")

class SilentModeStatus(Base):
    __tablename__ = "silent_mode_status"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    silent_mode = Column(Boolean, default=False)

    user = relationship("User", back_populates="silent_status")

class SilentModeSchedule(Base):
    __tablename__ = "silent_mode_schedule"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"))
    from_time = Column(String)
    to_time = Column(String)
    days = Column(String)
    active = Column(Boolean, default=True)

    user = relationship("User", back_populates="schedules")

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class ToggleSilentModeRequest(BaseModel):
    userId: int
    silentMode: bool

class SilentModeStatusResponse(BaseModel):
    silentMode: bool
    activeSchedule: Optional[dict] = None

class ScheduleRequest(BaseModel):
    userId: int
    from_time: str
    to_time: str
    days: List[str]

class ToggleScheduleRequest(BaseModel):
    scheduleId: str
    active: bool

class ScheduleResponse(BaseModel):
    id: str
    from_time: str
    to_time: str
    days: List[str]
    active: bool

    class Config:
        orm_mode = True

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
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

def send_otp_email(to_email: str, otp: str):
    if not EMAIL_USER or not EMAIL_PASSWORD:
        raise HTTPException(status_code=500, detail="Email credentials not configured.")

    if not to_email or not otp:
        raise HTTPException(status_code=400, detail="Missing recipient email or OTP.")

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
pending_signups = {}
pending_resets = {}

# Routes
@app.get("/")
def index():
    return {"status": "1", "message": "✅ SilentFocus is Live"}

@app.post("/signup")
async def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_email(email):
        return {"status": "0", "message": "Invalid email format."}

    if pending_signups.get(email):
        return {"status": "0", "message": "Pending OTP verification already initiated."}

    if db.query(User).filter(User.email == email).first():
        return {"status": "0", "message": "Account already exists."}

    # Removed username uniqueness check to allow duplicates
    # if db.query(User).filter(User.username == username).first():
    #     return {"status": "0", "message": "Username already taken."}

    otp = str(random.randint(100000, 999999))
    password_hash = get_password_hash(password)

    pending_signups[email] = {
        "email": email,
        "username": username,
        "password_hash": password_hash,
        "otp": otp,
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }

    send_otp_email(email, otp)

    return {
        "status": "1",
        "message": "OTP sent to email",
        "result": {"email": email, "username": username}
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
    if db.query(User).filter(User.username == pending["username"]).first():
        del pending_signups[email]
        return {"status": "0", "message": "Username already taken."}

    user = User(
        email=pending["email"],
        username=pending["username"],
        password_hash=pending["password_hash"]
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    del pending_signups[email]

    return {
        "status": "1",
        "message": "OTP verified. User created.",
        "result": {
            "user_id": user.id,
            "email": user.email,
            "username": user.username
        }
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
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number
           
        }
    }

@app.post("/resend-otp")
async def resend_otp(email: str = Form(...)):
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


@app.post("/resend-otp")
async def resend_otp(email: str = Form(...)):
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

@app.post("/forgot-password")
async def forgot_password(
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    # Validate email format
    if not validate_email(email):
        return {"status": "0", "message": "Invalid email format."}

    # Check if user exists
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"status": "0", "message": "User not found."}

    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))

    # Store OTP in memory
    pending_resets[email] = {
        "otp": otp,
        "verified": False,
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }

    # Send OTP via email
    try:
        send_otp_email(email, otp)
    except Exception as e:
        return {"status": "0", "message": f"Failed to send OTP: {str(e)}"}

    # Return success response
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
    # Validate email format first
    if not validate_email(email):
        return {"status": "0", "message": "Invalid email format."}

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

    del pending_resets[email]

    return {"status": "1", "message": "Password reset successfully"}




# ---------------------- Routes ----------------------

# @app.post("/api/silent-mode/toggle")
# def toggle_silent_mode(
#     userId: int = Form(...),
#     silentMode: bool = Form(...),
#     db: Session = Depends(get_db)
# ):
#     user = db.query(User).filter(User.id == userId).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")

#     status = db.query(SilentModeStatus).filter_by(user_id=user.id).first()
#     if not status:
#         status = SilentModeStatus(user_id=user.id, silent_mode=silentMode)
#         db.add(status)
#     else:
#         status.silent_mode = silentMode
#     db.commit()
#     return {"success": True, "message": f"Silent Mode turned {'ON' if silentMode else 'OFF'}"}

# @app.get("/api/silent-mode/status", response_model=SilentModeStatusResponse)
# def get_status(userId: int, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.id == userId).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")

#     status = db.query(SilentModeStatus).filter_by(user_id=userId).first()
#     silent_mode = status.silent_mode if status else False

#     schedule = db.query(SilentModeSchedule).filter_by(user_id=userId, active=True).first()
#     active_schedule = {
#         "from": schedule.from_time,
#         "to": schedule.to_time,
#         "days": schedule.days.split(",")
#     } if schedule else None

#     return {"silentMode": silent_mode, "activeSchedule": active_schedule}

# @app.post("/api/silent-mode/schedule")
# def create_schedule(
#     userId: int = Form(...),
#     from_time: str = Form(...),
#     to_time: str = Form(...),
#     days: str = Form(...),  # Pass as comma-separated string: "Mon,Tue,Wed"
#     db: Session = Depends(get_db)
# ):
#     user = db.query(User).filter(User.id == userId).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")

#     new_schedule = SilentModeSchedule(
#         user_id=userId,
#         from_time=from_time,
#         to_time=to_time,
#         days=days
#     )
#     db.add(new_schedule)
#     db.commit()
#     return {"success": True, "message": "Schedule created", "scheduleId": new_schedule.id}

# @app.get("/api/silent-mode/schedules", response_model=List[ScheduleResponse])
# def get_schedules(userId: int, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.id == userId).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")

#     user_schedules = db.query(SilentModeSchedule).filter_by(user_id=userId).all()
#     return [
#         ScheduleResponse(
#             id=s.id,
#             from_time=s.from_time,
#             to_time=s.to_time,
#             days=s.days.split(","),
#             active=s.active
#         ) for s in user_schedules
#     ]

# @app.post("/api/silent-mode/schedule/toggle")
# def toggle_schedule(
#     scheduleId: str = Form(...),
#     active: bool = Form(...),
#     db: Session = Depends(get_db)
# ):
#     schedule = db.query(SilentModeSchedule).filter_by(id=scheduleId).first()
#     if not schedule:
#         raise HTTPException(status_code=404, detail="Schedule not found")

#     schedule.active = active
#     db.commit()
#     return {"success": True, "message": f"Schedule {'enabled' if active else 'disabled'}"}

# @app.delete("/api/silent-mode/schedule/{scheduleId}")
# def delete_schedule(scheduleId: str, db: Session = Depends(get_db)):
#     schedule = db.query(SilentModeSchedule).filter_by(id=scheduleId).first()
#     if not schedule:
#         raise HTTPException(status_code=404, detail="Schedule not found")
#     db.delete(schedule)
#     db.commit()
#     return {"success": True, "message": "Schedule deleted"}



from fastapi import FastAPI, HTTPException, Depends, Form
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from typing import Optional



class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True

# FastAPI app initialization


# POST - Create a User (using FormData)


# GET - Retrieve User by ID
# @app.get("/users/{user_id}", response_model=UserResponse)
# async def get_user(user_id: int, db: Session = Depends(get_db)):
#     db_user = db.query(User).filter(User.id == user_id).first()
#     if db_user is None:
#         raise HTTPException(status_code=404, detail="User not found")
#     return db_user

# # PUT - Update User by ID
# @app.patch("/users/{user_id}", response_model=UserResponse)
# async def update_user(
#     user_id: int,
#     username: Optional[str] = Form(None),
#     email: Optional[str] = Form(None),
#     is_active: Optional[bool] = Form(None),
#     db: Session = Depends(get_db),
# ):
#     db_user = db.query(User).filter(User.id == user_id).first()

#     if db_user is None:
#         raise HTTPException(status_code=404, detail="User not found")

#     # Update the fields if provided
#     if username:
#         db_user.username = username
#     if email:
#         # Check if email is already taken by another user
#         existing_user = db.query(User).filter(User.email == email).first()
#         if existing_user and existing_user.id != user_id:
#             raise HTTPException(status_code=400, detail="Email already in use by another user")
#         db_user.email = email
#     if is_active is not None:
#         db_user.is_active = is_active

#     db.commit()
#     db.refresh(db_user)
#     return db_user

# # Exception Handling
# @app.exception_handler(HTTPException)
# async def http_exception_handler(request, exc: HTTPException):
#     return {"status": 0, "message": exc.detail, "result": None}


from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional

@app.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    try:
        # Retrieve the user by user_id
        user = db.query(User).filter_by(id=user_id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Return user data (exclude password_hash for security reasons)
        return {
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number,
            "created_at": user.created_at
        }
    
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to retrieve user: {str(e)}")
    

from fastapi import FastAPI, Depends, HTTPException, Form
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional

from hashlib import sha256



@app.put("/users/{user_id}")
def update_user(user_id: int, 
                username: Optional[str] = Form(None),
                email: Optional[str] = Form(None),
                phone_number: Optional[str] = Form(None),
                db: Session = Depends(get_db)):
    try:
        # Retrieve the user by user_id
        user = db.query(User).filter_by(id=user_id).first()

        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        # Update fields if provided
        if username is not None:
            user.username = username
        if email is not None:
            user.email = email
        if phone_number is not None:
            user.phone_number = phone_number

        db.commit()

        return {"status": "1", "message": "User details updated successfully"}
    
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update user: {str(e)}")


# Google Login 

import os
from fastapi import FastAPI, HTTPException, Depends, Form
from sqlalchemy.orm import Session
from pydantic import BaseModel
from google.auth.transport.requests import Request
from google.oauth2.id_token import verify_oauth2_token
from datetime import datetime
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Secret key to encode JWT tokens
SECRET_KEY = "your-jwt-secret-key"
ALGORITHM = "HS256"

# Google client ID for OAuth
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# Function to create JWT token
def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=30)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Function to verify Google token
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from fastapi import HTTPException

# Using the GOOGLE_CLIENT_ID variable
GOOGLE_CLIENT_ID = "526959144743-qmpd0hj10tvbq8pdqp17a1j2o14krgt7.apps.googleusercontent.com"

def verify_google_token(id_token_str: str):
    try:
        # The audience should be your Google Client ID
        target_audience = GOOGLE_CLIENT_ID  # Use the GOOGLE_CLIENT_ID here
        
        # Create a request object for validation
        request = Request()

        # Verify the token
        decoded_token = id_token.verify_oauth2_token(id_token_str, request, audience=target_audience)

        # Return the decoded token (which contains user info)
        return decoded_token
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")



# Pydantic model for Google login response
class GoogleLoginResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    full_name: str

# Google Login API endpoint
from fastapi import Body

class GoogleLoginRequest(BaseModel):
    id_token: str

from fastapi.responses import JSONResponse

@app.post("/login/google")
async def google_login(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    try:
        google_user = verify_google_token(request.id_token)
        # Log or check the google_user data
    except Exception as e:
        return {"status": "0", "message": f"Token verification failed: {str(e)}", "result": {}}

    user = db.query(User).filter(User.email == google_user["email"]).first()

    if not user:
        user = User(
            email=google_user["email"],
            full_name=google_user["name"],
            profile_photo=google_user.get("picture"),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token({"sub": user.email})

    return {
        "status": "1", 
        "message": "Google login successful", 
        "result": {
            "access_token": token, 
            "token_type": "bearer", 
            "user_id": user.id, 
            "full_name": user.full_name
        }
    }