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
    is_timer_enabled = Column(Boolean, default=False)  # Add this field
    is_calendar_event = Column(Boolean, default=False)  # default custom

    user = relationship("User", back_populates="schedules")

class SignupOTP(Base):
    __tablename__ = "signup_otps"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    otp = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)

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
    return {"status": "1", "message": "? SilentFocus is Live"}

@app.post("/signup")
async def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_email(email):
        return {"status": "0", "message": "Invalid email format."}

    if db.query(User).filter(User.email == email).first():
        return {"status": "0", "message": "Account already exists."}

    # Removed username uniqueness check to allow duplicates
    # if db.query(User).filter(User.username == username).first():
    #     return {"status": "0", "message": "Username already taken."}

    otp = str(random.randint(1000, 9999))
    password_hash = get_password_hash(password)

    existing = db.query(SignupOTP).filter(SignupOTP.email == email).first()
    if existing:
        existing.username = username
        existing.password_hash = password_hash
        existing.otp = otp
        existing.expires_at = datetime.utcnow() + timedelta(minutes=10)
    else:
        pending_row = SignupOTP(
            email=email,
            username=username,
            password_hash=password_hash,
            otp=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db.add(pending_row)
    db.commit()

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
    pending_row = db.query(SignupOTP).filter(SignupOTP.email == email).first()
    if not pending_row:
        return {"status": "0", "message": "No OTP found for this email."}

    if pending_row.otp != otp:
        return {"status": "0", "message": "Incorrect OTP."}

    if datetime.utcnow() > pending_row.expires_at:
        db.delete(pending_row)
        db.commit()
        return {"status": "0", "message": "OTP expired."}

    if db.query(User).filter(User.email == email).first():
        db.delete(pending_row)
        db.commit()
        return {"status": "0", "message": "Email already registered."}
    if db.query(User).filter(User.username == pending_row.username).first():
        db.delete(pending_row)
        db.commit()
        return {"status": "0", "message": "Username already taken."}

    user = User(
        email=pending_row.email,
        username=pending_row.username,
        password_hash=pending_row.password_hash
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    db.delete(pending_row)
    db.commit()

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
    # Note: DB session is required for OTP persistence
    # Create a short-lived session for this utility endpoint
    db = SessionLocal()
    try:
        pending_row = db.query(SignupOTP).filter(SignupOTP.email == email).first()
        if not pending_row:
            return {
                "status": "0",
                "message": "No pending signup found for this email."
            }

        new_otp = str(random.randint(1000, 9999))
        pending_row.otp = new_otp
        pending_row.expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()

        send_otp_email(email, new_otp)

        return {
            "status": "1",
            "message": "OTP resent to email",
            "result": {"email": email}
        }
    finally:
        db.close()



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
    otp = str(random.randint(1000, 9999))

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




from fastapi import Query

# ---------------- Silent Mode Schedule APIs ---------------- #


from fastapi import FastAPI, Form, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List


# Helper: parse HH:MM (24 hrs)
# def parse_time_24hrs(time_str: str):
#     try:
#         return datetime.strptime(time_str, "%H:%M").time()
#     except ValueError:
#         raise ValueError("Invalid time format. Use HH:MM in 24-hr format (e.g., 13:30)")

def parse_time_24hrs(time_str: str):
    time_str = time_str.strip()  # remove spaces
    
    # Handle various time formats
    time_formats = [
        "%H:%M",        # 13:30
        "%H:%M:%S",     # 13:30:00
        "%H.%M",        # 13.30
        "%H.%M.%S",     # 13.30.00
        "%H %M",        # 13 30
        "%H %M %S",     # 13 30 00
        "%I:%M %p",     # 1:30 PM
        "%I:%M:%S %p",  # 1:30:00 PM
        "%I.%M %p",     # 1.30 PM
        "%I.%M.%S %p",  # 1.30.00 PM
        "%I %M %p",     # 1 30 PM
        "%I %M %S %p",  # 1 30 00 PM
    ]
    
    for fmt in time_formats:
        try:
            parsed_time = datetime.strptime(time_str, fmt).time()
            return parsed_time
        except ValueError:
            continue
    
    # If no format matches, try to extract numbers and construct time
    import re
    numbers = re.findall(r'\d+', time_str)
    if len(numbers) >= 2:
        try:
            hour = int(numbers[0])
            minute = int(numbers[1])
            second = int(numbers[2]) if len(numbers) >= 3 else 0
            
            # Handle 12-hour format if PM/AM is present
            if any(period in time_str.upper() for period in ['AM', 'PM']):
                if 'PM' in time_str.upper() and hour != 12:
                    hour += 12
                elif 'AM' in time_str.upper() and hour == 12:
                    hour = 0
            
            if 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59:
                return datetime.strptime(f"{hour:02d}:{minute:02d}:{second:02d}", "%H:%M:%S").time()
        except (ValueError, IndexError):
            pass
    
    raise ValueError("Invalid time format. Supported formats: HH:MM, HH:MM:SS, HH.MM, 1:30 PM, etc. (e.g., 13:30, 1:30 PM)")




# Helper: check overlap
def time_overlap(start1, end1, start2, end2):
    return max(start1, start2) < min(end1, end2)

# Helper: check if days overlap
def days_overlap(days1: List[str], days2: List[str]):
    return any(day in days2 for day in days1)


# ========================
# CREATE / UPDATE SCHEDULE
# ========================
@app.post("/scheduleTimerData")
def create_schedule(
    userId: int = Form(...),
    from_time: str = Form(...),  # e.g., "09:00"
    to_time: str = Form(...),    # e.g., "17:00"
    days: str = Form(...),       # e.g., "Monday,Tuesday"
    db: Session = Depends(get_db)
):
    # Check if user exists
    user = db.query(User).filter(User.id == userId).first()
    if not user:
        return JSONResponse(status_code=404, content={
            "status": "0",
            "message": "User not found.",
            "results": []
        })

    # Parse times
    try:
        new_from = parse_time_24hrs(from_time)
        new_to = parse_time_24hrs(to_time)
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "0",
            "message": str(e),
            "results": []
        })

    if new_from >= new_to:
        return JSONResponse(status_code=400, content={
            "status": "0",
            "message": "Start time must be before end time.",
            "results": []
        })

    new_days = [d.strip() for d in days.split(",")]

    # Fetch existing schedules
    existing_schedules = db.query(SilentModeSchedule).filter(SilentModeSchedule.user_id == userId).all()

    for sched in existing_schedules:
        existing_days = [d.strip() for d in sched.days.split(",")]
        overlap_days = list(set(new_days) & set(existing_days))  # common days only
        if overlap_days:
            existing_from = parse_time_24hrs(sched.from_time)
            existing_to = parse_time_24hrs(sched.to_time)
            if time_overlap(new_from, new_to, existing_from, existing_to):
                return JSONResponse(status_code=400, content={
                    "status": "0",
                    "message": f"Conflict on days: {', '.join(overlap_days)}",
                    "results": []
                })

    # Create schedule
    schedule = SilentModeSchedule(
        user_id=userId,
        from_time=from_time,
        to_time=to_time,
        days=days,
        active=True
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    return {
        "status": "1",
        "message": "Schedule created successfully",
        "result": {
            "schedule_id": schedule.id,
            "from_time": schedule.from_time,
            "to_time": schedule.to_time,
            "selected_days": schedule.days.split(","),
            "isTimerEnabled": schedule.active
        }
    }


# ============
# DELETE API
# ============
@app.delete("/scheduleTimerData/{schedule_id}")
def delete_schedule(schedule_id: str, userId: int, db: Session = Depends(get_db)):
    schedule = db.query(SilentModeSchedule).filter(
        SilentModeSchedule.id == schedule_id,
        SilentModeSchedule.user_id == userId
    ).first()

    if not schedule:
        return JSONResponse(status_code=404, content={
            "status": "0",
            "message": "Schedule not found.",
            "results": []
        })

    db.delete(schedule)
    db.commit()

    return {
        "status": "1",
        "message": "Schedule deleted successfully",
        "result": {"deleted_schedule_id": schedule_id}
    }



# Get Schedule (only today's records)
@app.get("/get-scheduleTimerData")
def get_schedule(userId: int = Query(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == userId).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    today = datetime.today().strftime("%A")

    schedules = db.query(SilentModeSchedule).filter(
        SilentModeSchedule.user_id == userId
    ).all()

    result = []
    for s in schedules:
        days = [d.strip() for d in s.days.split(",")]
        if "Everyday" in days or today in days:
            result.append({
                "schedule_id": s.id,
                "from_time": s.from_time,
                "to_time": s.to_time,
                "selected_days": days,
                "isTimerEnabled": s.active,
                "event_type": "calendar" if s.is_calendar_event else "custom"
            })

    return {"status": "1", "result": result}



@app.post("/post-timerSchedule")
def toggle_schedule(
    schedule_id: str = Form(...),
    isTimerEnabled: bool = Form(...),
    db: Session = Depends(get_db)
):
    # Normalize ID (UUIDs stored as string in SQLite)
    schedule = db.query(SilentModeSchedule).filter(SilentModeSchedule.id == str(schedule_id)).first()
    if not schedule:
        return {"status": "0", "message": f"Schedule not found for id {schedule_id}"}

    schedule.active = isTimerEnabled
    db.commit()
    db.refresh(schedule)

    return {
        "status": "1",
        "message": "Schedule status updated",
        "result": {
            "schedule_id": schedule.id,
            "isTimerEnabled": schedule.active
        }
    }

@app.post("/logout")
def logout(
    user_id: int = Form(...),  # take user_id from form-urlencoded
    db: Session = Depends(get_db)
):
    # Retrieve user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Update all schedules: set active = False
    schedules = db.query(SilentModeSchedule).filter(SilentModeSchedule.user_id == user.id).all()
    for schedule in schedules:
        schedule.active = False
        db.add(schedule)

    db.commit()

    return {"status": "1", "message": "User logged out. All schedules disabled."}


from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os


# Set MODE = "test" for mock, "live" for real verification
MODE = os.getenv("SOCIAL_LOGIN_MODE", "test")  # default test

# ?? Facebook Credentials (needed only in live mode)
from dotenv import load_dotenv
import os

load_dotenv()  # .env file se env variables load karega

FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


class SocialLoginRequest(BaseModel):
    provider: str
    access_token: str


@app.post("/v1/social-login")
def social_login(payload: SocialLoginRequest):
    provider = payload.provider.lower()
    token = payload.access_token

    # --------------------------
    # TEST MODE (Mock responses)
    # --------------------------
    if MODE == "test":
        if token == "invalid":
            raise HTTPException(status_code=401, detail="Invalid access token (test)")
        return {
            "status": "success",
            "provider": provider,
            "user": {
                "id": "test_12345",
                "name": "Mock User",
                "email": "mockuser@example.com"
            }
        }

    # --------------------------
    # LIVE MODE (Real validation)
    # --------------------------
    if provider == "facebook":
        user_data = verify_facebook_token(token)
    elif provider == "google":
        user_data = verify_google_token(token)
    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    return {
        "status": "success",
        "provider": provider,
        "user": user_data,
    }


# ? Facebook Token Verification (Live mode)
def verify_facebook_token(token: str):
    debug_url = (
        f"https://graph.facebook.com/debug_token?"
        f"input_token={token}&access_token={FACEBOOK_APP_ID}|{FACEBOOK_APP_SECRET}"
    )
    resp = requests.get(debug_url).json()

    if "data" not in resp or not resp["data"].get("is_valid"):
        return None

    user_url = f"https://graph.facebook.com/me?fields=id,name,email&access_token={token}"
    user_info = requests.get(user_url).json()
    return user_info


# ? Google Token Verification (Live mode)
def verify_google_token(token: str):
    try:
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        return {
            "id": idinfo["sub"],
            "email": idinfo.get("email"),
            "name": idinfo.get("name"),
        }
    except Exception:
        return None
    


from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from fastapi.responses import JSONResponse

# Existing utility functions: parse_time_24hrs, time_overlap, get_db
# Models: User, SilentModeSchedule

class ScheduleItem(BaseModel):
    userId: int
    from_time: str  # "09:00"
    to_time: str    # "17:00"
    days: str       # "Monday,Tuesday"

@app.post("/scheduleTimerCalendarEventData")
def create_multiple_schedules(
    schedules: List[ScheduleItem] = Body(...),
    db: Session = Depends(get_db)
):
    created_schedules = []
    failed_schedules = []

    for item in schedules:
        user = db.query(User).filter(User.id == item.userId).first()
        if not user:
            failed_schedules.append({
                "userId": item.userId,
                "message": "User not found."
            })
            continue

        try:
            new_from = parse_time_24hrs(item.from_time)
            new_to = parse_time_24hrs(item.to_time)
        except ValueError as e:
            failed_schedules.append({
                "userId": item.userId,
                "message": str(e)
            })
            continue

        if new_from >= new_to:
            failed_schedules.append({
                "userId": item.userId,
                "message": "Start time must be before end time."
            })
            continue

        new_days = [d.strip() for d in item.days.split(",")]
        existing_schedules = db.query(SilentModeSchedule).filter(SilentModeSchedule.user_id == item.userId).all()

        conflict = False
        for sched in existing_schedules:
            existing_days = [d.strip() for d in sched.days.split(",")]
            overlap_days = list(set(new_days) & set(existing_days))
            if overlap_days:
                existing_from = parse_time_24hrs(sched.from_time)
                existing_to = parse_time_24hrs(sched.to_time)
                if time_overlap(new_from, new_to, existing_from, existing_to):
                    failed_schedules.append({
                        "userId": item.userId,
                        "message": f"Conflict on days: {', '.join(overlap_days)}"
                    })
                    conflict = True
                    break
        if conflict:
            continue
        # create_multiple_schedules (Calendar wali API) me create karte waqt
        schedule = SilentModeSchedule(
            user_id=item.userId,
            from_time=item.from_time,
            to_time=item.to_time,
            days=item.days,
            active=True,
            is_calendar_event=True   # 👈 calendar flag set
        )

        db.add(schedule)
        db.commit()
        db.refresh(schedule)

        created_schedules.append({
            "schedule_id": schedule.id,
            "userId": schedule.user_id,
            "from_time": schedule.from_time,
            "to_time": schedule.to_time,
            "selected_days": schedule.days.split(","),
            "isTimerEnabled": schedule.active
        })

    return {
        "status": "1" if created_schedules else "0",
        "message": "Schedules processed.",
        "created": created_schedules,
        "failed": failed_schedules
    }
