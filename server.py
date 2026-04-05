# from dotenv import load_dotenv
# load_dotenv()

from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
import logging
import bcrypt
import jwt
import secrets
import smtplib
import random
import string
import base64
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional, Any
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

MONGO_URL = os.getenv("MONGO_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
DB_NAME = os.getenv("DB_NAME")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*") 
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).parent

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
OTP_EXPIRE_MINUTES = 10

# Create the main app
app = FastAPI(title="Nikita Foundation LMS")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ============== MODELS ==============

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str
    name: Optional[str] = None
    mobile: Optional[str] = None
    password: Optional[str] = None

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    mobile: Optional[str] = None
    role: str
    created_at: datetime

class UserCreateByAdmin(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    password: str
    role: str = "collector"

class SMTPConfig(BaseModel):
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_email: EmailStr
    smtp_password: str

class LogoUpload(BaseModel):
    logo_base64: str  # Base64 encoded image

class LoanApplicationCreate(BaseModel):
    borrower_name: str
    borrower_father_name: str
    borrower_mobile: str
    borrower_email: EmailStr
    borrower_address: str
    loan_amount: float
    total_payable_amount: float
    emi_amount: float
    total_emi: int = 100
    borrow_date: str
    guarantor_name: str
    guarantor_father_name: str
    guarantor_mobile: str
    borrower_signature: Optional[str] = None  # Base64
    guarantor_signature: Optional[str] = None  # Base64
    loan_disbursement_name: str
    emi_penalty_amount: float = 100.0  # Penalty for overdue EMI
    borrower_photo: Optional[str] = None  # Base64 encoded photo

class EMIPayment(BaseModel):
    application_id: str
    emi_no: int
    amount: float
    include_penalty: bool = False

class EMIEdit(BaseModel):
    application_id: str
    emi_no: int
    new_amount: Optional[float] = None
    new_date: Optional[str] = None
    action: str = "edit"  # edit, delete, advance

# ============== HELPER FUNCTIONS ==============

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=6))

def generate_application_number() -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"NF-{timestamp}-{random_part}"

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {
            "id": str(user["_id"]),
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "mobile": user.get("mobile", ""),
            "role": user.get("role", "collector"),
            "created_at": user.get("created_at", datetime.now(timezone.utc))
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(request: Request) -> dict:
    user = await get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def get_smtp_config() -> Optional[dict]:
    config = await db.settings.find_one({"type": "smtp"}, {"_id": 0})
    return config

async def send_email(to_email: str, subject: str, body: str) -> bool:
    try:
        config = await get_smtp_config()
        if not config:
            logger.warning("SMTP not configured, email not sent")
            return False
        
        msg = MIMEMultipart()
        msg['From'] = config['smtp_email']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html', 'utf-8'))
        
        with smtplib.SMTP(config['smtp_host'], config['smtp_port']) as server:
            server.starttls()
            server.login(config['smtp_email'], config['smtp_password'])
            server.send_message(msg)
        
        logger.info(f"Email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

async def send_otp_email(to_email: str, otp: str, purpose: str = "verification") -> bool:
    subject = "Nikita Foundation - OTP Verification"
    body = f"""
    <html>
    <body style="font-family: 'IBM Plex Sans', Arial, sans-serif; background-color: #F9F8F6; padding: 20px;">
        <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 16px; padding: 30px; border: 1px solid #E4E2DC;">
            <h2 style="color: #2C5530; margin-bottom: 20px;">निकीता फाउंडेशन</h2>
            <p style="color: #1C241D;">आपका OTP है:</p>
            <h1 style="color: #C76B41; font-size: 32px; letter-spacing: 8px; text-align: center; padding: 20px; background: #F9F8F6; border-radius: 8px;">{otp}</h1>
            <p style="color: #576459; font-size: 14px;">यह OTP {OTP_EXPIRE_MINUTES} मिनट में समाप्त हो जाएगा।</p>
            <p style="color: #576459; font-size: 12px; margin-top: 20px;">यदि आपने यह अनुरोध नहीं किया है, तो कृपया इस ईमेल को अनदेखा करें।</p>
        </div>
    </body>
    </html>
    """
    return await send_email(to_email, subject, body)

async def send_loan_creation_email(loan: dict) -> bool:
    subject = "निकीता फाउंडेशन - ऋण विवरण"
    body = f"""
    <html>
    <body style="font-family: 'IBM Plex Sans', Arial, sans-serif; background-color: #F9F8F6; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; padding: 30px; border: 1px solid #E4E2DC;">
            <h2 style="color: #2C5530; margin-bottom: 20px;">निकीता फाउंडेशन, निवाई</h2>
            <h3 style="color: #1C241D;">ऋण विवरण</h3>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">आवेदन संख्या:</td>
                    <td style="padding: 10px 0; color: #1C241D; font-weight: bold;">{loan['application_number']}</td>
                </tr>
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">उधारकर्ता का नाम:</td>
                    <td style="padding: 10px 0; color: #1C241D;">{loan['borrower_name']}</td>
                </tr>
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">ऋण राशि:</td>
                    <td style="padding: 10px 0; color: #1C241D;">₹{loan['loan_amount']:,.2f}</td>
                </tr>
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">कुल देय राशि:</td>
                    <td style="padding: 10px 0; color: #1C241D;">₹{loan['total_payable_amount']:,.2f}</td>
                </tr>
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">किश्त राशि:</td>
                    <td style="padding: 10px 0; color: #1C241D;">₹{loan['emi_amount']:,.2f}</td>
                </tr>
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">कुल किश्त:</td>
                    <td style="padding: 10px 0; color: #1C241D;">{loan['total_emi']}</td>
                </tr>
                <tr style="border-bottom: 1px solid #E4E2DC;">
                    <td style="padding: 10px 0; color: #576459;">प्रारंभ तिथि:</td>
                    <td style="padding: 10px 0; color: #1C241D;">{loan['borrow_date']}</td>
                </tr>
            </table>
            
            <div style="background: #F9F8F6; padding: 20px; border-radius: 8px; margin-top: 20px;">
                <h4 style="color: #2C5530; margin-bottom: 15px;">नियम</h4>
                <ol style="color: #576459; font-size: 14px; line-height: 1.8;">
                    <li>अपनी किश्त की राशि प्रतिदिन अदा करें।</li>
                    <li>किश्त देते समय अपने संबंधित अधिकारी से इस पास बुक पर हस्ताक्षर अवश्य लें, अन्यथा किश्त जमा नहीं मानी जाएगी।</li>
                    <li>किसी समस्या के लिए कम्पनी कार्यालय पर संपर्क करें।</li>
                    <li>इस पास बुक को संभालकर रखें।</li>
                    <li>इस पास बुक के खो जाने पर कार्यालय में ₹100 जमा कराने पर ही दूसरी पास बुक प्रदान की जाएगी।</li>
                    <li>ऋण के 100 दिन पूरे होने पर ₹1100 पेनल्टी देनी होगी।</li>
                </ol>
            </div>
            
            <p style="color: #576459; font-size: 12px; margin-top: 20px; text-align: center;">
                धन्यवाद।<br>निकीता फाउंडेशन
            </p>
        </div>
    </body>
    </html>
    """
    return await send_email(loan['borrower_email'], subject, body)

async def send_noc_email(loan: dict) -> bool:
    subject = "ऋण पूर्ण भुगतान प्रमाण पत्र (NOC)"
    body = f"""
    <html>
    <body style="font-family: 'IBM Plex Sans', Arial, sans-serif; background-color: #F9F8F6; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; padding: 30px; border: 1px solid #E4E2DC;">
            <h2 style="color: #2C5530; margin-bottom: 20px;">निकीता फाउंडेशन</h2>
            <h3 style="color: #367B48;">ऋण पूर्ण भुगतान प्रमाण पत्र (NOC)</h3>
            
            <p style="color: #1C241D; line-height: 1.8;">
                प्रिय <strong>{loan['borrower_name']}</strong>,
            </p>
            
            <p style="color: #1C241D; line-height: 1.8;">
                हमें यह सूचित करते हुए खुशी हो रही है कि आपने निकिता फाउंडेशन से लिया गया आपका ऋण पूर्ण रूप से चुका दिया है।
            </p>
            
            <p style="color: #1C241D; line-height: 1.8;">
                आपके द्वारा सभी निर्धारित किश्तों (EMI) का सफलतापूर्वक भुगतान कर दिया गया है और अब आपके ऋण खाते में कोई बकाया राशि शेष नहीं है।
            </p>
            
            <div style="background: #367B48; color: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                <p style="margin: 0; font-size: 18px;">आवेदन संख्या: <strong>{loan['application_number']}</strong></p>
                <p style="margin: 10px 0 0 0;">स्थिति: <strong>बंद (Closed)</strong></p>
            </div>
            
            <p style="color: #1C241D; line-height: 1.8;">
                इस ईमेल के माध्यम से हम आपको यह प्रमाणित करते हैं कि आपका ऋण खाता अब पूरी तरह से बंद (Closed) कर दिया गया है और आपको "No Objection Certificate (NOC)" प्रदान किया जाता है।
            </p>
            
            <p style="color: #1C241D; line-height: 1.8;">
                हम आपके समय पर भुगतान और सहयोग के लिए आपका धन्यवाद करते हैं।
            </p>
            
            <p style="color: #1C241D; line-height: 1.8;">
                यदि भविष्य में आपको किसी भी प्रकार की सहायता की आवश्यकता हो, तो आप हमसे संपर्क कर सकते हैं।
            </p>
            
            <p style="color: #576459; font-size: 14px; margin-top: 30px;">
                धन्यवाद।<br><br>
                सादर,<br>
                <strong style="color: #2C5530;">निकीता फाउंडेशन</strong>
            </p>
        </div>
    </body>
    </html>
    """
    return await send_email(loan['borrower_email'], subject, body)

# ============== AUTH ROUTES ==============

@api_router.post("/auth/send-otp")
async def send_otp(data: dict, background_tasks: BackgroundTasks):
    email = data.get("email")
    purpose = data.get("purpose", "signup")  # signup, forgot_password
    
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    # For signup, check if user already exists
    if purpose == "signup":
        existing_user = await db.users.find_one({"email": email.lower()})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    # For forgot password, check if user exists
    if purpose == "forgot_password":
        existing_user = await db.users.find_one({"email": email.lower()})
        if not existing_user:
            raise HTTPException(status_code=400, detail="Email not found")
    
    # Generate and store OTP
    otp = generate_otp()
    await db.otps.delete_many({"email": email.lower()})
    await db.otps.insert_one({
        "email": email.lower(),
        "otp": otp,
        "purpose": purpose,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
    })
    
    # Send OTP email
    background_tasks.add_task(send_otp_email, email, otp, purpose)
    
    logger.info(f"OTP generated for {email}: {otp}")  # For testing
    return {"message": "OTP sent successfully", "otp_for_testing": otp}  # Remove otp_for_testing in production

@api_router.post("/auth/verify-otp")
async def verify_otp(data: OTPVerify):
    otp_record = await db.otps.find_one({
        "email": data.email.lower(),
        "otp": data.otp
    })
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if datetime.now(timezone.utc) > otp_record["expires_at"].replace(tzinfo=timezone.utc):
        await db.otps.delete_one({"_id": otp_record["_id"]})
        raise HTTPException(status_code=400, detail="OTP expired")
    
    # Delete used OTP
    await db.otps.delete_one({"_id": otp_record["_id"]})
    
    return {"message": "OTP verified successfully", "verified": True}

@api_router.post("/auth/register")
async def register(data: OTPVerify):
    # First verify OTP
    otp_record = await db.otps.find_one({
        "email": data.email.lower(),
        "otp": data.otp,
        "purpose": "signup"
    })
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    if datetime.now(timezone.utc) > otp_record["expires_at"].replace(tzinfo=timezone.utc):
        await db.otps.delete_one({"_id": otp_record["_id"]})
        raise HTTPException(status_code=400, detail="OTP expired")
    
    # Check if required fields are present
    if not data.name or not data.password or not data.mobile:
        raise HTTPException(status_code=400, detail="Name, mobile and password are required")
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": data.email.lower()})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_doc = {
        "name": data.name,
        "email": data.email.lower(),
        "mobile": data.mobile,
        "password_hash": hash_password(data.password),
        "role": "collector",  # Default role for self-registration
        "created_at": datetime.now(timezone.utc),
        "is_active": True
    }
    
    result = await db.users.insert_one(user_doc)
    
    # Delete used OTP
    await db.otps.delete_one({"_id": otp_record["_id"]})
    
    # Create access token
    token = create_access_token(str(result.inserted_id), data.email.lower(), "collector")
    
    response = JSONResponse(content={
        "message": "Registration successful",
        "user": {
            "id": str(result.inserted_id),
            "name": data.name,
            "email": data.email.lower(),
            "mobile": data.mobile,
            "role": "collector"
        },
        "token": token
    })
    response.set_cookie(key="access_token", value=token, httponly=True, secure=False, samesite="lax", max_age=86400, path="/")
    return response

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email.lower()})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is deactivated")
    
    token = create_access_token(str(user["_id"]), user["email"], user.get("role", "collector"))
    
    response = JSONResponse(content={
        "message": "Login successful",
        "user": {
            "id": str(user["_id"]),
            "name": user.get("name", ""),
            "email": user["email"],
            "mobile": user.get("mobile", ""),
            "role": user.get("role", "collector")
        },
        "token": token
    })
    response.set_cookie(key="access_token", value=token, httponly=True, secure=False, samesite="lax", max_age=86400, path="/")
    return response

@api_router.post("/auth/forgot-password")
async def forgot_password(data: ForgotPassword, background_tasks: BackgroundTasks):
    user = await db.users.find_one({"email": data.email.lower()})
    if not user:
        raise HTTPException(status_code=400, detail="Email not found")
    
    # Generate and store OTP
    otp = generate_otp()
    await db.otps.delete_many({"email": data.email.lower(), "purpose": "forgot_password"})
    await db.otps.insert_one({
        "email": data.email.lower(),
        "otp": otp,
        "purpose": "forgot_password",
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
    })
    
    background_tasks.add_task(send_otp_email, data.email, otp, "forgot_password")
    
    logger.info(f"Password reset OTP for {data.email}: {otp}")
    return {"message": "OTP sent successfully", "otp_for_testing": otp}

@api_router.post("/auth/reset-password")
async def reset_password(data: ResetPassword):
    otp_record = await db.otps.find_one({
        "email": data.email.lower(),
        "otp": data.otp,
        "purpose": "forgot_password"
    })
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if datetime.now(timezone.utc) > otp_record["expires_at"].replace(tzinfo=timezone.utc):
        await db.otps.delete_one({"_id": otp_record["_id"]})
        raise HTTPException(status_code=400, detail="OTP expired")
    
    # Update password
    await db.users.update_one(
        {"email": data.email.lower()},
        {"$set": {"password_hash": hash_password(data.new_password)}}
    )
    
    # Delete used OTP
    await db.otps.delete_one({"_id": otp_record["_id"]})
    
    return {"message": "Password reset successful"}

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {"user": user}

@api_router.post("/auth/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key="access_token", path="/")
    return response

# ============== USER MANAGEMENT ROUTES (Admin) ==============

@api_router.get("/users")
async def get_users(admin: dict = Depends(get_admin_user)):
    users = await db.users.find({}, {"password_hash": 0}).to_list(1000)
    result = []
    for user in users:
        result.append({
            "id": str(user["_id"]),
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "mobile": user.get("mobile", ""),
            "role": user.get("role", "collector"),
            "is_active": user.get("is_active", True),
            "created_at": user.get("created_at", datetime.now(timezone.utc)).isoformat()
        })
    return {"users": result}

@api_router.post("/users")
async def create_user(data: UserCreateByAdmin, admin: dict = Depends(get_admin_user)):
    existing = await db.users.find_one({"email": data.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    user_doc = {
        "name": data.name,
        "email": data.email.lower(),
        "mobile": data.mobile,
        "password_hash": hash_password(data.password),
        "role": data.role,
        "is_active": True,
        "created_at": datetime.now(timezone.utc)
    }
    
    result = await db.users.insert_one(user_doc)
    
    return {
        "message": "User created successfully",
        "user": {
            "id": str(result.inserted_id),
            "name": data.name,
            "email": data.email.lower(),
            "mobile": data.mobile,
            "role": data.role
        }
    }

@api_router.put("/users/{user_id}")
async def update_user(user_id: str, data: dict, admin: dict = Depends(get_admin_user)):
    update_data = {}
    if "name" in data:
        update_data["name"] = data["name"]
    if "mobile" in data:
        update_data["mobile"] = data["mobile"]
    if "role" in data:
        update_data["role"] = data["role"]
    if "is_active" in data:
        update_data["is_active"] = data["is_active"]
    if "password" in data and data["password"]:
        update_data["password_hash"] = hash_password(data["password"])
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User updated successfully"}

@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.users.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}

# ============== SETTINGS ROUTES (Admin) ==============

@api_router.get("/settings/smtp")
async def get_smtp_settings(admin: dict = Depends(get_admin_user)):
    config = await db.settings.find_one({"type": "smtp"}, {"_id": 0})
    if config:
        config.pop("smtp_password", None)  # Don't send password
    return {"config": config}

@api_router.post("/settings/smtp")
async def save_smtp_settings(config: SMTPConfig, admin: dict = Depends(get_admin_user)):
    await db.settings.update_one(
        {"type": "smtp"},
        {"$set": {
            "type": "smtp",
            "smtp_host": config.smtp_host,
            "smtp_port": config.smtp_port,
            "smtp_email": config.smtp_email,
            "smtp_password": config.smtp_password,
            "updated_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )
    return {"message": "SMTP settings saved successfully"}

@api_router.post("/settings/smtp/test")
async def test_smtp(admin: dict = Depends(get_admin_user)):
    config = await get_smtp_config()
    if not config:
        raise HTTPException(status_code=400, detail="SMTP not configured")
    
    try:
        with smtplib.SMTP(config['smtp_host'], config['smtp_port']) as server:
            server.starttls()
            server.login(config['smtp_email'], config['smtp_password'])
        return {"message": "SMTP connection successful"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"SMTP test failed: {str(e)}")

@api_router.get("/settings/logo")
async def get_logo():
    logo = await db.settings.find_one({"type": "logo"}, {"_id": 0})
    default_logo = "https://static.prod-images.emergentagent.com/jobs/04df6465-0ae2-4c67-a040-007b8dd7bc4b/images/5182ef1626dd29657c0bc411a5a888354abad8edd935a9fcca25f530b6c3042d.png"
    return {"logo_url": logo.get("logo_base64") if logo else default_logo}

@api_router.post("/settings/logo")
async def upload_logo(data: LogoUpload, admin: dict = Depends(get_admin_user)):
    await db.settings.update_one(
        {"type": "logo"},
        {"$set": {
            "type": "logo",
            "logo_base64": data.logo_base64,
            "updated_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )
    return {"message": "Logo uploaded successfully"}

# ============== LOAN APPLICATION ROUTES ==============

@api_router.post("/loans")
async def create_loan(data: LoanApplicationCreate, background_tasks: BackgroundTasks, user: dict = Depends(get_admin_user)):
    application_number = generate_application_number()
    
    # Generate EMI schedule based on borrow_date
    borrow_date = datetime.strptime(data.borrow_date, "%Y-%m-%d")
    emi_schedule = []
    for i in range(data.total_emi):
        emi_date = borrow_date + timedelta(days=i)
        emi_schedule.append({
            "emi_no": i + 1,
            "due_date": emi_date.strftime("%Y-%m-%d"),
            "amount": data.emi_amount,
            "status": "pending",  # pending, paid, overdue
            "paid_at": None,
            "collected_by": None,
            "collector_id": None,
            "penalty_applied": False,
            "penalty_amount": 0
        })
    
    loan_doc = {
        "application_number": application_number,
        "borrower_name": data.borrower_name,
        "borrower_father_name": data.borrower_father_name,
        "borrower_mobile": data.borrower_mobile,
        "borrower_email": data.borrower_email,
        "borrower_address": data.borrower_address,
        "loan_amount": data.loan_amount,
        "total_payable_amount": data.total_payable_amount,
        "emi_amount": data.emi_amount,
        "total_emi": data.total_emi,
        "paid_emi": 0,
        "remaining_emi": data.total_emi,
        "borrow_date": data.borrow_date,
        "guarantor_name": data.guarantor_name,
        "guarantor_father_name": data.guarantor_father_name,
        "guarantor_mobile": data.guarantor_mobile,
        "borrower_signature": data.borrower_signature,
        "guarantor_signature": data.guarantor_signature,
        "borrower_photo": data.borrower_photo,
        "loan_disbursement_name": data.loan_disbursement_name,
        "emi_penalty_amount": data.emi_penalty_amount,
        "status": "running",
        "emi_schedule": emi_schedule,
        "emi_history": [],
        "created_by": user["id"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    
    result = await db.loans.insert_one(loan_doc)
    loan_doc["_id"] = str(result.inserted_id)
    
    # Send loan creation email
    background_tasks.add_task(send_loan_creation_email, loan_doc)
    
    return {
        "message": "Loan application created successfully",
        "loan": {
            "id": str(result.inserted_id),
            "application_number": application_number,
            "borrower_name": data.borrower_name,
            "loan_amount": data.loan_amount,
            "status": "running"
        }
    }

@api_router.get("/loans")
async def get_loans(
    status: Optional[str] = None,
    search: Optional[str] = None,
    due_only: bool = False,
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_current_user)
):
    query = {}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    if status and status != "all":
        query["status"] = status
    
    if due_only:
        # Find loans with overdue EMIs
        query["status"] = "running"
        query["emi_schedule"] = {
            "$elemMatch": {
                "status": "pending",
                "due_date": {"$lt": today}
            }
        }
    
    if search:
        query["$or"] = [
            {"application_number": {"$regex": search, "$options": "i"}},
            {"borrower_name": {"$regex": search, "$options": "i"}},
            {"borrower_mobile": {"$regex": search, "$options": "i"}}
        ]
    
    skip = (page - 1) * limit
    total = await db.loans.count_documents(query)
    
    loans = await db.loans.find(query, {"borrower_signature": 0, "guarantor_signature": 0, "borrower_photo": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for loan in loans:
        # Count due EMIs
        due_emi_count = 0
        emi_schedule = loan.get("emi_schedule", [])
        for emi in emi_schedule:
            if emi.get("status") == "pending" and emi.get("due_date", "") < today:
                due_emi_count += 1
        
        result.append({
            "id": str(loan["_id"]),
            "application_number": loan.get("application_number", ""),
            "borrower_name": loan.get("borrower_name", ""),
            "borrower_mobile": loan.get("borrower_mobile", ""),
            "loan_amount": loan.get("loan_amount", 0),
            "total_payable_amount": loan.get("total_payable_amount", 0),
            "emi_amount": loan.get("emi_amount", 0),
            "emi_penalty_amount": loan.get("emi_penalty_amount", 100),
            "total_emi": loan.get("total_emi", 100),
            "paid_emi": loan.get("paid_emi", 0),
            "remaining_emi": loan.get("remaining_emi", 100),
            "due_emi_count": due_emi_count,
            "status": loan.get("status", "running"),
            "borrow_date": loan.get("borrow_date", ""),
            "created_at": loan.get("created_at", datetime.now(timezone.utc)).isoformat()
        })
    
    return {
        "loans": result,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit
    }

@api_router.get("/loans/{loan_id}")
async def get_loan(loan_id: str, user: dict = Depends(get_current_user)):
    loan = await db.loans.find_one({"_id": ObjectId(loan_id)})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    emi_schedule = loan.get("emi_schedule", [])
    
    # Update EMI schedule with penalty info
    for emi in emi_schedule:
        if emi.get("status") == "pending" and emi.get("due_date", "") < today:
            emi["is_overdue"] = True
            if not emi.get("penalty_applied"):
                emi["penalty_amount"] = loan.get("emi_penalty_amount", 100)
        else:
            emi["is_overdue"] = False
    
    return {
        "loan": {
            "id": str(loan["_id"]),
            "application_number": loan.get("application_number", ""),
            "borrower_name": loan.get("borrower_name", ""),
            "borrower_father_name": loan.get("borrower_father_name", ""),
            "borrower_mobile": loan.get("borrower_mobile", ""),
            "borrower_email": loan.get("borrower_email", ""),
            "borrower_address": loan.get("borrower_address", ""),
            "loan_amount": loan.get("loan_amount", 0),
            "total_payable_amount": loan.get("total_payable_amount", 0),
            "emi_amount": loan.get("emi_amount", 0),
            "emi_penalty_amount": loan.get("emi_penalty_amount", 100),
            "total_emi": loan.get("total_emi", 100),
            "paid_emi": loan.get("paid_emi", 0),
            "remaining_emi": loan.get("remaining_emi", 100),
            "borrow_date": loan.get("borrow_date", ""),
            "guarantor_name": loan.get("guarantor_name", ""),
            "guarantor_father_name": loan.get("guarantor_father_name", ""),
            "guarantor_mobile": loan.get("guarantor_mobile", ""),
            "borrower_signature": loan.get("borrower_signature"),
            "guarantor_signature": loan.get("guarantor_signature"),
            "borrower_photo": loan.get("borrower_photo"),
            "loan_disbursement_name": loan.get("loan_disbursement_name", ""),
            "status": loan.get("status", "running"),
            "emi_schedule": emi_schedule,
            "emi_history": loan.get("emi_history", []),
            "created_at": loan.get("created_at", datetime.now(timezone.utc)).isoformat()
        }
    }

@api_router.get("/loans/search/{query}")
async def search_loans(query: str, user: dict = Depends(get_current_user)):
    search_query = {
        "$or": [
            {"application_number": {"$regex": query, "$options": "i"}},
            {"borrower_name": {"$regex": query, "$options": "i"}},
            {"borrower_mobile": {"$regex": query, "$options": "i"}}
        ]
    }
    
    loans = await db.loans.find(search_query, {"emi_history": 0, "borrower_signature": 0, "guarantor_signature": 0}).limit(20).to_list(20)
    
    result = []
    for loan in loans:
        result.append({
            "id": str(loan["_id"]),
            "application_number": loan.get("application_number", ""),
            "borrower_name": loan.get("borrower_name", ""),
            "borrower_mobile": loan.get("borrower_mobile", ""),
            "loan_amount": loan.get("loan_amount", 0),
            "status": loan.get("status", "running")
        })
    
    return {"loans": result}

# ============== EMI ROUTES ==============

@api_router.post("/emi/pay")
async def mark_emi_paid(data: EMIPayment, background_tasks: BackgroundTasks, user: dict = Depends(get_current_user)):
    loan = await db.loans.find_one({"_id": ObjectId(data.application_id)})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    
    if loan.get("status") == "closed":
        raise HTTPException(status_code=400, detail="Loan is already closed")
    
    emi_schedule = loan.get("emi_schedule", [])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    # Find the specific EMI
    emi_index = data.emi_no - 1
    if emi_index < 0 or emi_index >= len(emi_schedule):
        raise HTTPException(status_code=400, detail="Invalid EMI number")
    
    emi = emi_schedule[emi_index]
    if emi.get("status") == "paid":
        raise HTTPException(status_code=400, detail="This EMI is already paid")
    
    # Calculate penalty if overdue
    penalty_amount = 0
    is_overdue = emi.get("due_date", "") < today
    if is_overdue and data.include_penalty:
        penalty_amount = loan.get("emi_penalty_amount", 100)
    
    total_amount = data.amount + penalty_amount
    
    # Update EMI in schedule
    emi_schedule[emi_index] = {
        **emi,
        "status": "paid",
        "paid_at": datetime.now(timezone.utc).isoformat(),
        "collected_by": user["name"],
        "collector_id": user["id"],
        "penalty_applied": is_overdue and data.include_penalty,
        "penalty_amount": penalty_amount,
        "total_paid": total_amount
    }
    
    new_paid_emi = sum(1 for e in emi_schedule if e.get("status") == "paid")
    new_remaining_emi = loan.get("total_emi", 100) - new_paid_emi
    new_status = "closed" if new_remaining_emi == 0 else "running"
    
    emi_record = {
        "emi_no": data.emi_no,
        "amount": data.amount,
        "penalty_amount": penalty_amount,
        "total_amount": total_amount,
        "collected_by": user["name"],
        "collector_id": user["id"],
        "paid_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.loans.update_one(
        {"_id": ObjectId(data.application_id)},
        {
            "$set": {
                "paid_emi": new_paid_emi,
                "remaining_emi": new_remaining_emi,
                "status": new_status,
                "emi_schedule": emi_schedule,
                "updated_at": datetime.now(timezone.utc)
            },
            "$push": {"emi_history": emi_record}
        }
    )
    
    # Record daily collection
    collection_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    await db.daily_collections.update_one(
        {"date": collection_date, "collector_id": user["id"]},
        {
            "$inc": {"total_amount": total_amount, "emi_count": 1},
            "$set": {
                "collector_name": user["name"],
                "updated_at": datetime.now(timezone.utc)
            },
            "$push": {
                "collections": {
                    "loan_id": data.application_id,
                    "emi_no": data.emi_no,
                    "amount": total_amount,
                    "time": datetime.now(timezone.utc).isoformat()
                }
            }
        },
        upsert=True
    )
    
    # If loan is closed, send NOC email
    if new_status == "closed":
        loan["application_number"] = loan.get("application_number", "")
        loan["borrower_name"] = loan.get("borrower_name", "")
        loan["borrower_email"] = loan.get("borrower_email", "")
        background_tasks.add_task(send_noc_email, loan)
    
    return {
        "message": "EMI marked as paid",
        "emi_no": data.emi_no,
        "amount": data.amount,
        "penalty_amount": penalty_amount,
        "total_amount": total_amount,
        "paid_emi": new_paid_emi,
        "remaining_emi": new_remaining_emi,
        "status": new_status
    }

@api_router.put("/emi/edit")
async def edit_emi(data: EMIEdit, user: dict = Depends(get_admin_user)):
    loan = await db.loans.find_one({"_id": ObjectId(data.application_id)})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    
    emi_schedule = loan.get("emi_schedule", [])
    emi_index = data.emi_no - 1
    
    if emi_index < 0 or emi_index >= len(emi_schedule):
        raise HTTPException(status_code=400, detail="Invalid EMI number")
    
    if data.action == "delete":
        # Reset EMI to pending (undo payment)
        if emi_schedule[emi_index].get("status") != "paid":
            raise HTTPException(status_code=400, detail="EMI is not paid yet")
        
        emi_schedule[emi_index] = {
            "emi_no": data.emi_no,
            "due_date": emi_schedule[emi_index].get("due_date"),
            "amount": loan.get("emi_amount", 0),
            "status": "pending",
            "paid_at": None,
            "collected_by": None,
            "collector_id": None,
            "penalty_applied": False,
            "penalty_amount": 0
        }
        
        # Remove from history
        emi_history = [e for e in loan.get("emi_history", []) if e.get("emi_no") != data.emi_no]
        
        new_paid_emi = sum(1 for e in emi_schedule if e.get("status") == "paid")
        new_remaining_emi = loan.get("total_emi", 100) - new_paid_emi
        
        await db.loans.update_one(
            {"_id": ObjectId(data.application_id)},
            {
                "$set": {
                    "paid_emi": new_paid_emi,
                    "remaining_emi": new_remaining_emi,
                    "status": "running",
                    "emi_schedule": emi_schedule,
                    "emi_history": emi_history,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )
        
        return {"message": "EMI payment deleted successfully"}
    
    elif data.action == "edit":
        # Edit EMI details
        if data.new_amount is not None:
            emi_schedule[emi_index]["amount"] = data.new_amount
        if data.new_date is not None:
            emi_schedule[emi_index]["due_date"] = data.new_date
        
        await db.loans.update_one(
            {"_id": ObjectId(data.application_id)},
            {"$set": {"emi_schedule": emi_schedule, "updated_at": datetime.now(timezone.utc)}}
        )
        
        return {"message": "EMI updated successfully"}
    
    raise HTTPException(status_code=400, detail="Invalid action")

@api_router.get("/emi/schedule/{loan_id}")
async def get_emi_schedule(loan_id: str, user: dict = Depends(get_current_user)):
    loan = await db.loans.find_one({"_id": ObjectId(loan_id)})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    emi_schedule = loan.get("emi_schedule", [])
    
    # Add overdue status and penalty info
    for emi in emi_schedule:
        if emi.get("status") == "pending" and emi.get("due_date", "") < today:
            emi["is_overdue"] = True
            emi["penalty_amount"] = loan.get("emi_penalty_amount", 100)
        else:
            emi["is_overdue"] = False
            if emi.get("status") == "pending":
                emi["penalty_amount"] = 0
    
    return {
        "application_number": loan.get("application_number", ""),
        "borrower_name": loan.get("borrower_name", ""),
        "emi_amount": loan.get("emi_amount", 0),
        "emi_penalty_amount": loan.get("emi_penalty_amount", 100),
        "emi_schedule": emi_schedule
    }

@api_router.get("/emi/history/{loan_id}")
async def get_emi_history(loan_id: str, user: dict = Depends(get_current_user)):
    loan = await db.loans.find_one({"_id": ObjectId(loan_id)}, {"emi_history": 1, "application_number": 1, "borrower_name": 1})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    
    return {
        "application_number": loan.get("application_number", ""),
        "borrower_name": loan.get("borrower_name", ""),
        "emi_history": loan.get("emi_history", [])
    }

@api_router.get("/collections/daily")
async def get_daily_collections(
    date: Optional[str] = None,
    collector_id: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    query = {"date": date}
    if collector_id:
        query["collector_id"] = collector_id
    elif user["role"] != "admin":
        # Non-admin can only see their own collections
        query["collector_id"] = user["id"]
    
    collections = await db.daily_collections.find(query, {"_id": 0}).to_list(100)
    
    total_collected = sum(c.get("total_amount", 0) for c in collections)
    total_emis = sum(c.get("emi_count", 0) for c in collections)
    
    return {
        "date": date,
        "collections": collections,
        "total_collected": total_collected,
        "total_emis": total_emis
    }

# ============== DASHBOARD ROUTES ==============

@api_router.get("/dashboard/stats")
async def get_dashboard_stats(user: dict = Depends(get_current_user)):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    total_applications = await db.loans.count_documents({})
    running_applications = await db.loans.count_documents({"status": "running"})
    closed_applications = await db.loans.count_documents({"status": "closed"})
    
    # Count loans with due EMIs
    due_emi_query = {
        "status": "running",
        "emi_schedule": {
            "$elemMatch": {
                "status": "pending",
                "due_date": {"$lt": today}
            }
        }
    }
    due_emi_applications = await db.loans.count_documents(due_emi_query)
    
    # Calculate total loan amount
    pipeline = [{"$group": {"_id": None, "total": {"$sum": "$loan_amount"}}}]
    total_loan_result = await db.loans.aggregate(pipeline).to_list(1)
    total_loan_amount = total_loan_result[0]["total"] if total_loan_result else 0
    
    # Calculate total pending EMI amount
    pipeline_pending = [
        {"$match": {"status": "running"}},
        {"$project": {"pending_amount": {"$multiply": ["$remaining_emi", "$emi_amount"]}}},
        {"$group": {"_id": None, "total": {"$sum": "$pending_amount"}}}
    ]
    pending_result = await db.loans.aggregate(pipeline_pending).to_list(1)
    pending_emi_amount = pending_result[0]["total"] if pending_result else 0
    
    # Calculate total collected amount
    pipeline_collected = [
        {"$project": {"collected": {"$multiply": ["$paid_emi", "$emi_amount"]}}},
        {"$group": {"_id": None, "total": {"$sum": "$collected"}}}
    ]
    collected_result = await db.loans.aggregate(pipeline_collected).to_list(1)
    total_collected = collected_result[0]["total"] if collected_result else 0
    
    # Get today's collection
    today_collection = await db.daily_collections.aggregate([
        {"$match": {"date": today}},
        {"$group": {"_id": None, "total": {"$sum": "$total_amount"}, "count": {"$sum": "$emi_count"}}}
    ]).to_list(1)
    today_collected = today_collection[0]["total"] if today_collection else 0
    today_emi_count = today_collection[0]["count"] if today_collection else 0
    
    return {
        "total_applications": total_applications,
        "running_applications": running_applications,
        "closed_applications": closed_applications,
        "due_emi_applications": due_emi_applications,
        "total_loan_amount": total_loan_amount,
        "pending_emi_amount": pending_emi_amount,
        "total_collected": total_collected,
        "today_collected": today_collected,
        "today_emi_count": today_emi_count
    }

@api_router.get("/dashboard/recent")
async def get_recent_activities(user: dict = Depends(get_current_user)):
    # Recent loans
    recent_loans = await db.loans.find({}, {"emi_history": 0, "borrower_signature": 0, "guarantor_signature": 0}).sort("created_at", -1).limit(5).to_list(5)
    
    loans = []
    for loan in recent_loans:
        loans.append({
            "id": str(loan["_id"]),
            "application_number": loan.get("application_number", ""),
            "borrower_name": loan.get("borrower_name", ""),
            "loan_amount": loan.get("loan_amount", 0),
            "status": loan.get("status", "running"),
            "created_at": loan.get("created_at", datetime.now(timezone.utc)).isoformat()
        })
    
    return {"recent_loans": loans}

# ============== ROOT ROUTE ==============

@api_router.get("/")
async def root():
    return {"message": "Nikita Foundation LMS API", "version": "1.0.0"}

# Include the router in the main app
app.include_router(api_router)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event
@app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.otps.create_index("expires_at", expireAfterSeconds=0)
    await db.loans.create_index("application_number", unique=True)
    await db.loans.create_index("borrower_mobile")
    await db.loans.create_index("borrower_name")
    
    # Seed admin user
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@nikitafoundation.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@123")
    
    existing_admin = await db.users.find_one({"email": admin_email})
    if not existing_admin:
        await db.users.insert_one({
            "name": "Admin",
            "email": admin_email,
            "mobile": "9999999999",
            "password_hash": hash_password(admin_password),
            "role": "admin",
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        })
        logger.info(f"Admin user created: {admin_email}")
    
    # Write test credentials
    try:
        os.makedirs("/app/memory", exist_ok=True)
        with open("/app/memory/test_credentials.md", "w") as f:
            f.write(f"# Test Credentials\n\n")
            f.write(f"## Admin\n")
            f.write(f"- Email: {admin_email}\n")
            f.write(f"- Password: {admin_password}\n")
            f.write(f"- Role: admin\n\n")
            f.write(f"## API Endpoints\n")
            f.write(f"- Login: POST /api/auth/login\n")
            f.write(f"- Register: POST /api/auth/register\n")
            f.write(f"- Dashboard: GET /api/dashboard/stats\n")
    except Exception as e:
        logger.error(f"Failed to write test credentials: {e}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
