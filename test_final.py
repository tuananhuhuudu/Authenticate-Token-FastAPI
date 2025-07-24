from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Any, Union

#=================== Schemas =================#
class RoleEnum(str, Enum):
    admin = "admin"
    user = "user"

class UserBase(BaseModel):
    username: str

class UserInDB(UserBase):
    hash_password: str
    role: RoleEnum

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: str

#=================== Config ==================#
SECRET_KEY = "abc123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
refresh_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="refresh")

#=================== Fake DB =================#
db = {
    "1": {
        "username": "Bùi Duy Tuấn Anh",
        "hash_password": "",  # sẽ cập nhật
        "role": RoleEnum.admin
    },
    "2": {
        "username": "Nguyễn Bảo Ngọc",
        "hash_password": "",  # sẽ cập nhật
        "role": RoleEnum.user
    }
}

#=================== Init mật khẩu ===========#
def get_hash_password(password: str):
    return pwd_context.hash(password)

db["1"]["hash_password"] = get_hash_password("adminpassword")
db["2"]["hash_password"] = get_hash_password("userpassword")

#=================== Tiện ích =================#
def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def get_user(db, username: str):
    for user in db.values():
        if user["username"] == username:
            return UserInDB(
                username=user["username"],
                hash_password=user["hash_password"],
                role=user["role"]
            )
    return None

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.hash_password):
        return None
    return user

def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_token_pair(user_id: str):
    access_token = create_token(
        {"sub": user_id}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_token(
        {"sub": user_id}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    return access_token, refresh_token

#=================== Auth ===================#
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user_data = db.get(user_id)
        if user_data is None:
            raise credentials_exception
        return UserInDB(**user_data)
    except JWTError:
        raise credentials_exception

def admin_required(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != RoleEnum.admin:
        raise HTTPException(
            status_code=403, detail="Admin only"
        )
    return current_user

#=================== App ===================#
app = FastAPI()

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(401, "Incorrect username or password")

    user_id = [uid for uid, u in db.items() if u["username"] == user.username][0]
    access_token, refresh_token = create_token_pair(user_id)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh", response_model=Token)
def refresh_token(refresh_token: str = Depends(refresh_oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None or user_id not in db:
            raise credentials_exception
        new_access_token, new_refresh_token = create_token_pair(user_id)
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
    except JWTError:
        raise credentials_exception

@app.get("/me")
def read_me(current_user: UserInDB = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "role": current_user.role
    }

@app.get("/admin-only")
def admin_route(current_user: UserInDB = Depends(admin_required)):
    return {"message": f"Hello admin {current_user.username}"}
