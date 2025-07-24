from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Union, Any

#======================= Schemas ==============================#
class RoleEnum(str, Enum):
    admin = "admin"
    user = "user"

class UserBase(BaseModel):
    username: str

class UserLogin(UserBase):
    password: str

class UserRegister(UserBase):
    password: str

class UserInDB(UserBase):
    hash_password: str
    role: RoleEnum

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: str

#======================= Config ===============================#
SECRET_KEY = "abc123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#==================== Fake DB ================================#
db = {
    "1": {
        "username": "Bùi Duy Tuấn Anh",
        "hash_password": "",  # Will be updated below
        "role": RoleEnum.admin
    },
    "2": {
        "username": "Nguyễn Bảo Ngọc",
        "hash_password": "",  # Will be updated below
        "role": RoleEnum.user
    }
}

#=================== Init password hash ======================#
def get_hash_password(password: str):
    return pwd_context.hash(password)

db["1"]["hash_password"] = get_hash_password("adminpassword")
db["2"]["hash_password"] = get_hash_password("userpassword")

#================= Utility Functions =========================#
def verify_password(pwd_input: str, pwd_hash: str):
    return pwd_context.verify(pwd_input, pwd_hash)

def get_user(db, username: str):
    for user in db.values():
        if user["username"] == username:
            return UserInDB(
                username=user["username"],
                hash_password=user["hash_password"],
                role=user["role"]
            )
    return None

def authentic_user(db, username: str, password: str):
    user = get_user(db, username=username)
    if not user:
        return None
    if not verify_password(password, user.hash_password):
        return None
    return user

def create_access_token(subject: dict, expires_delta: Optional[timedelta] = None):
    to_encode = subject.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

#=================== Auth Dependencies =======================#
def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credential_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credential_exception
    user_dict = db.get(token_data.user_id)
    if user_dict is None:
        raise credential_exception
    return UserInDB(
        username=user_dict["username"],
        hash_password=user_dict["hash_password"],
        role=user_dict["role"]
    )

def admin_required(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != RoleEnum.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action"
        )
    return current_user

#=================== FastAPI App =============================#
app = FastAPI()

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authentic_user(
        db=db,
        username=form_data.username,
        password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=404,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = [k for k, v in db.items() if v["username"] == user.username][0]
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        {"sub": user_id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

#=================== Protected Routes ========================#
@app.get("/admin-only")
def read_admin_data(current_user: UserInDB = Depends(admin_required)):
    return {"message": f"Welcome Admin {current_user.username}"}

@app.get("/me")
def read_my_profile(current_user: UserInDB = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}


