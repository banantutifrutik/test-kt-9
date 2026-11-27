from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles # <-- Добавили для фронтенда

app = FastAPI()
security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET = "secret"
ALGO = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS = {}

class RegisterReq(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)
    email: EmailStr
    name: str

class LoginReq(BaseModel):
    username: str
    password: str

class ProfileRes(BaseModel):
    username: str
    email: EmailStr
    name: str

class UpdateReq(BaseModel):
    email: EmailStr | None = None
    name: str | None = None

def get_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401)
    try:
        payload = jwt.decode(creds.credentials, SECRET, algorithms=[ALGO])
        username = payload.get("sub")
        if username not in USERS:
            raise HTTPException(status_code=401)
        return username
    except JWTError:
        raise HTTPException(status_code=401)

@app.post("/api/register", status_code=201)
async def register(data: RegisterReq):
    if data.username in USERS:
        raise HTTPException(status_code=409, detail="User exists")
    USERS[data.username] = {
        "username": data.username,
        "password_hash": pwd_context.hash(data.password),
        "email": data.email,
        "name": data.name
    }
    token = jwt.encode({"sub": data.username, "exp": datetime.now(timezone.utc) + timedelta(minutes=30)}, SECRET, algorithm=ALGO)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/login")
async def login(data: LoginReq):
    user = USERS.get(data.username)
    if not user or not pwd_context.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401)
    token = jwt.encode({"sub": data.username, "exp": datetime.now(timezone.utc) + timedelta(minutes=30)}, SECRET, algorithm=ALGO)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/profile", response_model=ProfileRes)
async def get_profile(username: str = Depends(get_user)):
    u = USERS[username]
    return ProfileRes(username=u["username"], email=u["email"], name=u["name"])

@app.put("/api/profile", response_model=ProfileRes)
async def update_profile(data: UpdateReq, username: str = Depends(get_user)):
    u = USERS[username]
    if data.email: u["email"] = data.email
    if data.name: u["name"] = data.name
    return ProfileRes(username=u["username"], email=u["email"], name=u["name"])

# --- ВОТ ЭТА СТРОКА РАЗДАЕТ ФРОНТЕНД ---
app.mount("/", StaticFiles(directory=".", html=True), name="static")