from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from app.auth import create_access_token, hash_password, verify_password
from app.models import TokenData, UserCreate, UserResponse

router = APIRouter()

fake_db = {}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate):
    if user.email in fake_db:
        raise HTTPException(status_code=400, detail="Email already registered")

    fake_db[user.email] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hash_password(user.password),
    }
    return user


@router.post("/token", response_model=TokenData)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}
