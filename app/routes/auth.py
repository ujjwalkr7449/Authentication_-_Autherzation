from datetime import datetime, timedelta, timezone
import os

import jwt
from pwdlib import PasswordHash
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User
from app.schemas import UserCreate, UserResponse, Token

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Configure a strong secret in your environment before running.
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Set the JWT_SECRET_KEY environment variable")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")