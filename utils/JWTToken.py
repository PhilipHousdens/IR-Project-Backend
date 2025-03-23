import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import HTTPException
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError, ImmatureSignatureError
import secrets
from starlette import status

# Secret key for encoding and decoding JWT tokens
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expiry in minutes


# Function to create JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    expire = datetime.now() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    to_encode = data.copy()
    to_encode.update({
        "exp": expire,
        # "iat": datetime.now(),  # Issued at claim
        "sub": str(data.get("sub"))  # Optionally add the "sub" claim (e.g., user ID)
    })

    print(datetime.now())

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Token generation success debug line, can be removed in production
    print(f"Generated token: {encoded_jwt}")

    return encoded_jwt


# Function to verify JWT token
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], leeway=60)

        if 'sub' not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is missing 'sub' claim",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload
    except Exception as e:
        print(f"JWT decode error: {e}")
        print(f"Exception: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
