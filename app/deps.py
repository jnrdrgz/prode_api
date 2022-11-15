from typing import Generator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from . import models, schemas, security
from .database import SessionLocal

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"/login/access-token"
)

def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(reusable_oauth2)
):
    try:
        #settings.SECRET_KEY
        payload = jwt.decode(
            token, "secret", algorithms=[security.ALGORITHM]
        )
        print("payload", payload)
        token_data = schemas.TokenPayload(**payload)
        print("payload", token_data)
        user_id = payload["sub"].split("-")[0]
        username = payload["sub"].split("-")[1]
        print("payload", user_id, username)
    except (jwt.JWTError, ValidationError):
        print("ERROR")
        #raise HTTPException(
        #    status_code=status.HTTP_403_FORBIDDEN,
        #    detail="Could not validate credentials",
        #)
        return None
    user = db.query(models.User).filter(models.User.id == user_id).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user