from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr

__all__ = (
    "UserCreate",
    "UserLogin",
    "EditUser"
)


class UserBase(BaseModel):
    username: str
    password: str


class UserCreate(UserBase):
    email: EmailStr


class UserLogin(UserBase):
    ...


class EditUser(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    email: Optional[EmailStr] = None
