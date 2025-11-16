from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class UserRole(str, Enum):
    student = "student"
    staff = "staff"
    authority = "authority"


class User(BaseModel):
    id: str
    email: str
    username: str
    password: str
    role: UserRole


class UserResponseDto(BaseModel):
    id: str
    email: str
    username: str
    role: UserRole


class SessionToken(BaseModel):
    token: str
    user_id: str
    expires_at: str
