from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime
from datetime import datetime, timezone
from pydantic import BaseModel, EmailStr, Field as PydanticField
from typing import Optional, Literal, Dict, Any
import uuid

from enum import Enum

class UserRole(str, Enum):
    USER = 'user'
    ADMIN = 'admin'

class UserBase(SQLModel):
    username: str = Field(nullable=False, unique=True, index=True)
    email: EmailStr = Field(nullable=False, unique=True, index=True)

class User(UserBase, table=True):
    uid: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    hashed_password: str = Field(nullable=False)
    role: UserRole = Field(default=UserRole.USER, nullable=False)
    email_verified: bool = Field(default=False)
    email_verification_code_hash: str | None = Field(default=None, max_length=64)
    email_verification_attempts: int = Field(default=0, nullable=False)
    email_verification_expires_at: datetime | None = Field(
    default=None,
    sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    # created_at: datetime | None = Field(default_factory=datetime.now)
    # updated_at: datetime | None = Field(default_factory=datetime.now, sa_column_kwargs={"onupdate": datetime.now})
    # Timezone-aware UTC default factories
    created_at: datetime = Field(
    default_factory=lambda: datetime.now(timezone.utc),
    sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
    default_factory=lambda: datetime.now(timezone.utc),
    sa_column=Column(
        DateTime(timezone=True),
        nullable=False,
        onupdate=lambda: datetime.now(timezone.utc),
        ),
    )
                                

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    uid: uuid.UUID
    role: str
    email_verified: bool

class UserLoginBase(BaseModel):
    username: str
    password: str


class EmailVerificationRequest(BaseModel):
    user_id: uuid.UUID
    code: str = PydanticField(pattern=r"^\d{6}$")


class EmailVerificationResendRequest(BaseModel):
    email: EmailStr

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: Optional[int] = None  # seconds until access token expiry (optional)

class AccessTokenPayload(BaseModel):
    sub: str
    iss: Optional[str]
    exp: int
    type: Literal["access"]
    jti: Optional[str] = None
    role: Optional[str] = None
    extra_claims: Optional[Dict[str, Any]] = None  # additional custom claims

class RefreshTokenPayload(BaseModel):
    sub: str
    iss: Optional[str]
    exp: int
    type: Literal["refresh"]
    jti: Optional[str] = None
    extra_claims: Optional[Dict[str, Any]] = None
