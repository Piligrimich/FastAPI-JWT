from datetime import datetime
from typing import Optional, List


from sqlmodel import Field, SQLModel


__all__ = ("User",)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(nullable=False)
    email: str = Field(nullable=False)
    password: str = Field(nullable=False)
    roles: List[str] = Field(default=[])
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)
    is_active: bool = Field(default=False, nullable=False)
    is_totp_enabled: bool = Field(default=False, nullable=False)
    is_superuser: bool = Field(default=False, nullable=False)
    uuid: str = Field(nullable=False)

