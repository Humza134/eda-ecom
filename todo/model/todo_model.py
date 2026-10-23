from pydantic import BaseModel
from sqlmodel import Field, SQLModel
from datetime import datetime
import uuid

class TodoBase(SQLModel):
    title: str
    description: str

class Todo(TodoBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    owner_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    created_at: datetime | None = Field(default_factory=datetime.now)
    updated_at: datetime | None = Field(default_factory=datetime.now, sa_column_kwargs={"onupdate": datetime.now})

class TodoCreate(TodoBase):
    pass

class TodoResponse(TodoBase):
    id: uuid.UUID

class TodoUpdate(BaseModel):
    title: str | None = None
    description: str | None = None

class DeleteMessageResponse(BaseModel):
    message: str


