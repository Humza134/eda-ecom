from fastapi import FastAPI, Depends, status, HTTPException
from typing import Annotated
from sqlmodel.ext.asyncio.session import AsyncSession
from database.connection import get_session
from service.todo_service import TodoService
from model.todo_model import TodoCreate, TodoResponse, TodoUpdate, DeleteMessageResponse
from dependencies import get_current_user_id
from uuid import UUID


todo_service = TodoService()

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     await init_db()
#     yield

app = FastAPI(title="Todo API", version="1.0.0")

# health check
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# get all todos
@app.get("/todos", response_model=list[TodoResponse], status_code=status.HTTP_200_OK)
async def get_all_todos(
    session: Annotated[AsyncSession, Depends(get_session)],
    owner_id: Annotated[UUID, Depends(get_current_user_id)],
):
    return await todo_service.get_all_todos_service(session, owner_id)

@app.get("/todos/me", response_model=list[TodoResponse], status_code=status.HTTP_200_OK)
async def get_todo(session: Annotated[AsyncSession, Depends(get_session)], owner_id: Annotated[UUID, Depends(get_current_user_id)]):
    if owner_id is None:
        raise HTTPException(status_code=400, detail="Invalid token details: missing user UUID")
    return await todo_service.get_user_todos_service(session, owner_id)

@app.post("/todos", response_model=TodoResponse, status_code=status.HTTP_201_CREATED)
async def todo_create(todo_data: TodoCreate, session: Annotated[AsyncSession, Depends(get_session)],owner_id: Annotated[UUID, Depends(get_current_user_id)]):
    return await todo_service.create_todo_service(session, todo_data, owner_id)

@app.patch("/todos/{todo_id}", response_model=TodoResponse, status_code=status.HTTP_200_OK)
async def todo_update(todo_id: UUID, todo_data: TodoUpdate, session: Annotated[AsyncSession, Depends(get_session)], owner_id: Annotated[UUID, Depends(get_current_user_id)]):
    return await todo_service.update_todo_service(session, todo_id, todo_data, owner_id)

@app.delete("/todos/{todo_id}", response_model=DeleteMessageResponse, status_code=status.HTTP_200_OK)
async def todo_delete(todo_id: UUID, session: Annotated[AsyncSession, Depends(get_session)], owner_id: Annotated[UUID, Depends(get_current_user_id)]):
    return await todo_service.delete_todo_service(session, todo_id, owner_id)
