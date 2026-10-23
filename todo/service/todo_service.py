from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select, desc
from model.todo_model import Todo, TodoCreate, TodoUpdate
from uuid import UUID

class TodoService:

    async def get_all_todos_service(self, session: AsyncSession, owner_id: UUID):
        try:
            statement = (
                select(Todo)
                .where(Todo.owner_id == owner_id)
                .order_by(desc(Todo.created_at))
            )
            result = await session.exec(statement)
            todos = result.all()
            return todos
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to retrieve todos",
            ) from e
        
    async def get_user_todos_service(self, session: AsyncSession, owner_id: UUID):
        try:
            statement = select(Todo).where(Todo.owner_id == owner_id)
            result = await session.exec(statement)
            todo = result.all()
            return todo
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to retrieve todos",
            ) from e
        
    async def create_todo_service(self, session: AsyncSession, todo_data: TodoCreate, owner_id: UUID):
        try:
            new_todo = Todo(**todo_data.model_dump(), owner_id=owner_id)
            session.add(new_todo)
            await session.commit()
            await session.refresh(new_todo)
            return new_todo
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to create todo",
            ) from e
        
    async def update_todo_service(
    self,
    session: AsyncSession,
    todo_id: UUID,
    todo_data: TodoUpdate,
    owner_id: UUID,
    ):
        try:
            statement = select(Todo).where(
                Todo.id == todo_id,
                Todo.owner_id == owner_id,
            )

            result = await session.exec(statement)
            todo = result.first()

            if not todo:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Todo not found",
                )

            update_data = todo_data.model_dump(exclude_unset=True)

            for key, value in update_data.items():
                setattr(todo, key, value)

            await session.commit()
            await session.refresh(todo)

            return todo

        except HTTPException:
            raise

        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to update todo",
            ) from e
    async def delete_todo_service(
    self,
    session: AsyncSession,
    todo_id: UUID,
    owner_id: UUID,
    ):
        try:
            statement = select(Todo).where(
                Todo.id == todo_id,
                Todo.owner_id == owner_id,
            )

            result = await session.exec(statement)
            todo = result.first()

            if not todo:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Todo not found",
                )

            await session.delete(todo)
            await session.commit()

            return {
                "message": "Todo deleted successfully"
            }

        except HTTPException:
            raise

        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to delete todo",
            ) from e
