from collections.abc import AsyncIterator
from datetime import datetime, timezone
import os
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost/test"
os.environ["JWKS_URL"] = "http://auth-user.test/.well-known/jwks.json"
os.environ["JWT_ISSUER"] = "auth-user.test"
os.environ["JWT_AUDIENCE"] = "todo.test"

from database.connection import get_session
from dependencies import get_current_user_id
from main import app, todo_service
from model.todo_model import Todo, TodoCreate, TodoUpdate
from service.todo_service import TodoService


class QueryResult:
    def __init__(self, todos: list[Todo]) -> None:
        self._todos = todos

    def all(self) -> list[Todo]:
        return self._todos

    def first(self) -> Todo | None:
        return self._todos[0] if self._todos else None


class InMemorySession:
    def __init__(self, todos: list[Todo] | None = None) -> None:
        self.todos = list(todos or [])
        self.executed_statements: list[object] = []
        self.commits = 0
        self.rollbacks = 0

    async def exec(self, statement: object) -> QueryResult:
        self.executed_statements.append(statement)
        parameters = set(statement.compile().params.values())  # type: ignore[attr-defined]
        uuid_parameters = {value for value in parameters if isinstance(value, UUID)}
        matches = [
            todo
            for todo in self.todos
            if todo.owner_id in uuid_parameters
            and (todo.id in uuid_parameters or len(uuid_parameters) == 1)
        ]
        return QueryResult(matches)

    def add(self, todo: Todo) -> None:
        self.todos.append(todo)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, todo: Todo) -> None:
        return None

    async def rollback(self) -> None:
        self.rollbacks += 1

    async def delete(self, todo: Todo) -> None:
        self.todos.remove(todo)


class TodoApiSecurityTests(TestCase):
    def setUp(self) -> None:
        self.session = object()

        async def override_session() -> AsyncIterator[object]:
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_get_todos_rejects_unauthenticated_request(self) -> None:
        with patch.object(
            todo_service,
            "get_all_todos_service",
            new_callable=AsyncMock,
        ) as get_todos:
            response = self.client.get("/todos")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid auth header"})
        get_todos.assert_not_awaited()

    def test_get_todos_rejects_invalid_jwt(self) -> None:
        response = self.client.get(
            "/todos",
            headers={"Authorization": "Bearer not-a-jwt"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid token"})

    def test_other_todo_crud_routes_also_reject_unauthenticated_requests(self) -> None:
        todo_id = uuid4()
        requests = (
            ("get", "/todos/me", None),
            ("post", "/todos", {"title": "New", "description": "Todo"}),
            ("patch", f"/todos/{todo_id}", {"title": "Changed"}),
            ("delete", f"/todos/{todo_id}", None),
        )

        for method, path, body in requests:
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path, json=body)
                self.assertEqual(response.status_code, 401)

    def test_get_todos_passes_authenticated_user_to_service(self) -> None:
        user_id = uuid4()
        own_todo = Todo(
            id=uuid4(),
            owner_id=user_id,
            title="Mine",
            description="Owned by authenticated user",
        )
        app.dependency_overrides[get_current_user_id] = lambda: user_id

        with patch.object(
            todo_service,
            "get_all_todos_service",
            AsyncMock(return_value=[own_todo]),
        ) as get_todos:
            response = self.client.get("/todos")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["id"], str(own_todo.id))
        get_todos.assert_awaited_once_with(self.session, user_id)


class TodoOwnershipServiceTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.service = TodoService()
        self.user_a = uuid4()
        self.user_b = uuid4()
        self.todo_a = Todo(
            id=uuid4(),
            owner_id=self.user_a,
            title="A",
            description="User A todo",
            created_at=datetime.now(timezone.utc),
        )
        self.todo_b = Todo(
            id=uuid4(),
            owner_id=self.user_b,
            title="B",
            description="User B todo",
            created_at=datetime.now(timezone.utc),
        )

    async def test_list_query_returns_only_authenticated_users_todos(self) -> None:
        session = InMemorySession([self.todo_a, self.todo_b])

        result = await self.service.get_all_todos_service(session, self.user_a)  # type: ignore[arg-type]

        self.assertEqual(result, [self.todo_a])
        statement = session.executed_statements[0]
        self.assertIn("todo.owner_id", str(statement))
        self.assertIn(self.user_a, statement.compile().params.values())  # type: ignore[attr-defined]

    async def test_user_cannot_update_another_users_todo(self) -> None:
        session = InMemorySession([self.todo_b])

        with self.assertRaises(HTTPException) as raised:
            await self.service.update_todo_service(
                session,  # type: ignore[arg-type]
                self.todo_b.id,
                TodoUpdate(title="Stolen"),
                self.user_a,
            )

        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(self.todo_b.title, "B")
        self.assertEqual(session.commits, 0)

    async def test_user_cannot_delete_another_users_todo(self) -> None:
        session = InMemorySession([self.todo_b])

        with self.assertRaises(HTTPException) as raised:
            await self.service.delete_todo_service(
                session,  # type: ignore[arg-type]
                self.todo_b.id,
                self.user_a,
            )

        self.assertEqual(raised.exception.status_code, 404)
        self.assertIn(self.todo_b, session.todos)
        self.assertEqual(session.commits, 0)

    async def test_authenticated_user_can_create_update_and_delete_own_todo(self) -> None:
        session = InMemorySession()
        created = await self.service.create_todo_service(
            session,  # type: ignore[arg-type]
            TodoCreate(title="Original", description="Description"),
            self.user_a,
        )

        self.assertEqual(created.owner_id, self.user_a)
        updated = await self.service.update_todo_service(
            session,  # type: ignore[arg-type]
            created.id,
            TodoUpdate(title="Updated"),
            self.user_a,
        )
        self.assertEqual(updated.title, "Updated")

        response = await self.service.delete_todo_service(
            session,  # type: ignore[arg-type]
            created.id,
            self.user_a,
        )
        self.assertEqual(response, {"message": "Todo deleted successfully"})
        self.assertNotIn(created, session.todos)
        self.assertEqual(session.commits, 3)
