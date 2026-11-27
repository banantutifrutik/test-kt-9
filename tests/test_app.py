import pytest
import httpx
import uuid
from httpx import ASGITransport
from backend.main import app, USERS

@pytest.fixture(autouse=True)
def clear_db():
    USERS.clear()
    yield
    USERS.clear()

@pytest.fixture
async def client():
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

@pytest.fixture
def user_data():
    uid = uuid.uuid4().hex[:8]
    return {
        "username": f"u_{uid}",
        "password": "Str0ngPass!",
        "email": f"{uid}@ex.com",
        "name": "Test User"
    }

@pytest.mark.asyncio
async def test_register(client, user_data):
    r = await client.post("/api/register", json=user_data)
    assert r.status_code == 201
    assert "access_token" in r.json()

@pytest.mark.asyncio
async def test_login(client, user_data):
    await client.post("/api/register", json=user_data)
    r = await client.post("/api/login", json={"username": user_data["username"], "password": user_data["password"]})
    assert r.status_code == 200
    assert "access_token" in r.json()

@pytest.mark.asyncio
async def test_profile(client, user_data):
    r = await client.post("/api/register", json=user_data)
    token = r.json()["access_token"]
    r = await client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == user_data["username"]

@pytest.mark.asyncio
async def test_update_profile(client, user_data):
    r = await client.post("/api/register", json=user_data)
    token = r.json()["access_token"]
    new_data = {"name": "Updated Name"}
    r = await client.put("/api/profile", headers={"Authorization": f"Bearer {token}"}, json=new_data)
    assert r.status_code == 200
    assert r.json()["name"] == "Updated Name"

@pytest.mark.asyncio
async def test_unauthorized(client):
    r = await client.get("/api/profile")
    assert r.status_code == 401