#Usa o TestClient do FastAPI para testar as rotas sem precisar subir o servidor manualmente.
from fastapi.testclient import TestClient
from app.main import app
import pytest

client = TestClient(app)

@pytest.fixture
def client():
    return TestClient(app)

def test_read_root(client):
    response = client.get("/")
    assert response.status_code == 200
    

def test_health_check():
    r = client.get("/")
    assert r.status_code == 200

def test_findings_retorna_lista():
    r = client.get("/api/findings")
    assert r.status_code == 200
    assert isinstance(r.json(), list)

def test_findigns_error():
    r= client.get("/a")

def test_scan_sem_url_retorna_erro():
    r = client.post("/api/scan")
    assert r.status_code == 410




    