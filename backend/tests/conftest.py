"""
Pytest configuration and shared fixtures.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """
    Placeholder for authenticated request headers.
    TODO: Implement test user creation and token generation.
    """
    return {"Authorization": "Bearer test-token"}
