"""
tests/validation/conftest.py

Pytest configuration, fixtures, and execution hooks for the PHISHGUARD automated validation campaign.

Responsibilities:
1. Initialize test database schema and isolated sessions.
2. Provide authenticated user tokens and headers for API contracts.
3. Automatically capture test outcomes into the ValidationCollector.
4. Export multi-format validation reports at test session conclusion.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Generator
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import models, database, auth as auth_utils
from tests.validation.collector import collector, record_test


@pytest.fixture(scope="session", autouse=True)
def init_test_environment():
    """Ensure database schema is created and clean before test execution."""
    database.engine.dispose()
    models.Base.metadata.create_all(bind=database.engine)
    database.ensure_sqlite_schema(database.engine)
    yield


@pytest.fixture(scope="function")
def db_session() -> Generator:
    """Provide an isolated database session per test function."""
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def test_user(db_session) -> models.User:
    """Create and return an isolated test user."""
    uid = uuid.uuid4().hex[:8]
    user = models.User(
        username=f"val_user_{uid}",
        email=f"val_user_{uid}@validation.internal",
        password_hash=auth_utils.hash_password("ValSecurePass123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def auth_headers(test_user) -> dict:
    """Generate authenticated JWT bearer token headers for the test user."""
    token = auth_utils.create_access_token(
        data={"sub": str(test_user.id), "username": test_user.username}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def client() -> TestClient:
    """FastAPI TestClient instance."""
    return TestClient(app)


def pytest_sessionfinish(session, exitstatus):
    """
    Hook called after all tests complete: automatically generates validation reports.
    """
    if collector.records:
        reports = collector.export_all("reports/validation")
        summary = collector.summary()
        print(f"\n========================================================")
        print(f"PHISHGUARD AUTOMATED VALIDATION SUMMARY:")
        print(f"Total: {summary['total']} | PASS: {summary['pass']} | FAIL: {summary['fail']} | BLOCKED: {summary['blocked']} | MANUAL: {summary['manual']}")
        print(f"Reports exported to: {reports['json']}, {reports['md']}, {reports['html']}")
        print(f"========================================================\n")
