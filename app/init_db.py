"""
Initialize the application database.

Creates all tables (users, analysis_results) if they do not already exist.
Does NOT create any default credentials.
"""

from app.database import Base
from app.database import engine

# Import all models so Base.metadata knows about them.
from app.models import User          # noqa: F401
from app.models import AnalysisResult  # noqa: F401


def initialize_database():
    """
    Create all database tables.
    """

    Base.metadata.create_all(
        bind=engine
    )


if __name__ == "__main__":

    initialize_database()

    print(
        "Database initialized successfully."
    )
