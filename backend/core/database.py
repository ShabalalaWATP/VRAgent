from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

# Connection pool settings for multi-user support
# pool_size: number of connections to keep open
# max_overflow: additional connections allowed beyond pool_size
# pool_timeout: seconds to wait for a connection from pool
# pool_recycle: recycle connections after N seconds (prevents stale connections)
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
    pool_size=10,  # Base connections for ~20 concurrent users
    max_overflow=20,  # Allow burst to 30 total connections
    pool_timeout=30,  # Wait up to 30s for connection
    pool_recycle=1800,  # Recycle connections every 30 min
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
