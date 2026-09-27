from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from app.core.config import settings

# SQLite specific configuration for better concurrency
if settings.database_url.startswith("sqlite"):
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
else:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        echo=False,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables, FTS virtual tables and seed default users if empty"""
    from app.models.models import Base as ModelsBase, User, UserRole
    from app.core.security import hash_password
    from sqlalchemy import text
    
    ModelsBase.metadata.create_all(bind=engine)
    
    # Initialize FTS5 virtual table for SQLite
    if "sqlite" in settings.database_url:
        with engine.connect() as conn:
            try:
                conn.execute(text("CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(cve_id, description, cpe_matches);"))
                conn.commit()
            except Exception as e:
                print(f"FTS5 init note: {e}")

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            default_admin = User(
                username="admin",
                email="admin@security.local",
                hashed_password=hash_password("admin123"),
                role=UserRole.ADMIN,
                is_active=True
            )
            default_analyst = User(
                username="analyst",
                email="analyst@security.local",
                hashed_password=hash_password("analyst123"),
                role=UserRole.ANALYST,
                is_active=True
            )
            default_readonly = User(
                username="readonly",
                email="readonly@security.local",
                hashed_password=hash_password("readonly123"),
                role=UserRole.READ_ONLY,
                is_active=True
            )
            db.add_all([default_admin, default_analyst, default_readonly])
            db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()