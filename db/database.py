from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

#1. connection string
SQLALCHEMY_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/soc_db'

#2. Engine (physical connection to postgres)
engine = create_engine(SQLALCHEMY_DATABASE_URL)

#3. Session (temporary workspace for saving data)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#4. Base (master blueprint that our models will inherit from)
Base = declarative_base()

#5. Dependency Injection (provides a database session to FastAPI routes)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()