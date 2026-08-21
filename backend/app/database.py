from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base

DATABASE_URL = "postgresql://CodeShield:CodeShield123@localhost/CodeShield"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Cria as tabelas no banco ao iniciar o servidor."""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Abre e fecha a sessão com o banco."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()