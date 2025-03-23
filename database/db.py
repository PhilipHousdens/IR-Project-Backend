import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Load environment variables from .env file
load_dotenv()

# Get the database URL
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in .env file")

# Create the engine
engine = create_engine(DATABASE_URL, connect_args={"options": "-csearch_path=recipes_tb"})

# Create the session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
