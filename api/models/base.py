"""
Database Base Model
Contains the SQLAlchemy database instance and base model class.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/hygiene360')

# Create database engine
engine = create_engine(DATABASE_URL)

# Create a scoped session
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

# Create a base class for models
Base = declarative_base()
Base.query = db_session.query_property()

# Initialize database
def init_db():
    """Initialize the database and create all tables."""
    # Import all models to ensure they are registered
    from . import device
    from . import security_data
    from . import software
    from . import policy
    from . import alert

    # Create tables
    Base.metadata.create_all(bind=engine)

# Database instance
class Database:
    def __init__(self):
        self.session = db_session
    
    def add(self, obj):
        """Add an object to the database."""
        self.session.add(obj)
    
    def commit(self):
        """Commit the current transaction."""
        try:
            self.session.commit()
        except:
            self.session.rollback()
            raise
    
    def rollback(self):
        """Rollback the current transaction."""
        self.session.rollback()
    
    def close(self):
        """Close the session."""
        self.session.close()

# Create a database instance
db = Database() 