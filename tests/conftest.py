import sys
import os

# Add the backend directory to Python's path so that
# "from app.main import app" and "from db.database import ..." both work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
