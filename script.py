from app import create_app
from init_db import init_db

# Create the Flask application
app = create_app()

# Initialize the database (app already has db.init_app(app) called in create_app)
init_db(app)

print("Application setup complete.")