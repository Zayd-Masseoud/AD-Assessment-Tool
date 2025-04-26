from models import db, ApplicationUser
from werkzeug.security import generate_password_hash

def init_db(app):
    """
    Initialize the database with default data.
    This function should be called with an existing Flask app that has
    already had db.init_app(app) called on it.
    """
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Verify all expected tables are created
        expected_tables = [
            'target_config', 'assessment_run', 'finding', 'ad_user', 'ad_group',
            'ad_computer', 'ad_group_membership', 'finding_user', 'finding_group', 
            'finding_computer', 'application_user', 'password_policy'
        ]
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        missing_tables = [table for table in expected_tables if table not in existing_tables]
        if missing_tables:
            print(f"Warning: The following tables were not created: {missing_tables}")
        else:
            print("All expected tables created successfully")
        
        # Check if default admin user exists, if not create one
        if not ApplicationUser.query.filter_by(username='admin').first():
            admin = ApplicationUser(
                username='admin',
                password_hash=generate_password_hash('change_this_password'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user")
        
        print("Database initialized successfully")
