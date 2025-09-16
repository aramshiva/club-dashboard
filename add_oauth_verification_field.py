
#!/usr/bin/env python3

"""
Migration script to add requires_identity_verification field to oauth applications
"""

import os
import sys
from sqlalchemy import create_engine, text

def get_database_url():
    url = os.getenv('DATABASE_URL')
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

def main():
    database_url = get_database_url()
    if not database_url:
        print("DATABASE_URL environment variable not set")
        sys.exit(1)
    
    engine = create_engine(database_url)
    
    try:
        with engine.connect() as conn:
            # Check if column already exists
            result = conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'o_auth_application' 
                AND column_name = 'requires_identity_verification'
            """))
            
            if result.fetchone():
                print("Column requires_identity_verification already exists")
                return
            
            # Add the column
            conn.execute(text("""
                ALTER TABLE o_auth_application 
                ADD COLUMN requires_identity_verification BOOLEAN NOT NULL DEFAULT FALSE
            """))
            
            conn.commit()
            print("Successfully added requires_identity_verification column to o_auth_application table")
            
    except Exception as e:
        print(f"Error adding column: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
