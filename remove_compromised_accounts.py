#!/usr/bin/env python3
"""
Security script to remove compromised accounts from the database
Run this immediately to remove accounts with known compromised credentials
"""

import os
import sys
from datetime import datetime, timezone

# Add the current directory to the Python path
sys.path.insert(0, '/app')
sys.path.insert(0, '.')

def remove_compromised_accounts():
    """Remove known compromised accounts from the database"""
    try:
        from main import app, db, User
        
        print("🔒 Starting compromised account removal...")
        
        with app.app_context():
            # List of compromised accounts to remove
            compromised_emails = [
                'admin@hackclub.local',
                'test@hackclub.local'
            ]
            
            removed_count = 0
            for email in compromised_emails:
                user = User.query.filter_by(email=email).first()
                if user:
                    print(f"🗑️  Removing compromised account: {email}")
                    db.session.delete(user)
                    removed_count += 1
                else:
                    print(f"ℹ️  Account not found (already removed?): {email}")
            
            if removed_count > 0:
                db.session.commit()
                print(f"✅ Successfully removed {removed_count} compromised account(s)")
            else:
                print("ℹ️  No compromised accounts found to remove")
                
            # Log security event
            print(f"🔐 Security cleanup completed at {datetime.now(timezone.utc).isoformat()}")
            
    except Exception as e:
        print(f"❌ Error removing compromised accounts: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    remove_compromised_accounts()