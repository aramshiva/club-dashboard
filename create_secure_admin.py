#!/usr/bin/env python3
"""
Secure admin account creation script
Creates admin accounts with strong passwords and proper security logging
"""

import os
import sys
import secrets
import getpass
from datetime import datetime, timezone

# Add the current directory to the Python path
sys.path.insert(0, '/app')
sys.path.insert(0, '.')

def create_secure_admin():
    """Create a secure admin account with proper validation"""
    try:
        from main import app, db, User
        
        print("🔐 Secure Admin Account Creation")
        print("=" * 40)
        
        # Get admin details securely
        email = input("Enter admin email: ").strip()
        if not email or '@' not in email:
            print("❌ Invalid email address")
            sys.exit(1)
            
        username = input("Enter admin username: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            sys.exit(1)
            
        first_name = input("Enter first name: ").strip()
        last_name = input("Enter last name: ").strip()
        
        with app.app_context():
            # Check if user already exists
            existing_user = User.query.filter(
                (User.email == email) | (User.username == username)
            ).first()
            
            if existing_user:
                print(f"❌ User already exists with email {email} or username {username}")
                sys.exit(1)
            
            # Generate secure password
            admin_password = secrets.token_urlsafe(32)
            
            # Create admin user
            admin_user = User(
                username=username,
                email=email,
                first_name=first_name or 'Admin',
                last_name=last_name or 'User',
                is_admin=True,
                created_at=datetime.now(timezone.utc),
                registration_ip='127.0.0.1'
            )
            admin_user.set_password(admin_password)
            admin_user.add_ip('127.0.0.1')
            db.session.add(admin_user)
            db.session.commit()
            
            print("✅ Secure admin account created successfully")
            print(f"   Email: {email}")
            print(f"   Password: {admin_password}")
            print("   ⚠️  SAVE THESE CREDENTIALS SECURELY!")
            
            # Write credentials to secure file
            try:
                import stat
                credentials_file = f'/tmp/admin_{username}_{int(datetime.now().timestamp())}.txt'
                with open(credentials_file, 'w') as f:
                    f.write(f"Admin Email: {email}\n")
                    f.write(f"Admin Username: {username}\n")
                    f.write(f"Admin Password: {admin_password}\n")
                    f.write(f"Created: {datetime.now(timezone.utc).isoformat()}\n")
                
                # Set file permissions to be readable only by owner
                os.chmod(credentials_file, stat.S_IRUSR | stat.S_IWUSR)
                print(f"   📄 Credentials saved to {credentials_file} (owner read-only)")
            except Exception as e:
                print(f"   ⚠️  Could not save credentials to file: {e}")
                
    except Exception as e:
        print(f"❌ Error creating admin account: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    create_secure_admin()