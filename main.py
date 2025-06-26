import os
import time
import json
import hashlib
import requests
import logging
import re
import html
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, redirect, flash, request, jsonify, url_for, abort, session, Response
import psycopg2
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import string
import urllib.parse
from better_profanity import profanity
try:
    import profanity_check
    PROFANITY_CHECK_AVAILABLE = True
except ImportError:
    PROFANITY_CHECK_AVAILABLE = False

# Setup logger
logger = logging.getLogger(__name__)

# Initialize profanity filters with comprehensive settings
profanity.load_censor_words()  # Load default profanity word list

# Add custom profanity words that are commonly used inappropriately
custom_profane_words = [
    'screw', 'crap', 'damn', 'hell', 'piss', 'ass', 'bitch', 'bastard'
]

# Configure profanity filter for appropriate context

def get_database_url():
    url = os.getenv('DATABASE_URL')
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Input validation and sanitization functions
def sanitize_string(value, max_length=None, allow_html=False):
    """Sanitize string input to prevent XSS and injection attacks"""
    if not value:
        return value

    # Convert to string if not already
    value = str(value).strip()

    # Limit length if specified
    if max_length and len(value) > max_length:
        value = value[:max_length]

    # Remove or escape HTML/script tags
    if not allow_html:
        # Remove script tags completely
        value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)
        # Remove other potentially dangerous tags
        value = re.sub(r'<(script|iframe|object|embed|form|input|button|link|style)[^>]*>', '', value, flags=re.IGNORECASE)
        # Escape remaining HTML
        value = html.escape(value)

    # Remove null bytes and other control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value

def check_profanity_comprehensive(text):
    """
    Comprehensive profanity detection using multiple methods to catch evasion attempts.
    Returns True if profanity is detected, False otherwise.
    """
    if not text or not isinstance(text, str):
        return False
    
    # Normalize text for better detection
    normalized_text = text.lower().strip()
    
    # Method 1: Use profanity-check (ML-based, context-aware) if available
    if PROFANITY_CHECK_AVAILABLE:
        try:
            if profanity_check.predict([normalized_text])[0] == 1:
                return True
        except Exception:
            pass  # Fall back to other methods if profanity-check fails
    
    # Method 2: Use better-profanity (pattern-based, handles variations)
    if profanity.contains_profanity(normalized_text):
        # Allow mild words like 'screw' and 'crap' in appropriate contexts
        if normalized_text.strip() in ['screw', 'crap']:
            return False
        return True
    
    # Method 3: Advanced evasion detection
    # Handle character substitutions (l33t speak, symbol replacements)
    substitutions = {
        '4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', 
        '5': 's', '$': 's', '7': 't', '+': 't', '2': 'z', '8': 'b',
        '6': 'g', '9': 'g', 'ph': 'f', 'ck': 'k', 'x': 'ks', '*': '',
        'u*k': 'uck', 'u*': 'uc'
    }
    
    # Create variations by replacing common substitutions
    text_variations = [normalized_text]
    current_text = normalized_text
    
    for symbol, letter in substitutions.items():
        if symbol in current_text:
            current_text = current_text.replace(symbol, letter)
            text_variations.append(current_text)
    
    # Check variations
    for variation in text_variations:
        if profanity.contains_profanity(variation):
            # Allow mild words in context
            if variation.strip() in ['screw', 'crap']:
                continue
            return True
    
    # Method 4: Check with spaces removed (handles "f u c k" -> "fuck")
    no_spaces = re.sub(r'[\s\-_\.]+', '', normalized_text)
    if len(no_spaces) != len(normalized_text) and profanity.contains_profanity(no_spaces):
        return True
    
    # Method 5: Check with repeated characters normalized ("fuuuuck" -> "fuck")
    no_repeats = re.sub(r'(.)\1{2,}', r'\1', normalized_text)
    if no_repeats != normalized_text and profanity.contains_profanity(no_repeats):
        return True
    
    # Method 6: Check reversed text (handles some evasion attempts)
    reversed_text = normalized_text[::-1]
    if profanity.contains_profanity(reversed_text):
        return True
    
    return False

def filter_profanity_comprehensive(text, replacement="***"):
    """
    Filter profanity with comprehensive evasion detection and replacement.
    Returns the filtered text or raises ValueError if profanity is detected.
    """
    if not text or not isinstance(text, str):
        return text
    
    if check_profanity_comprehensive(text):
        raise ValueError("Content contains inappropriate language")
    
    return text

def validate_username(username):
    """Validate username format"""
    if not username:
        return False, "Username is required"

    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 30:
        return False, "Username must be less than 30 characters"

    # Only allow alphanumeric characters, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"

    return True, username

def validate_email(email):
    """Validate email format"""
    if not email:
        return False, "Email is required"

    email = email.strip().lower()
    if len(email) > 120:
        return False, "Email is too long"

    # Basic email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format"

    return True, email

def validate_name(name, field_name="Name"):
    """Validate first/last name"""
    if not name:
        return True, ""  # Names are optional

    name = name.strip()
    if len(name) > 50:
        return False, f"{field_name} must be less than 50 characters"

    # Only allow letters, spaces, hyphens, and apostrophes
    if not re.match(r"^[a-zA-Z\s'-]+$", name):
        return False, f"{field_name} can only contain letters, spaces, hyphens, and apostrophes"

    return True, name

# Session configuration for multiple servers
app.config['SESSION_COOKIE_SECURE'] = True if os.getenv('FLASK_ENV') == 'production' else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_TYPE'] = 'filesystem'

SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

HACKCLUB_IDENTITY_URL = os.getenv('HACKCLUB_IDENTITY_URL', 'https://identity.hackclub.com')
HACKCLUB_IDENTITY_CLIENT_ID = os.getenv('HACKCLUB_IDENTITY_CLIENT_ID')
HACKCLUB_IDENTITY_CLIENT_SECRET = os.getenv('HACKCLUB_IDENTITY_CLIENT_SECRET')

# Initialize database
db = SQLAlchemy(app)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Simple User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    birthday = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    hackatime_api_key = db.Column(db.String(255))
    slack_user_id = db.Column(db.String(255), unique=True)
    identity_token = db.Column(db.String(500))
    identity_verified = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    rate_limit = db.Column(db.Integer, default=1000)  # requests per hour
    scopes = db.Column(db.Text)  # JSON array of allowed scopes

    user = db.relationship('User', backref=db.backref('api_keys', cascade='all, delete-orphan'))

    def generate_key(self):
        self.key = secrets.token_urlsafe(48)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthApplication(db.Model):
    __tablename__ = 'o_auth_application'
    
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    client_secret = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    redirect_uris = db.Column(db.Text)  # JSON array of allowed redirect URIs
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    scopes = db.Column(db.Text)  # JSON array of allowed scopes
    
    # Relationships
    tokens = db.relationship(
        'OAuthToken',
        primaryjoin='OAuthApplication.id == OAuthToken.application_id',
        back_populates='application',
        cascade='all, delete-orphan'
    )
    authorization_codes = db.relationship(
        'OAuthAuthorizationCode',
        primaryjoin='OAuthApplication.id == OAuthAuthorizationCode.application_id',
        back_populates='application',
        cascade='all, delete-orphan'
    )

    user = db.relationship('User', backref=db.backref('oauth_applications', cascade='all, delete-orphan'))

    def generate_credentials(self):
        self.client_id = secrets.token_urlsafe(32)
        self.client_secret = secrets.token_urlsafe(64)

    def get_redirect_uris(self):
        try:
            return json.loads(self.redirect_uris) if self.redirect_uris else []
        except:
            return []

    def set_redirect_uris(self, uris_list):
        self.redirect_uris = json.dumps(uris_list)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthToken(db.Model):
    __tablename__ = 'o_auth_token'
    
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    refresh_token = db.Column(db.String(128), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
    scopes = db.Column(db.Text)  # JSON array of granted scopes
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)

    user = db.relationship('User', backref=db.backref('oauth_tokens', cascade='all, delete-orphan'))
    application = db.relationship('OAuthApplication', back_populates='tokens', foreign_keys=[application_id])

    def generate_tokens(self):
        self.access_token = secrets.token_urlsafe(48)
        self.refresh_token = secrets.token_urlsafe(48)
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthAuthorizationCode(db.Model):
    __tablename__ = 'o_auth_authorization_code'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    scopes = db.Column(db.Text)  # JSON array of requested scopes
    state = db.Column(db.String(500))
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('oauth_authorization_codes', cascade='all, delete-orphan'))
    application = db.relationship('OAuthApplication', back_populates='authorization_codes', foreign_keys=[application_id])

    def generate_code(self):
        self.code = secrets.token_urlsafe(32)
        self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

# API authentication decorators
def api_key_required(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({
                    'error': 'Missing Authorization header',
                    'error_code': 'MISSING_AUTH_HEADER',
                    'message': 'The Authorization header is required for API access',
                    'how_to_fix': 'Include the Authorization header in your request: "Authorization: Bearer YOUR_API_KEY"'
                }), 401
            
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid Authorization header format',
                    'error_code': 'INVALID_AUTH_FORMAT',
                    'message': 'Authorization header must use Bearer token format',
                    'how_to_fix': 'Use the format: "Authorization: Bearer YOUR_API_KEY"',
                    'received': f'Authorization: {auth_header[:50]}...' if len(auth_header) > 50 else f'Authorization: {auth_header}'
                }), 401

            try:
                api_key = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({
                    'error': 'Malformed Authorization header',
                    'error_code': 'MALFORMED_AUTH_HEADER',
                    'message': 'Authorization header is missing the API key',
                    'how_to_fix': 'Ensure your header follows the format: "Authorization: Bearer YOUR_API_KEY"'
                }), 401

            if not api_key or len(api_key) < 10:
                return jsonify({
                    'error': 'Invalid API key format',
                    'error_code': 'INVALID_KEY_FORMAT',
                    'message': 'API key appears to be malformed or too short',
                    'how_to_fix': 'Ensure you are using the complete API key provided by your administrator'
                }), 401

            key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()

            if not key_obj:
                # Check if key exists but is inactive
                inactive_key = APIKey.query.filter_by(key=api_key, is_active=False).first()
                if inactive_key:
                    return jsonify({
                        'error': 'API key is disabled',
                        'error_code': 'KEY_DISABLED',
                        'message': 'This API key has been disabled by an administrator',
                        'how_to_fix': 'Contact your administrator to reactivate the API key or request a new one'
                    }), 401
                else:
                    return jsonify({
                        'error': 'Invalid API key',
                        'error_code': 'INVALID_API_KEY',
                        'message': 'The provided API key does not exist or has been revoked',
                        'how_to_fix': 'Verify your API key is correct, or contact your administrator for a new one'
                    }), 401

            # Check scopes if provided
            if scopes:
                key_scopes = key_obj.get_scopes()
                if not any(scope in key_scopes for scope in scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'INSUFFICIENT_SCOPES',
                        'message': f'API key does not have required scopes: {", ".join(scopes)}',
                        'required_scopes': scopes,
                        'available_scopes': key_scopes,
                        'how_to_fix': 'Contact your administrator to add the required scopes to your API key'
                    }), 403

            # Update last used timestamp
            try:
                key_obj.last_used_at = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Failed to update API key last_used_at: {e}")

            # Add key info to request context
            request.api_key = key_obj
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def oauth_required(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({
                    'error': 'Missing Authorization header',
                    'error_code': 'MISSING_AUTH_HEADER',
                    'message': 'OAuth access token is required',
                    'how_to_fix': 'Include the Authorization header: "Authorization: Bearer YOUR_ACCESS_TOKEN"'
                }), 401
            
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid Authorization header format',
                    'error_code': 'INVALID_AUTH_FORMAT',
                    'message': 'Authorization header must use Bearer token format for OAuth',
                    'how_to_fix': 'Use the format: "Authorization: Bearer YOUR_ACCESS_TOKEN"',
                    'received': f'Authorization: {auth_header[:50]}...' if len(auth_header) > 50 else f'Authorization: {auth_header}'
                }), 401

            try:
                access_token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({
                    'error': 'Malformed Authorization header',
                    'error_code': 'MALFORMED_AUTH_HEADER',
                    'message': 'Authorization header is missing the access token',
                    'how_to_fix': 'Ensure your header follows the format: "Authorization: Bearer YOUR_ACCESS_TOKEN"'
                }), 401

            if not access_token or len(access_token) < 10:
                return jsonify({
                    'error': 'Invalid access token format',
                    'error_code': 'INVALID_TOKEN_FORMAT',
                    'message': 'Access token appears to be malformed or too short',
                    'how_to_fix': 'Ensure you are using the complete access token from the OAuth flow'
                }), 401

            token_obj = OAuthToken.query.filter_by(
                access_token=access_token, 
                is_active=True
            ).first()

            if not token_obj:
                # Check if token exists but is inactive
                inactive_token = OAuthToken.query.filter_by(access_token=access_token, is_active=False).first()
                if inactive_token:
                    return jsonify({
                        'error': 'Access token revoked',
                        'error_code': 'TOKEN_REVOKED',
                        'message': 'This access token has been revoked',
                        'how_to_fix': 'Obtain a new access token by repeating the OAuth authorization flow'
                    }), 401
                else:
                    return jsonify({
                        'error': 'Invalid OAuth token',
                        'error_code': 'INVALID_ACCESS_TOKEN',
                        'message': 'The provided access token does not exist',
                        'how_to_fix': 'Verify your access token is correct, or obtain a new one through the OAuth flow'
                    }), 401

            # Check if token is expired
            if token_obj.expires_at < datetime.now(timezone.utc):
                return jsonify({
                    'error': 'OAuth token expired',
                    'error_code': 'TOKEN_EXPIRED',
                    'message': f'Access token expired at {token_obj.expires_at.isoformat()}',
                    'expires_at': token_obj.expires_at.isoformat(),
                    'how_to_fix': 'Use your refresh token to obtain a new access token, or repeat the OAuth authorization flow'
                }), 401

            # Check scopes if provided
            if scopes:
                token_scopes = token_obj.get_scopes()
                if not any(scope in token_scopes for scope in scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'INSUFFICIENT_SCOPES',
                        'message': f'Access token does not have required scopes: {", ".join(scopes)}',
                        'required_scopes': scopes,
                        'available_scopes': token_scopes,
                        'how_to_fix': 'Request authorization with the required scopes during the OAuth flow'
                    }), 403

            # Add token and user info to request context
            request.oauth_token = token_obj
            request.oauth_user = token_obj.user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(255))
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    co_leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    join_code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    balance = db.Column(db.Numeric(10, 2), default=0.00)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    airtable_data = db.Column(db.Text)  # JSON field for additional Airtable metadata

    leader = db.relationship('User', foreign_keys=[leader_id], backref='led_clubs')
    co_leader = db.relationship('User', foreign_keys=[co_leader_id], backref='co_led_clubs')
    members = db.relationship('ClubMembership', back_populates='club', cascade='all, delete-orphan')

    def generate_join_code(self):
        self.join_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def get_airtable_data(self):
        """Get parsed Airtable data"""
        try:
            return json.loads(self.airtable_data) if self.airtable_data else {}
        except:
            return {}

    def set_airtable_data(self, data):
        """Set Airtable data as JSON"""
        self.airtable_data = json.dumps(data)

class ClubMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='club_memberships')
    club = db.relationship('Club', back_populates='members')

class ClubPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='posts')
    user = db.relationship('User', backref='posts')

class ClubAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime)
    for_all_members = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='assignments')

class ClubMeeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    meeting_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(10), nullable=False)
    end_time = db.Column(db.String(10))
    location = db.Column(db.String(255))
    meeting_link = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='meetings')

class ClubResource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='book')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='resources')

class ClubProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500))
    github_url = db.Column(db.String(500))
    featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='projects')
    user = db.relationship('User', backref='projects')

# Authentication helpers
def get_current_user():
    user_id = session.get('user_id')
    logged_in = session.get('logged_in')

    if not user_id or not logged_in:
        return None

    try:
        user = db.session.get(User, int(user_id))
        if not user:
            # Clear invalid session
            session.clear()
            return None
        return user
    except Exception as e:
        app.logger.error(f"Error getting current user: {e}")
        try:
            db.session.rollback()
            # Create a new session for retry
            db.session.close()
            user = db.session.get(User, int(user_id))
            if not user:
                session.clear()
            return user
        except Exception as e2:
            app.logger.error(f"Error on retry getting current user: {e2}")
            session.clear()
            return None

def login_user(user, remember=False):
    session['user_id'] = user.id
    session['logged_in'] = True
    if remember:
        session.permanent = True
    user.last_login = datetime.now(timezone.utc)
    try:
        db.session.commit()
    except:
        db.session.rollback()

def logout_user():
    session.pop('user_id', None)
    session.pop('logged_in', None)
    session.clear()

def is_authenticated():
    return session.get('logged_in') and session.get('user_id')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authenticated = is_authenticated()
        current_user = get_current_user()

        app.logger.debug(f"Auth check for {request.endpoint}: authenticated={authenticated}, user_id={session.get('user_id')}, logged_in={session.get('logged_in')}, current_user={current_user.username if current_user else None}")

        if not authenticated or not current_user:
            app.logger.warning(f"Authentication failed for {request.endpoint}: user_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        
        # Check if user is suspended (but allow access to suspended page and logout)
        if current_user.is_suspended and request.endpoint not in ['suspended', 'logout']:
            if request.is_json:
                return jsonify({'error': 'Account suspended'}), 403
            return redirect(url_for('suspended'))
            
        return f(*args, **kwargs)
    return decorated_function

# Make current_user available in templates
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())

# Airtable Service for Pizza Grants and Club Management
class AirtableService:
    def __init__(self):
        self.api_token = os.environ.get('AIRTABLE_TOKEN')
        self.base_id = os.environ.get('AIRTABLE_BASE_ID', 'appSnnIu0BhjI3E1p')
        self.table_name = os.environ.get('AIRTABLE_TABLE_NAME', 'Grants')
        # New club management base
        self.clubs_base_id = os.environ.get('AIRTABLE_CLUBS_BASE_ID', 'appSUAc40CDu6bDAp')
        self.clubs_table_id = os.environ.get('AIRTABLE_CLUBS_TABLE_ID', 'tbl5saCV1f7ZWjsn0')
        self.clubs_table_name = os.environ.get('AIRTABLE_CLUBS_TABLE_NAME', 'Clubs Dashboard')
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
        encoded_table_name = urllib.parse.quote(self.table_name)
        self.base_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_table_name}'
        
        # Club management URLs - use table ID for direct access
        self.clubs_base_url = f'https://api.airtable.com/v0/{self.clubs_base_id}/{self.clubs_table_id}'

    def verify_club_leader(self, email, club_name):
        if not self.api_token:
            app.logger.error("Airtable API token not configured")
            return False
        
        if not self.clubs_base_id or not self.clubs_table_name:
            app.logger.error("Airtable clubs base ID or table name not configured")
            return False
            
        try:
            # First, try to find records with the email address
            email_filter_params = {
                'filterByFormula': f'FIND("{email}", {{Current Leaders\' Emails}}) > 0'
            }
            
            app.logger.info(f"Verifying club leader: email={email}, club={club_name}")
            app.logger.debug(f"Airtable URL: {self.clubs_base_url}")
            app.logger.debug(f"Email filter formula: {email_filter_params['filterByFormula']}")
            
            response = requests.get(self.clubs_base_url, headers=self.headers, params=email_filter_params)
            
            app.logger.info(f"Airtable response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                app.logger.info(f"Found {len(records)} records with email {email}")
                
                if len(records) == 0:
                    app.logger.info("No records found with that email address")
                    return False
                
                # Check if any of the records match the club name (case-insensitive partial match)
                club_name_lower = club_name.lower()
                for record in records:
                    fields = record.get('fields', {})
                    venue = fields.get('Venue', '').lower()
                    app.logger.debug(f"Checking venue: '{venue}' against club name: '{club_name_lower}'")
                    
                    # Try multiple matching strategies
                    if (club_name_lower in venue or 
                        venue.find(club_name_lower) >= 0 or
                        any(word in venue for word in club_name_lower.split() if len(word) > 2)):
                        app.logger.info(f"Found matching club: {fields.get('Venue', '')}")
                        return True
                
                # If no exact match, log all available venues for debugging
                venues = [record.get('fields', {}).get('Venue', '') for record in records]
                app.logger.info(f"No venue match found. Available venues for {email}: {venues}")
                return False
                
            elif response.status_code == 403:
                app.logger.error(f"Airtable 403 Forbidden - check API token permissions. Response: {response.text}")
                return False
            elif response.status_code == 404:
                app.logger.error(f"Airtable 404 Not Found - check base ID and table name. Response: {response.text}")
                return False
            else:
                app.logger.error(f"Airtable API error {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"Exception during Airtable verification: {str(e)}")
            return False

    def log_pizza_grant(self, submission_data):
        if not self.api_token:
            app.logger.error("Airtable API token not configured")
            return None

        try:
            hours = float(submission_data.get('project_hours', 0))
            
            # New detailed earning structure: $5 per hour, capped at $20
            # Must be in-person meeting and have 3+ members to redeem
            grant_amount = min(hours * 5, 20)  # $5/hour, max $20
            
            # Round down to nearest dollar for clean amounts
            grant_amount = int(grant_amount)
            
            # Ensure minimum requirements are met for any grant
            if grant_amount > 0:
                # Check if club meets requirements (will be validated on submission)
                is_in_person = submission_data.get('is_in_person_meeting', False)
                club_member_count = submission_data.get('club_member_count', 0)
                
                if not is_in_person:
                    grant_amount = 0
                    app.logger.info(f"Grant denied: Not an in-person meeting")
                elif club_member_count < 3:
                    grant_amount = 0
                    app.logger.info(f"Grant denied: Club has {club_member_count} members, need 3+")
                else:
                    app.logger.info(f"Grant approved: ${grant_amount} for {hours} hours (in-person meeting, {club_member_count} members)")

            # Use YSWS Project Submission table fields - updated field names to match actual table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'

            fields = {
                'Code URL': submission_data.get('github_url', ''),
                'Playable URL': submission_data.get('live_url', ''),
                'First Name': submission_data.get('first_name', ''),
                'Last Name': submission_data.get('last_name', ''),
                'Email': submission_data.get('email', ''),
                'Age': submission_data.get('age', ''),
                'Status': 'Pending',
                'Decision Reason': '',
                'How did you hear about this?': 'Through Club Leader',
                'What are we doing well?': submission_data.get('doing_well', ''),
                'How can we improve?': submission_data.get('improve', ''),
                'Screenshot': [{'url': submission_data.get('screenshot_url', '')}] if submission_data.get('screenshot_url') else [],
                'Description': submission_data.get('project_description', ''),
                'GitHub Username': submission_data.get('github_username', ''),
                'Address (Line 1)': submission_data.get('address_1', ''),
                'Address (Line 2)': submission_data.get('address_2', ''),
                'City': submission_data.get('city', ''),
                'State / Province': submission_data.get('state', ''),
                'Country': submission_data.get('country', ''),
                'ZIP / Postal Code': submission_data.get('zip', ''),
                'Birthday': submission_data.get('birthday', ''),
                'Hackatime Project': submission_data.get('project_name', ''),
                'Hours': str(hours),
                'Grant Amount': f"${grant_amount}",
                'Club Name': submission_data.get('club_name', ''),
                'Leader Email': submission_data.get('leader_email', ''),
                'In-Person Meeting': 'Yes' if submission_data.get('is_in_person_meeting', False) else 'No',
                'Club Member Count': str(submission_data.get('club_member_count', 0)),
                'Meeting Requirements Met': 'Yes' if (submission_data.get('is_in_person_meeting', False) and submission_data.get('club_member_count', 0) >= 3) else 'No'
            }

            # Debug log submission data
            app.logger.debug(f"Club name in submission_data: '{submission_data.get('club_name', 'NOT_FOUND')}'")
            app.logger.debug(f"Leader email in submission_data: '{submission_data.get('leader_email', 'NOT_FOUND')}'")
            
            # Remove empty fields to avoid validation issues
            fields_before_filter = fields.copy()
            fields = {k: v for k, v in fields.items() if v not in [None, '', []]}
            
            # Log which fields were filtered out
            filtered_out = set(fields_before_filter.keys()) - set(fields.keys())
            if filtered_out:
                app.logger.debug(f"Fields filtered out due to empty values: {filtered_out}")

            payload = {'records': [{'fields': fields}]}
            
            app.logger.info(f"Submitting to Airtable: {project_url}")
            app.logger.debug(f"Airtable payload fields: {list(fields.keys())}")
            app.logger.info(f"Screenshot field value: {fields.get('Screenshot', 'NOT_FOUND')}")
            app.logger.debug(f"Full payload: {payload}")
            
            response = requests.post(project_url, headers=self.headers, json=payload)
            
            app.logger.info(f"Airtable response status: {response.status_code}")
            if response.status_code not in [200, 201]:
                app.logger.error(f"Airtable submission failed: {response.text}")
                return None
            
            app.logger.info("Successfully submitted to Airtable")
            return response.json()
            
        except Exception as e:
            app.logger.error(f"Exception in log_pizza_grant: {str(e)}")
            return None

    def submit_pizza_grant(self, grant_data):
        """Submit pizza grant to Grants table"""
        if not self.api_token:
            return None

        # Use Grants table instead
        grants_table_name = urllib.parse.quote('Grants')
        grants_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}'

        fields = {
            'Club': grant_data.get('club_name', ''),
            'Email': grant_data.get('contact_email', ''),
            'Status': 'In progress',
            'Grant Amount': str(grant_data.get('grant_amount', 0)),
            'Grant Type': 'Pizza Card',
            'Address': grant_data.get('club_address', ''),
            'Order ID': grant_data.get('order_id', '')
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(grants_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable response status: {response.status_code}")
            app.logger.debug(f"Airtable response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                app.logger.error(f"Airtable error: {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Exception submitting to Airtable: {str(e)}")
            return None

    def submit_purchase_request(self, purchase_data):
        """Submit purchase request to Grant Fulfillment table"""
        if not self.api_token:
            return None

        # Use Grant Fulfillment table
        fulfillment_table_name = urllib.parse.quote('Grant Fulfillment')
        fulfillment_url = f'https://api.airtable.com/v0/{self.base_id}/{fulfillment_table_name}'

        fields = {
            'Leader First Name': purchase_data.get('leader_first_name', ''),
            'Leader Last Name': purchase_data.get('leader_last_name', ''),
            'Leader Email': purchase_data.get('leader_email', ''),
            'Purchase Type': purchase_data.get('purchase_type', ''),
            'Purchase Description': purchase_data.get('description', ''),
            'Purchase Reason': purchase_data.get('reason', ''),
            'Fulfillment Method': purchase_data.get('fulfillment_method', ''),
            'Status': 'Pending',
            'Club Name': purchase_data.get('club_name', ''),
            'Amount': str(purchase_data.get('amount', 0))
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(fulfillment_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable Grant Fulfillment response status: {response.status_code}")
            app.logger.debug(f"Airtable Grant Fulfillment response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                app.logger.error(f"Airtable Grant Fulfillment error: {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Exception submitting to Airtable Grant Fulfillment: {str(e)}")
            return None

    def get_pizza_grant_submissions(self):
        if not self.api_token:
            return []

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            
            response = requests.get(project_url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                submissions = []
                for record in records:
                    fields = record.get('fields', {})
                    submissions.append({
                        'id': record['id'],
                        'project_name': fields.get('Hackatime Project', ''),
                        'first_name': fields.get('First Name', ''),
                        'last_name': fields.get('Last Name', ''),
                        'email': fields.get('Email', ''),
                        'club_name': fields.get('Club Name', fields.get('Hack Club', '')),
                        'description': fields.get('Description', ''),
                        'github_url': fields.get('Code URL', ''),
                        'live_url': fields.get('Playable URL', ''),
                        'doing_well': fields.get('What are we doing well?', ''),
                        'improve': fields.get('How can we improve?', ''),
                        'address_1': fields.get('Address (Line 1)', ''),
                        'city': fields.get('City', ''),
                        'state': fields.get('State / Province', ''),
                        'zip': fields.get('ZIP / Postal Code', ''),
                        'country': fields.get('Country', ''),
                        'hours': fields.get('Hours', 0),
                        'grant_amount': fields.get('Grant Amount', ''),
                        'status': fields.get('Status', fields.get('Grant Status', fields.get('Review Status', 'Pending'))),
                        'created_time': record.get('createdTime', '')
                    })

                return submissions
            else:
                app.logger.error(f"Failed to fetch submissions: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            app.logger.error(f"Error fetching pizza grant submissions: {str(e)}")
            return []

    def get_submission_by_id(self, submission_id):
        if not self.api_token:
            return None

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"
            
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                fields = data.get('fields', {})
                return {
                    'id': data['id'],
                    'project_name': fields.get('Hackatime Project', ''),
                    'hours': fields.get('Hours', 0),
                    'status': 'Submitted'
                }
            return None
        except Exception as e:
            app.logger.error(f"Error fetching submission {submission_id}: {str(e)}")
            return None

    def update_submission_status(self, submission_id, action):
        if not self.api_token:
            return False

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"
            
            # Map action to status
            status = 'Approved' if action == 'approve' else 'Rejected'
            
            # First, try to get the current record to see what fields exist
            get_response = requests.get(url, headers=self.headers)
            if get_response.status_code == 200:
                current_record = get_response.json()
                fields = current_record.get('fields', {})
                app.logger.info(f"Current record fields: {list(fields.keys())}")
            
            # Try different status field names one by one
            possible_status_fields = ['Status', 'Grant Status', 'Review Status', 'Approval Status']
            
            for field_name in possible_status_fields:
                update_data = {
                    'fields': {
                        field_name: status
                    }
                }
                
                response = requests.patch(url, headers=self.headers, json=update_data)
                
                if response.status_code == 200:
                    app.logger.info(f"Submission {submission_id} status updated to {status} using field '{field_name}'")
                    return True
                else:
                    app.logger.debug(f"Failed to update with field '{field_name}': {response.status_code} - {response.text}")
            
            # If no field worked, log the error and return False
            app.logger.error(f"Failed to update submission status with any field name. Last response: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            app.logger.error(f"Error updating submission status: {str(e)}")
            return False

    def delete_submission(self, submission_id):
        if not self.api_token:
            return False

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"
            
            response = requests.delete(url, headers=self.headers)
            return response.status_code == 200
        except Exception as e:
            app.logger.error(f"Error deleting submission: {str(e)}")
            return False

    def get_all_clubs_from_airtable(self):
        """Fetch all clubs from Airtable"""
        if not self.api_token:
            return []

        try:
            all_records = []
            offset = None
            
            while True:
                params = {}
                if offset:
                    params['offset'] = offset
                
                response = requests.get(self.clubs_base_url, headers=self.headers, params=params)
                if response.status_code != 200:
                    app.logger.error(f"Airtable API error: {response.status_code} - {response.text}")
                    break
                
                data = response.json()
                all_records.extend(data.get('records', []))
                
                offset = data.get('offset')
                if not offset:
                    break
            
            clubs = []
            for record in all_records:
                fields = record.get('fields', {})
                
                # Extract club information from Airtable fields
                club_data = {
                    'airtable_id': record['id'],
                    'name': fields.get('Venue', '').strip(),
                    'leader_email': fields.get("Current Leaders' Emails", '').split(',')[0].strip() if fields.get("Current Leaders' Emails") else '',
                    'location': fields.get('Location', '').strip(),
                    'description': fields.get('Description', '').strip(),
                    'status': fields.get('Status', '').strip(),
                    'meeting_day': fields.get('Meeting Day', '').strip(),
                    'meeting_time': fields.get('Meeting Time', '').strip(),
                    'website': fields.get('Website', '').strip(),
                    'slack_channel': fields.get('Slack Channel', '').strip(),
                    'github': fields.get('GitHub', '').strip(),
                    'latitude': fields.get('Latitude'),
                    'longitude': fields.get('Longitude'),
                    'country': fields.get('Country', '').strip(),
                    'region': fields.get('Region', '').strip(),
                    'timezone': fields.get('Timezone', '').strip(),
                    'primary_leader': fields.get('Primary Leader', '').strip(),
                    'co_leaders': fields.get('Co-Leaders', '').strip(),
                    'meeting_notes': fields.get('Meeting Notes', '').strip(),
                    'club_applications_link': fields.get('Club Applications Link', '').strip(),
                }
                
                # Only include clubs with valid names and leader emails
                if club_data['name'] and club_data['leader_email']:
                    clubs.append(club_data)
            
            return clubs
            
        except Exception as e:
            app.logger.error(f"Error fetching clubs from Airtable: {str(e)}")
            return []

    def sync_club_with_airtable(self, club_id, airtable_data):
        """Sync a specific club with Airtable data"""
        try:
            club = Club.query.get(club_id)
            if not club:
                return False
            
            # Update club fields with Airtable data
            if 'name' in airtable_data and airtable_data['name']:
                filtered_name = filter_profanity_comprehensive(airtable_data['name'])
                club.name = filtered_name
            else:
                club.name = club.name
            club.location = airtable_data.get('location', club.location)
            if 'description' in airtable_data and airtable_data['description']:
                filtered_description = filter_profanity_comprehensive(airtable_data['description'])
                club.description = filtered_description
            else:
                club.description = club.description
            
            # Store additional Airtable metadata as JSON in a new field
            club.airtable_data = json.dumps({
                'airtable_id': airtable_data.get('airtable_id'),
                'status': airtable_data.get('status'),
                'meeting_day': airtable_data.get('meeting_day'),
                'meeting_time': airtable_data.get('meeting_time'),
                'website': airtable_data.get('website'),
                'slack_channel': airtable_data.get('slack_channel'),
                'github': airtable_data.get('github'),
                'latitude': airtable_data.get('latitude'),
                'longitude': airtable_data.get('longitude'),
                'country': airtable_data.get('country'),
                'region': airtable_data.get('region'),
                'timezone': airtable_data.get('timezone'),
                'primary_leader': airtable_data.get('primary_leader'),
                'co_leaders': airtable_data.get('co_leaders'),
                'meeting_notes': airtable_data.get('meeting_notes'),
                'club_applications_link': airtable_data.get('club_applications_link'),
            })
            
            club.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            return True
            
        except Exception as e:
            app.logger.error(f"Error syncing club {club_id} with Airtable: {str(e)}")
            db.session.rollback()
            return False

    def create_club_from_airtable(self, airtable_data):
        """Create a new club from Airtable data"""
        try:
            # Find or create leader by email
            leader_email = airtable_data.get('leader_email')
            if not leader_email:
                return None
            
            leader = User.query.filter_by(email=leader_email).first()
            if not leader:
                # Create a placeholder leader account
                username = leader_email.split('@')[0]
                # Ensure username is unique
                counter = 1
                original_username = username
                while User.query.filter_by(username=username).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                leader = User(
                    username=username,
                    email=leader_email,
                    first_name=airtable_data.get('primary_leader', '').split(' ')[0] if airtable_data.get('primary_leader') else '',
                    last_name=' '.join(airtable_data.get('primary_leader', '').split(' ')[1:]) if airtable_data.get('primary_leader') else ''
                )
                leader.set_password(secrets.token_urlsafe(16))  # Random password
                db.session.add(leader)
                db.session.flush()
            
            # Create club
            filtered_name = filter_profanity_comprehensive(airtable_data.get('name'))
            default_desc = f"Official {filtered_name} Hack Club"
            club_desc = airtable_data.get('description', default_desc)
            filtered_description = filter_profanity_comprehensive(club_desc)
            club = Club(
                name=filtered_name,
                description=filtered_description,
                location=airtable_data.get('location'),
                leader_id=leader.id,
                airtable_data=json.dumps({
                    'airtable_id': airtable_data.get('airtable_id'),
                    'status': airtable_data.get('status'),
                    'meeting_day': airtable_data.get('meeting_day'),
                    'meeting_time': airtable_data.get('meeting_time'),
                    'website': airtable_data.get('website'),
                    'slack_channel': airtable_data.get('slack_channel'),
                    'github': airtable_data.get('github'),
                    'latitude': airtable_data.get('latitude'),
                    'longitude': airtable_data.get('longitude'),
                    'country': airtable_data.get('country'),
                    'region': airtable_data.get('region'),
                    'timezone': airtable_data.get('timezone'),
                    'primary_leader': airtable_data.get('primary_leader'),
                    'co_leaders': airtable_data.get('co_leaders'),
                    'meeting_notes': airtable_data.get('meeting_notes'),
                    'club_applications_link': airtable_data.get('club_applications_link'),
                })
            )
            club.generate_join_code()
            
            db.session.add(club)
            db.session.commit()
            
            return club
            
        except Exception as e:
            app.logger.error(f"Error creating club from Airtable data: {str(e)}")
            db.session.rollback()
            return None

    def update_club_in_airtable(self, airtable_record_id, fields):
        """Update a specific club record in Airtable"""
        if not self.api_token or not airtable_record_id:
            return False
            
        try:
            update_url = f"{self.clubs_base_url}/{airtable_record_id}"
            payload = {'fields': fields}
            
            response = requests.patch(update_url, headers=self.headers, json=payload)
            
            if response.status_code == 200:
                return True
            else:
                app.logger.error(f"Airtable update error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"Error updating Airtable record: {str(e)}")
            return False

    def sync_all_clubs_with_airtable(self):
        """Sync all clubs with Airtable data"""
        try:
            airtable_clubs = self.get_all_clubs_from_airtable()
            
            created_count = 0
            updated_count = 0
            
            for airtable_club in airtable_clubs:
                # Try to find existing club by leader email
                leader_email = airtable_club.get('leader_email')
                if not leader_email:
                    continue
                
                leader = User.query.filter_by(email=leader_email).first()
                existing_club = None
                
                if leader:
                    existing_club = Club.query.filter_by(leader_id=leader.id).first()
                
                if existing_club:
                    # Update existing club
                    if self.sync_club_with_airtable(existing_club.id, airtable_club):
                        updated_count += 1
                else:
                    # Create new club
                    new_club = self.create_club_from_airtable(airtable_club)
                    if new_club:
                        created_count += 1
            
            return {
                'success': True,
                'created': created_count,
                'updated': updated_count,
                'total_airtable_clubs': len(airtable_clubs)
            }
            
        except Exception as e:
            app.logger.error(f"Error syncing all clubs with Airtable: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

airtable_service = AirtableService()

# Hackatime Service
class HackatimeService:
    def __init__(self):
        self.base_url = "https://hackatime.hackclub.com/api/v1"

    def get_user_stats(self, api_key):
        if not api_key:
            return None
        url = f"{self.base_url}/users/my/stats?features=projects"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

    def get_user_projects(self, api_key):
        stats = self.get_user_stats(api_key)
        if not stats or 'data' not in stats:
            return []
        projects = stats['data'].get('projects', [])
        active_projects = [p for p in projects if p.get('total_seconds', 0) > 0]
        active_projects.sort(key=lambda x: x.get('total_seconds', 0), reverse=True)
        for project in active_projects:
            total_seconds = project.get('total_seconds', 0)
            project['formatted_time'] = self.format_duration(total_seconds)
        return active_projects

    def format_duration(self, total_seconds):
        if total_seconds < 60:
            return f"{total_seconds}s"
        minutes = total_seconds // 60
        hours = minutes // 60
        days = hours // 24
        remaining_hours = hours % 24
        remaining_minutes = minutes % 60
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if remaining_hours > 0:
            parts.append(f"{remaining_hours}h")
        if remaining_minutes > 0:
            parts.append(f"{remaining_minutes}m")
        return " ".join(parts) if parts else "0m"

hackatime_service = HackatimeService()

# Hack Club Identity Service
class HackClubIdentityService:
    def __init__(self):
        self.base_url = HACKCLUB_IDENTITY_URL
        self.client_id = HACKCLUB_IDENTITY_CLIENT_ID
        self.client_secret = HACKCLUB_IDENTITY_CLIENT_SECRET

    def get_auth_url(self, redirect_uri, state=None):
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'basic_info address'  # Use scopes that match Hack Club Identity
        }
        if state:
            params['state'] = state
        return f"{self.base_url}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code, redirect_uri):
        data = {
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        try:
            response = requests.post(f'{self.base_url}/oauth/token', json=data)
            return response.json()
        except:
            return {'error': 'Request failed'}

    def get_user_identity(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(f'{self.base_url}/api/v1/me', headers=headers)
            if response.status_code == 200:
                data = response.json()
                app.logger.debug(f"Identity API response: {data}")
                return data
            else:
                app.logger.warning(f"Identity API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Identity API request failed: {str(e)}")
            return None

hackclub_identity_service = HackClubIdentityService()

# Slack OAuth Service
class SlackOAuthService:
    def __init__(self):
        self.client_id = SLACK_CLIENT_ID
        self.client_secret = SLACK_CLIENT_SECRET
        self.base_url = "https://slack.com/api"

    def get_auth_url(self, redirect_uri):
        params = {
            'client_id': self.client_id,
            'scope': 'users:read,users:read.email,users.profile:read',
            'user_scope': 'identity.basic,identity.email,identity.avatar',
            'redirect_uri': redirect_uri,
            'state': secrets.token_urlsafe(32)
        }
        session['oauth_state'] = params['state']
        return f"https://slack.com/oauth/v2/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code, redirect_uri):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri
        }
        try:
            response = requests.post('https://slack.com/api/oauth.v2.access', data=data)
            return response.json()
        except:
            return {'ok': False, 'error': 'Request failed'}

    def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        identity_url = f'{self.base_url}/users.identity'
        identity_response = requests.get(identity_url, headers=headers)
        if identity_response.status_code != 200:
            return None
        try:
            identity_data = identity_response.json()
            if not identity_data.get('ok'):
                return None
            user_id = identity_data['user']['id']
            profile_url = f'{self.base_url}/users.info'
            profile_params = {'user': user_id}
            profile_response = requests.get(profile_url, headers=headers, params=profile_params)
            if profile_response.status_code == 200:
                try:
                    profile_data = profile_response.json()
                    if profile_data.get('ok'):
                        identity_data['user']['profile'] = profile_data['user']['profile']
                except:
                    pass
            return identity_data
        except:
            return None

slack_oauth_service = SlackOAuthService()

# Hack Club Identity Routes
@app.route('/api/identity/authorize', methods=['GET'])
@login_required
@limiter.limit("20 per minute")
def hackclub_identity_authorize():
    if not HACKCLUB_IDENTITY_CLIENT_ID or not HACKCLUB_IDENTITY_CLIENT_SECRET:
        return jsonify({'error': 'Hack Club Identity is not configured'}), 500
    
    redirect_uri = url_for('hackclub_identity_callback', _external=True, _scheme='https')
    state = secrets.token_urlsafe(32)
    session['hackclub_identity_state'] = state
    
    auth_url = hackclub_identity_service.get_auth_url(redirect_uri, state)
    return jsonify({'url': auth_url})

@app.route('/identity/callback')
@limiter.limit("20 per minute")
def hackclub_identity_callback():
    stored_state = session.get('hackclub_identity_state')
    received_state = request.args.get('state')
    
    if not stored_state or received_state != stored_state:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='Invalid state parameter. Please try again.')
    
    session.pop('hackclub_identity_state', None)
    
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message=f'Authorization failed: {error}')
    
    if not code:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='No authorization code received')
    
    if not is_authenticated():
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='Please log in to complete identity verification')
    
    current_user = get_current_user()
    redirect_uri = url_for('hackclub_identity_callback', _external=True, _scheme='https')
    
    token_data = hackclub_identity_service.exchange_code(code, redirect_uri)
    
    if 'error' in token_data:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message=f'Token exchange failed: {token_data.get("error", "Unknown error")}')
    
    # Store token
    current_user.identity_token = token_data.get('access_token')
    
    # Get user identity info
    identity_info = hackclub_identity_service.get_user_identity(current_user.identity_token)
    
    app.logger.info(f"Full identity response received: {json.dumps(identity_info, indent=2) if identity_info else 'None'}")
    
    if identity_info and 'identity' in identity_info:
        verification_status = identity_info['identity'].get('verification_status', 'unverified')
        current_user.identity_verified = (verification_status == 'verified')
        
        db.session.commit()
        
        # Check for pending OAuth flow
        pending_oauth = session.get('pending_oauth')
        if pending_oauth:
            # Always complete the OAuth flow regardless of verification status
            session.pop('pending_oauth', None)
            
            auth_code = OAuthAuthorizationCode(
                user_id=current_user.id,
                application_id=pending_oauth['application_id'],
                redirect_uri=pending_oauth['redirect_uri'],
                state=pending_oauth['state']
            )
            auth_code.generate_code()
            auth_code.set_scopes(pending_oauth['scopes'])

            db.session.add(auth_code)
            db.session.commit()

            # Redirect back to client with authorization code
            redirect_url = f"{pending_oauth['redirect_uri']}?code={auth_code.code}"
            if pending_oauth['state']:
                redirect_url += f"&state={pending_oauth['state']}"

            return redirect(redirect_url)
        
        if verification_status == 'verified':
            return render_template('hackclub_identity_result.html', 
                                 status='success', 
                                 message='Identity verified successfully!')
        elif verification_status == 'pending':
            return render_template('hackclub_identity_result.html', 
                                 status='pending', 
                                 message='Your identity verification is pending review.')
        elif verification_status == 'rejected':
            rejection_reason = identity_info['identity'].get('rejection_reason', 'No reason provided')
            return render_template('hackclub_identity_result.html', 
                                 status='rejected', 
                                 message=f'Identity verification was rejected: {rejection_reason}')
    else:
        db.session.commit()
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='Failed to retrieve identity information')

@app.route('/api/identity/status', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def hackclub_identity_status():
    current_user = get_current_user()
    
    if not current_user.identity_token:
        return jsonify({'status': 'unverified', 'verified': False})
    
    identity_info = hackclub_identity_service.get_user_identity(current_user.identity_token)
    
    if identity_info and 'identity' in identity_info:
        verification_status = identity_info['identity'].get('verification_status', 'unverified')
        verified = (verification_status == 'verified')
        
        # Update database if status changed
        if current_user.identity_verified != verified:
            current_user.identity_verified = verified
            db.session.commit()
        
        return jsonify({
            'status': verification_status,
            'verified': verified,
            'rejection_reason': identity_info['identity'].get('rejection_reason')
        })
    
    return jsonify({'status': 'error', 'verified': False, 'message': 'Failed to check status'})

# Routes
@app.route('/')
def index():
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    # Check if mobile device and redirect to login
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Redirect mobile users directly to login
    if (is_mobile or force_mobile) and not force_desktop:
        return redirect(url_for('login', mobile='true'))
    
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if is_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'

        if not email or not password:
            flash('Email and password are required', 'error')
            # Check if mobile for error case
            user_agent = request.headers.get('User-Agent', '').lower()
            is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
            force_mobile = request.args.get('mobile', '').lower() == 'true'
            force_desktop = request.args.get('desktop', '').lower() == 'true'
            if (is_mobile or force_mobile) and not force_desktop:
                return render_template('login_mobile.html')
            else:
                return render_template('login.html')

        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            try:
                db.session.rollback()
                user = User.query.filter_by(email=email).first()
            except:
                flash('Database connection error. Please try again.', 'error')
                # Check if mobile for error case
                user_agent = request.headers.get('User-Agent', '').lower()
                is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
                force_mobile = request.args.get('mobile', '').lower() == 'true'
                force_desktop = request.args.get('desktop', '').lower() == 'true'
                if (is_mobile or force_mobile) and not force_desktop:
                    return render_template('login_mobile.html')
                else:
                    return render_template('login.html')

        if user and user.check_password(password):
            app.logger.info(f"User {user.username} (ID: {user.id}) logging in from IP: {request.remote_addr}")
            login_user(user, remember=remember_me)
            app.logger.info(f"Session created for user {user.username}: session_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            flash(f'Welcome back, {user.username}!', 'success')

            # Check for pending OAuth flow
            oauth_params = session.get('oauth_params')
            if oauth_params:
                session.pop('oauth_params', None)
                # Redirect back to OAuth authorize with original params
                query_string = '&'.join([f"{k}={v}" for k, v in oauth_params.items()])
                return redirect(url_for('oauth_authorize') + f'?{query_string}')

            # Check for pending join code
            pending_join_code = session.get('pending_join_code')
            if pending_join_code:
                session.pop('pending_join_code', None)
                return redirect(url_for('join_club_redirect') + f'?code={pending_join_code}')

            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Determine template to use
    if (is_mobile or force_mobile) and not force_desktop:
        return render_template('login_mobile.html')
    else:
        return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if is_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Get and validate inputs
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        birthday = request.form.get('birthday', '')
        is_leader = request.form.get('is_leader') == 'on'

        # Validate username
        valid, result = validate_username(username)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        username = result

        # Validate email
        valid, result = validate_email(email)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        email = result

        # Validate password
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('signup.html')

        # Validate names
        if first_name:
            valid, result = validate_name(first_name, "First name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            first_name = result

        if last_name:
            valid, result = validate_name(last_name, "Last name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            last_name = result

        # Check for existing users
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return render_template('signup.html')

        # Create user account first (regardless of leader status)
        user = User(
            username=username, 
            email=email, 
            first_name=first_name, 
            last_name=last_name, 
            birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if is_leader:
            # Log them in and redirect to leader verification
            login_user(user, remember=False)
            flash('Account created! Now please verify your club leadership.', 'info')
            return redirect(url_for('verify_leader'))

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/suspended')
@login_required
def suspended():
    return render_template('suspended.html')

@app.route('/dashboard')
@login_required
def dashboard():
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access your dashboard.', 'info')
        return redirect(url_for('login'))

    memberships = ClubMembership.query.filter_by(user_id=current_user.id).all()
    led_clubs = Club.query.filter_by(leader_id=current_user.id).all()

    all_clubs = led_clubs + [m.club for m in memberships]
    if len(all_clubs) == 1:
        return redirect(url_for('club_dashboard', club_id=all_clubs[0].id))

    return render_template('dashboard.html', memberships=memberships, led_clubs=led_clubs)

@app.route('/club-dashboard')
@app.route('/club-dashboard/<int:club_id>')
@login_required
def club_dashboard(club_id=None):
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access the club dashboard.', 'info')
        return redirect(url_for('login'))

    if club_id:
        club = Club.query.get_or_404(club_id)
        is_leader = club.leader_id == current_user.id
        is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
        is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

        if not is_leader and not is_co_leader and not is_member:
            flash('You are not a member of this club', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if club is suspended
        if club.is_suspended and not current_user.is_admin:
            flash('This club has been suspended', 'error')
            return redirect(url_for('dashboard'))
    else:
        club = Club.query.filter_by(leader_id=current_user.id).first()
        if not club:
            membership = ClubMembership.query.filter_by(user_id=current_user.id).first()
            if membership:
                club = membership.club

        if not club:
            flash('You are not a member of any club', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if club is suspended
        if club.is_suspended and not current_user.is_admin:
            flash('This club has been suspended', 'error')
            return redirect(url_for('dashboard'))

    # Determine user role
    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    membership = ClubMembership.query.filter_by(club_id=club.id, user_id=current_user.id).first()
    is_member = membership is not None

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Route to appropriate template based on role
    if is_leader or is_co_leader:
        # Leaders and co-leaders get the full dashboard
        if (is_mobile or force_mobile) and not force_desktop:
            return render_template('club_dashboard_mobile.html', club=club)
        else:
            return render_template('club_dashboard.html', club=club)
    elif is_member:
        # Regular members get the member-specific dashboard
        # Get membership date for member templates
        membership_date = membership.joined_at if membership else None
        
        if (is_mobile or force_mobile) and not force_desktop:
            return render_template('club_dashboard_member_mobile.html', club=club, membership_date=membership_date)
        else:
            return render_template('club_dashboard_member.html', club=club, membership_date=membership_date)
    else:
        # User is not a member of this club
        flash('You are not a member of this club', 'error')
        return redirect(url_for('dashboard'))

@app.route('/verify-leader', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_leader():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip()
        club_name = data.get('club_name', '').strip()

        if not email or not club_name:
            return jsonify({'error': 'Email and club name are required'}), 400

        # Check if Airtable is configured
        if not airtable_service.api_token:
            app.logger.error("Airtable verification failed: API token not configured")
            return jsonify({'error': 'Club verification service is not configured. Please contact support.'}), 500

        is_verified = airtable_service.verify_club_leader(email, club_name)

        if is_verified:
            session['leader_verification'] = {
                'email': email,
                'club_name': club_name,
                'verified': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            return jsonify({'success': True, 'message': 'Leader verification successful!'})
        else:
            app.logger.error(f"Club leader verification failed for {email}/{club_name}")
            
            # Try to get available venues for this email to help with debugging
            try:
                email_params = {'filterByFormula': f'FIND("{email}", {{Current Leaders\' Emails}}) > 0'}
                email_response = requests.get(airtable_service.clubs_base_url, headers=airtable_service.headers, params=email_params)
                if email_response.status_code == 200:
                    email_data = email_response.json()
                    email_records = email_data.get('records', [])
                    if email_records:
                        venues = [record.get('fields', {}).get('Venue', '') for record in email_records]
                        return jsonify({
                            'error': f'Club verification failed. Your email was found but the club name didn\'t match. Available clubs for your email: {", ".join(venues)}'
                        }), 400
                    else:
                        return jsonify({
                            'error': 'Email address not found in the Hack Club directory. Please ensure you are using the email address registered with Hack Club.'
                        }), 400
                else:
                    return jsonify({
                        'error': 'Club leader verification failed. Please ensure you are using the correct email address and club name that are registered in the Hack Club directory.'
                    }), 400
            except:
                return jsonify({
                    'error': 'Club leader verification failed. Please ensure you are using the correct email address and club name that are registered in the Hack Club directory.'
                }), 400

    return render_template('verify_leader.html')

@app.route('/complete-leader-signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def complete_leader_signup():
    leader_verification = session.get('leader_verification')

    if not leader_verification or not leader_verification.get('verified'):
        flash('Invalid verification session. Please start over.', 'error')
        return redirect(url_for('dashboard'))

    if 'timestamp' in leader_verification:
        verification_time = datetime.fromisoformat(leader_verification['timestamp'])
        if (datetime.now(timezone.utc) - verification_time).total_seconds() > 3600:
            session.pop('leader_verification', None)
            flash('Verification expired. Please start over.', 'error')
            return redirect(url_for('verify_leader'))

    try:
        user = get_current_user()
        if not user:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))

        # Fetch full club data from Airtable
        email = leader_verification['email']
        club_data = None
        
        try:
            # Search for the club in Airtable using the verified email
            email_filter_params = {
                'filterByFormula': f'FIND("{email}", {{Current Leaders\' Emails}}) > 0'
            }
            
            response = requests.get(airtable_service.clubs_base_url, headers=airtable_service.headers, params=email_filter_params)
            
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                
                if records:
                    # Find the matching club record
                    club_name_lower = leader_verification['club_name'].lower()
                    for record in records:
                        fields = record.get('fields', {})
                        venue = fields.get('Venue', '').lower()
                        
                        if (club_name_lower in venue or 
                            venue.find(club_name_lower) >= 0 or
                            any(word in venue for word in club_name_lower.split() if len(word) > 2)):
                            
                            club_data = {
                                'airtable_id': record['id'],
                                'name': fields.get('Venue', '').strip(),
                                'location': fields.get('Location', '').strip(),
                                'description': fields.get('Description', '').strip() or f"Official {fields.get('Venue', '')} Hack Club",
                                'status': fields.get('Status', '').strip(),
                                'meeting_day': fields.get('Meeting Day', '').strip(),
                                'meeting_time': fields.get('Meeting Time', '').strip(),
                                'website': fields.get('Website', '').strip(),
                                'slack_channel': fields.get('Slack Channel', '').strip(),
                                'github': fields.get('GitHub', '').strip(),
                                'latitude': fields.get('Latitude'),
                                'longitude': fields.get('Longitude'),
                                'country': fields.get('Address Country', '').strip(),
                                'region': fields.get('Continent', '').strip(),
                                'timezone': fields.get('Timezone', '').strip(),
                                'primary_leader': fields.get('Current Leader(s)', '').strip(),
                                'co_leaders': fields.get('Co-Leaders', '').strip(),
                                'meeting_notes': fields.get('Meeting Notes', '').strip(),
                                'club_applications_link': fields.get('Application Link', '').strip(),
                            }
                            break
        except Exception as e:
            app.logger.warning(f"Failed to fetch club data from Airtable: {str(e)}")

        # Check if user already has a club
        existing_club = Club.query.filter_by(leader_id=user.id).first()
        
        if existing_club:
            # User already has a club - update it with Airtable data if verification succeeded
            if club_data:
                # Update existing club with verified Airtable data
                filtered_name = filter_profanity_comprehensive(club_data['name'])
                filtered_description = filter_profanity_comprehensive(club_data['description'])
                existing_club.name = filtered_name
                existing_club.description = filtered_description
                existing_club.location = club_data['location']
                existing_club.airtable_data = json.dumps({
                    'airtable_id': club_data['airtable_id'],
                    'status': club_data['status'],
                    'meeting_day': club_data['meeting_day'],
                    'meeting_time': club_data['meeting_time'],
                    'website': club_data['website'],
                    'slack_channel': club_data['slack_channel'],
                    'github': club_data['github'],
                    'latitude': club_data['latitude'],
                    'longitude': club_data['longitude'],
                    'country': club_data['country'],
                    'region': club_data['region'],
                    'timezone': club_data['timezone'],
                    'primary_leader': club_data['primary_leader'],
                    'co_leaders': club_data['co_leaders'],
                    'meeting_notes': club_data['meeting_notes'],
                    'club_applications_link': club_data['club_applications_link'],
                })
                existing_club.updated_at = datetime.now(timezone.utc)
                db.session.commit()
                
                session.pop('leader_verification', None)
                flash(f'Club successfully verified and updated with official data from the Hack Club directory! Welcome to {club_data["name"]}!', 'success')
                return redirect(url_for('club_dashboard', club_id=existing_club.id))
            else:
                # User already has a club but verification failed to find it in Airtable
                session.pop('leader_verification', None)
                flash("We can't find your club in the Hack Club directory! Please verify your club information again to sync it properly.", 'warning')
                return redirect(url_for('club_dashboard', club_id=existing_club.id))
        else:
            # Create new club after successful verification
            if not club_data:
                session.pop('leader_verification', None)
                flash("We can't find your club in the Hack Club directory! Please verify your club information again.", 'error')
                return redirect(url_for('verify_leader'))
            
            # Create club with Airtable data
            filtered_name = filter_profanity_comprehensive(club_data['name'])
            filtered_description = filter_profanity_comprehensive(club_data['description'])
            club = Club(
                name=filtered_name,
                description=filtered_description,
                location=club_data['location'],
                leader_id=user.id,
                airtable_data=json.dumps({
                    'airtable_id': club_data['airtable_id'],
                    'status': club_data['status'],
                    'meeting_day': club_data['meeting_day'],
                    'meeting_time': club_data['meeting_time'],
                    'website': club_data['website'],
                    'slack_channel': club_data['slack_channel'],
                    'github': club_data['github'],
                    'latitude': club_data['latitude'],
                    'longitude': club_data['longitude'],
                    'country': club_data['country'],
                    'region': club_data['region'],
                    'timezone': club_data['timezone'],
                    'primary_leader': club_data['primary_leader'],
                    'co_leaders': club_data['co_leaders'],
                    'meeting_notes': club_data['meeting_notes'],
                    'club_applications_link': club_data['club_applications_link'],
                })
            )
            club.generate_join_code()
            db.session.add(club)
            db.session.commit()
            
            session.pop('leader_verification', None)
            flash(f'Club created successfully! Welcome to {club_data["name"]}!', 'success')
            return redirect(url_for('club_dashboard', club_id=club.id))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in complete_leader_signup: {str(e)}")
        flash('Database error. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/join-club')
def join_club_redirect():
    join_code = request.args.get('code')
    if not join_code:
        flash('Invalid join code', 'error')
        return redirect(url_for('dashboard'))

    if is_authenticated():
        current_user = get_current_user()
        club = Club.query.filter_by(join_code=join_code).first()
        if not club:
            flash('Invalid join code', 'error')
            return redirect(url_for('dashboard'))

        # Check if user is already the leader
        if club.leader_id == current_user.id:
            flash(f"You are the leader of {club.name}", 'info')
            return redirect(url_for('club_dashboard', club_id=club.id))

        existing_membership = ClubMembership.query.filter_by(
            user_id=current_user.id, club_id=club.id).first()

        if existing_membership:
            flash(f"You are already a member of {club.name}", 'info')
            return redirect(url_for('club_dashboard', club_id=club.id))

        new_membership = ClubMembership(
            user_id=current_user.id,
            club_id=club.id,
            role='member'
        )
        db.session.add(new_membership)
        db.session.commit()

        flash(f"You have successfully joined {club.name}!", 'success')
        return redirect(url_for('club_dashboard', club_id=club.id))
    else:
        session['pending_join_code'] = join_code
        flash('Please log in or sign up to join the club', 'info')
        return redirect(url_for('login'))

# Slack OAuth Routes
@app.route('/auth/slack')
@limiter.limit("20 per minute")
def slack_login():
    if not SLACK_CLIENT_ID or not SLACK_CLIENT_SECRET:
        flash('Slack OAuth is not configured', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    auth_url = slack_oauth_service.get_auth_url(redirect_uri)
    return redirect(auth_url)

@app.route('/auth/slack/callback')
@limiter.limit("20 per minute")
def slack_callback():
    stored_state = session.get('oauth_state')
    received_state = request.args.get('state')

    if not stored_state or received_state != stored_state:
        session.clear()
        flash('Invalid OAuth state parameter. Please try again.', 'error')
        return redirect(url_for('login'))

    session.pop('oauth_state', None)

    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'Unknown error')
        flash(f'Slack authorization failed: {error}', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    token_data = slack_oauth_service.exchange_code(code, redirect_uri)

    if not token_data.get('ok'):
        error = token_data.get('error', 'Token exchange failed')
        flash(f'Slack authentication failed: {error}', 'error')
        return redirect(url_for('login'))

    user_token = None
    if 'authed_user' in token_data:
        user_token = token_data['authed_user'].get('access_token')

    if not user_token:
        user_token = token_data.get('access_token')

    if not user_token:
        flash('Failed to get user access token from Slack', 'error')
        return redirect(url_for('login'))

    user_info = slack_oauth_service.get_user_info(user_token)
    if not user_info or not user_info.get('ok'):
        if 'authed_user' in token_data:
            slack_user_id = token_data['authed_user']['id']
            user_info = {
                'ok': True,
                'user': {
                    'id': slack_user_id,
                    'name': f"user_{slack_user_id}",
                    'real_name': "",
                    'profile': {}
                }
            }
        else:
            flash('Failed to retrieve user information from Slack', 'error')
            return redirect(url_for('login'))

    slack_user = user_info['user']
    slack_user_id = slack_user['id']
    email = slack_user.get('email')
    name = slack_user.get('name', '')
    real_name = slack_user.get('real_name', '')
    profile = slack_user.get('profile', {})

    user = None
    try:
        if slack_user_id:
            user = User.query.filter_by(slack_user_id=slack_user_id).first()

        if not user and email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.slack_user_id = slack_user_id
                db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
            if slack_user_id:
                user = User.query.filter_by(slack_user_id=slack_user_id).first()
            if not user and email:
                user = User.query.filter_by(email=email).first()
        except Exception as e2:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('login'))

    if user:
        app.logger.info(f"Slack OAuth: User {user.username} (ID: {user.id}) logging in from IP: {request.remote_addr}")
        login_user(user, remember=True)
        app.logger.info(f"Slack OAuth: Session created for user {user.username}: session_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
        flash(f'Welcome back, {user.username}!', 'success')

        # Check for pending join code
        pending_join_code = session.get('pending_join_code')
        if pending_join_code:
            session.pop('pending_join_code', None)
            return redirect(url_for('join_club_redirect') + f'?code={pending_join_code}')

        return redirect(url_for('dashboard'))
    else:
        session.clear()
        session['slack_signup_data'] = {
            'slack_user_id': slack_user_id,
            'email': email or '',
            'name': name,
            'real_name': real_name,
            'first_name': profile.get('first_name', ''),
            'last_name': profile.get('last_name', ''),
            'display_name': profile.get('display_name', ''),
            'image_url': profile.get('image_512', profile.get('image_192', ''))
        }
        return redirect(url_for('complete_slack_signup'))

@app.route('/complete-slack-signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def complete_slack_signup():
    slack_data = session.get('slack_signup_data')
    if not slack_data:
        flash('No Slack signup data found. Please try again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json()

        username = data.get('username', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        birthday = data.get('birthday', '').strip()
        email = data.get('email', slack_data.get('email', '')).strip()
        password = data.get('password', '').strip()
        is_leader = data.get('is_leader', False)

        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        if not first_name:
            return jsonify({'error': 'First name is required'}), 400

        if not password or len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        try:
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                slack_user_id=slack_data['slack_user_id'],
                birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
            )
            user.set_password(password)

            db.session.add(user)
            db.session.flush()

            db.session.commit()

            session.pop('slack_signup_data', None)

            login_user(user, remember=True)

            if is_leader:
                return jsonify({
                    'success': True, 
                    'message': 'Account created! Now please verify your club leadership.',
                    'redirect': '/verify-leader'
                })

            return jsonify({'success': True, 'message': 'Account created successfully!'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

    return render_template('slack_signup_complete.html', slack_data=slack_data)

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

# API Routes
@app.route('/api/clubs/<int:club_id>/join-code', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def generate_club_join_code(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False

    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only leaders and co-leaders can generate join codes'}), 403

    club.generate_join_code()
    db.session.commit()

    return jsonify({'join_code': club.join_code})

@app.route('/api/clubs/<int:club_id>/posts', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_posts(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        # Only leaders and co-leaders can create posts
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can create posts'}), 403
            
        data = request.get_json()
        content = data.get('content')

        if not content:
            return jsonify({'error': 'Content is required'}), 400

        # Sanitize content to prevent XSS
        content = sanitize_string(content, max_length=5000, allow_html=False)

        if not content.strip():
            return jsonify({'error': 'Content cannot be empty after sanitization'}), 400

        post = ClubPost(
            club_id=club_id,
            user_id=current_user.id,
            content=content
        )
        db.session.add(post)
        db.session.commit()

        return jsonify({'message': 'Post created successfully'})

    posts = ClubPost.query.filter_by(club_id=club_id).order_by(ClubPost.created_at.desc()).all()
    posts_data = [{
        'id': post.id,
        'content': post.content,
        'created_at': post.created_at.isoformat(),
        'user': {
            'id': post.user.id,
            'username': post.user.username
        }
    } for post in posts]

    return jsonify({'posts': posts_data})

@app.route('/api/user/update', methods=['PUT'])
@login_required
@limiter.limit("20 per hour")
def update_user():
    current_user = get_current_user()
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    birthday = data.get('birthday')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    hackatime_api_key = data.get('hackatime_api_key')

    # Validate username
    if username and username != current_user.username:
        valid, result = validate_username(username)
        if not valid:
            return jsonify({'error': result}), 400

        existing_user = User.query.filter_by(username=result).first()
        if existing_user:
            return jsonify({'error': 'Username already taken'}), 400
        current_user.username = result

    # Validate email
    if email and email != current_user.email:
        valid, result = validate_email(email)
        if not valid:
            return jsonify({'error': result}), 400

        existing_user = User.query.filter_by(email=result).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400
        current_user.email = result

    # Validate names
    if first_name is not None:
        valid, result = validate_name(first_name, "First name")
        if not valid:
            return jsonify({'error': result}), 400
        current_user.first_name = result if result.strip() else None

    if last_name is not None:
        valid, result = validate_name(last_name, "Last name")
        if not valid:
            return jsonify({'error': result}), 400
        current_user.last_name = result if result.strip() else None

    if birthday is not None:
        current_user.birthday = datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None

    if hackatime_api_key is not None:
        # Sanitize API key
        api_key = sanitize_string(hackatime_api_key, max_length=255)
        current_user.hackatime_api_key = api_key if api_key.strip() else None

    if new_password:
        if not current_password:
            return jsonify({'error': 'Current password required to change password'}), 400
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        current_user.set_password(new_password)

    db.session.commit()
    return jsonify({'message': 'Account updated successfully'})

# Admin routes (simplified)
@app.route('/admin')
@login_required
def admin_dashboard():
    current_user = get_current_user()
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('index'))

    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()

    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_clubs = Club.query.order_by(Club.created_at.desc()).limit(5).all()
    recent_posts = ClubPost.query.order_by(ClubPost.created_at.desc()).limit(10).all()

    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_clubs=total_clubs,
                         total_posts=total_posts,
                         total_assignments=total_assignments,
                         recent_users=recent_users,
                         recent_clubs=recent_clubs,
                         recent_posts=recent_posts)

@app.route('/api/clubs/<int:club_id>/assignments', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_assignments(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        is_leader = club.leader_id == current_user.id
        is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can create assignments'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        due_date = data.get('due_date')
        for_all_members = data.get('for_all_members', True)

        if not title or not description:
            return jsonify({'error': 'Title and description are required'}), 400

        # Sanitize inputs
        title = sanitize_string(title, max_length=200)
        description = sanitize_string(description, max_length=5000)

        if not title.strip() or not description.strip():
            return jsonify({'error': 'Title and description cannot be empty'}), 400

        assignment = ClubAssignment(
            club_id=club_id,
            title=title,
            description=description,
            due_date=datetime.fromisoformat(due_date) if due_date else None,
            for_all_members=for_all_members
        )
        db.session.add(assignment)
        db.session.commit()

        return jsonify({'message': 'Assignment created successfully'})

    assignments = ClubAssignment.query.filter_by(club_id=club_id).order_by(ClubAssignment.created_at.desc()).all()
    assignments_data = [{
        'id': assignment.id,
        'title': assignment.title,
        'description': assignment.description,
        'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
        'for_all_members': assignment.for_all_members,
        'status': assignment.status,
        'created_at': assignment.created_at.isoformat()
    } for assignment in assignments]

    return jsonify({'assignments': assignments_data})

@app.route('/api/clubs/<int:club_id>/meetings', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_meetings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        is_leader = club.leader_id == current_user.id
        is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can schedule meetings'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        meeting_date = data.get('meeting_date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        location = data.get('location')
        meeting_link = data.get('meeting_link')

        if not title or not meeting_date or not start_time:
            return jsonify({'error': 'Title, date, and start time are required'}), 400

        meeting = ClubMeeting(
            club_id=club_id,
            title=title,
            description=description,
            meeting_date=datetime.strptime(meeting_date, '%Y-%m-%d').date(),
            start_time=start_time,
            end_time=end_time,
            location=location,
            meeting_link=meeting_link
        )
        db.session.add(meeting)
        db.session.commit()

        return jsonify({'message': 'Meeting scheduled successfully'})

    meetings = ClubMeeting.query.filter_by(club_id=club_id).order_by(ClubMeeting.meeting_date.desc()).all()
    meetings_data = [{
        'id': meeting.id,
        'title': meeting.title,
        'description': meeting.description,
        'meeting_date': meeting.meeting_date.isoformat(),
        'start_time': meeting.start_time,
        'end_time': meeting.end_time,
        'location': meeting.location,
        'meeting_link': meeting.meeting_link,
        'created_at': meeting.created_at.isoformat()
    } for meeting in meetings]

    return jsonify({'meetings': meetings_data})

@app.route('/api/clubs/<int:club_id>/meetings/<int:meeting_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_meeting_detail(club_id, meeting_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    meeting = ClubMeeting.query.get_or_404(meeting_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can manage meetings'}), 403

    if meeting.club_id != club_id:
        return jsonify({'error': 'Meeting does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(meeting)
        db.session.commit()
        return jsonify({'message': 'Meeting deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        meeting.title = data.get('title', meeting.title)
        meeting.description = data.get('description', meeting.description)
        if data.get('meeting_date'):
            meeting.meeting_date = datetime.strptime(data['meeting_date'], '%Y-%m-%d').date()
        meeting.start_time = data.get('start_time', meeting.start_time)
        meeting.end_time = data.get('end_time', meeting.end_time)
        meeting.location = data.get('location', meeting.location)
        meeting.meeting_link = data.get('meeting_link', meeting.meeting_link)

        db.session.commit()
        return jsonify({'message': 'Meeting updated successfully'})

@app.route('/api/clubs/<int:club_id>/pizza-grants', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_pizza_grants(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        data = request.get_json()
        
        # Basic validation
        required_fields = ['member_id', 'project_name', 'first_name', 'last_name', 'email', 
                          'project_description', 'github_url', 'live_url', 'is_in_person_meeting']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate new requirements
        is_in_person = data.get('is_in_person_meeting', False)
        if not is_in_person:
            return jsonify({'error': 'Project submissions must be from in-person meetings only. Virtual meetings are not eligible for grants.'}), 400
        
        # Count club members (leader + co-leader + memberships)
        member_count = 1  # Leader
        if club.co_leader_id:
            member_count += 1  # Co-leader
        member_count += len(club.members)  # Regular members
        
        if member_count < 3:
            return jsonify({'error': f'Your club must have at least 3 members to submit for grants. Current members: {member_count}'}), 400

        # Submit to Airtable
        submission_data = {
            'project_name': data.get('project_name'),
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name'),
            'email': data.get('email'),
            'birthday': data.get('birthday'),
            'age': data.get('age', ''),
            'project_description': data.get('project_description'),
            'github_url': data.get('github_url'),
            'github_username': data.get('github_username', ''),
            'live_url': data.get('live_url'),
            'learning': data.get('learning'),
            'doing_well': data.get('doing_well'),
            'improve': data.get('improve'),
            'address_1': data.get('address_1'),
            'address_2': data.get('address_2'),
            'city': data.get('city'),
            'state': data.get('state'),
            'zip': data.get('zip'),
            'country': data.get('country'),
            'screenshot_url': data.get('screenshot_url'),
            'project_hours': data.get('project_hours', '0'),
            'club_name': club.name,
            'leader_email': club.leader.email,
            'is_in_person_meeting': is_in_person,
            'club_member_count': member_count
        }

        app.logger.info(f"Pizza grant submission data: project_name={submission_data.get('project_name')}")
        app.logger.info(f"Screenshot URL received: {submission_data.get('screenshot_url')}")
        app.logger.info(f"Full submission data keys: {list(submission_data.keys())}")

        # Log to Airtable
        airtable_result = airtable_service.log_pizza_grant(submission_data)
        
        if airtable_result:
            # Clean up uploaded screenshot file after successful submission
            screenshot_url = submission_data.get('screenshot_url')
            if screenshot_url and 'static/uploads/' in screenshot_url:
                try:
                    # Extract filename from URL
                    filename = screenshot_url.split('static/uploads/')[-1]
                    file_path = os.path.join(app.root_path, 'static', 'uploads', filename)
                    
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        app.logger.info(f"Cleaned up uploaded file: {file_path}")
                except Exception as e:
                    app.logger.warning(f"Failed to clean up uploaded file: {str(e)}")
            
            return jsonify({'message': 'Project submission successful!'})
        else:
            return jsonify({'error': 'Failed to submit to grants system'}), 500

    # GET request - return submissions for this club
    try:
        submissions = airtable_service.get_pizza_grant_submissions()
        # Filter submissions for this club
        club_submissions = [s for s in submissions if s.get('club_name', '').lower() == club.name.lower()]
        return jsonify({'submissions': club_submissions})
    except Exception as e:
        app.logger.error(f"Error fetching submissions: {str(e)}")
        return jsonify({'submissions': []})

@app.route('/api/clubs/<int:club_id>/projects', methods=['GET'])
@login_required
@limiter.limit("500 per hour")
def club_projects(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    projects = ClubProject.query.filter_by(club_id=club_id).order_by(ClubProject.updated_at.desc()).all()
    projects_data = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'url': project.url,
        'github_url': project.github_url,
        'featured': project.featured,
        'created_at': project.created_at.isoformat(),
        'updated_at': project.updated_at.isoformat(),
        'owner': {
            'id': project.user.id,
            'username': project.user.username
        }
    } for project in projects]

    return jsonify({'projects': projects_data})

@app.route('/api/clubs/<int:club_id>/resources', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_resources(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        is_leader = club.leader_id == current_user.id
        is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can add resources'}), 403

        data = request.get_json()
        title = data.get('title')
        url = data.get('url')
        description = data.get('description')
        icon = data.get('icon', 'book')

        if not title or not url:
            return jsonify({'error': 'Title and URL are required'}), 400

        resource = ClubResource(
            club_id=club_id,
            title=title,
            url=url,
            description=description,
            icon=icon
        )
        db.session.add(resource)
        db.session.commit()

        return jsonify({'message': 'Resource added successfully'})

    resources = ClubResource.query.filter_by(club_id=club_id).order_by(ClubResource.created_at.desc()).all()
    resources_data = [{
        'id': resource.id,
        'title': resource.title,
        'url': resource.url,
        'description': resource.description,
        'icon': resource.icon,
        'created_at': resource.created_at.isoformat()
    } for resource in resources]

    return jsonify({'resources': resources_data})

@app.route('/api/clubs/<int:club_id>/posts/<int:post_id>', methods=['DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_post_detail(club_id, post_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    post = ClubPost.query.get_or_404(post_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can delete posts'}), 403

    if post.club_id != club_id:
        return jsonify({'error': 'Post does not belong to this club'}), 404

    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted successfully'})

@app.route('/api/clubs/<int:club_id>/assignments/<int:assignment_id>', methods=['DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_assignment_detail(club_id, assignment_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    assignment = ClubAssignment.query.get_or_404(assignment_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can delete assignments'}), 403

    if assignment.club_id != club_id:
        return jsonify({'error': 'Assignment does not belong to this club'}), 404

    db.session.delete(assignment)
    db.session.commit()
    return jsonify({'message': 'Assignment deleted successfully'})

@app.route('/api/clubs/<int:club_id>/resources/<int:resource_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_resource_detail(club_id, resource_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    resource = ClubResource.query.get_or_404(resource_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can manage resources'}), 403

    if resource.club_id != club_id:
        return jsonify({'error': 'Resource does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(resource)
        db.session.commit()
        return jsonify({'message': 'Resource deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        resource.title = data.get('title', resource.title)
        resource.url = data.get('url', resource.url)
        resource.description = data.get('description', resource.description)
        resource.icon = data.get('icon', resource.icon)

        db.session.commit()
        return jsonify({'message': 'Resource updated successfully'})

@app.route('/api/clubs/<int:club_id>/members/<int:user_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def remove_club_member(club_id, user_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Check if user is leader or co-leader
    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if hasattr(club, 'co_leader_id') else False

    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can remove members'}), 403

    if user_id == club.leader_id:
        return jsonify({'error': 'Cannot remove club leader'}), 400

    if hasattr(club, 'co_leader_id') and user_id == club.co_leader_id:
        return jsonify({'error': 'Cannot remove co-leader'}), 400

    membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id).first()
    if not membership:
        return jsonify({'error': 'User is not a member of this club'}), 404

    db.session.delete(membership)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Member removed successfully'})

@app.route('/api/clubs/<int:club_id>/co-leader', methods=['POST', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def make_co_leader(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Only club leaders can make/remove co-leaders
    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can manage co-leaders'}), 403

    if request.method == 'DELETE':
        # Remove co-leader
        if not hasattr(club, 'co_leader_id') or not club.co_leader_id:
            return jsonify({'error': 'Club does not have a co-leader'}), 400

        try:
            co_leader_id = club.co_leader_id
            club.co_leader_id = None

            # Update membership role back to member
            membership = ClubMembership.query.filter_by(club_id=club_id, user_id=co_leader_id).first()
            if membership:
                membership.role = 'member'

            db.session.commit()
            return jsonify({'success': True, 'message': 'Co-leader removed successfully'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to remove co-leader: {str(e)}'}), 500

    else:
        # POST method - Make user co-leader
        data = request.get_json()
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        # Check if user is a member of the club
        membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id).first()
        if not membership and user_id != club.leader_id:
            return jsonify({'error': 'User is not a member of this club'}), 404

        # Check if user is already the leader
        if user_id == club.leader_id:
            return jsonify({'error': 'User is already the club leader'}), 400

        # Check if there's already a co-leader
        if hasattr(club, 'co_leader_id') and club.co_leader_id:
            return jsonify({'error': 'Club already has a co-leader'}), 400

        # Make user co-leader
        try:
            if hasattr(club, 'co_leader_id'):
                club.co_leader_id = user_id
            else:
                # If the column doesn't exist yet, we need to run the migration
                return jsonify({'error': 'Co-leader feature not available. Please run database migration.'}), 500

            # Update membership role if user is a member
            if membership:
                membership.role = 'co-leader'

            db.session.commit()
            return jsonify({'success': True, 'message': 'User promoted to co-leader successfully'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to promote user: {str(e)}'}), 500

@app.route('/api/clubs/<int:club_id>/make-co-leader', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def make_co_leader_legacy(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Only club leaders can make co-leaders
    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can appoint co-leaders'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400

    # Check if user is a member of the club
    membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id).first()
    if not membership and user_id != club.leader_id:
        return jsonify({'error': 'User is not a member of this club'}), 404

    # Check if user is already the leader
    if user_id == club.leader_id:
        return jsonify({'error': 'User is already the club leader'}), 400

    # Check if there's already a co-leader
    if hasattr(club, 'co_leader_id') and club.co_leader_id:
        return jsonify({'error': 'Club already has a co-leader'}), 400

    # Make user co-leader
    try:
        if hasattr(club, 'co_leader_id'):
            club.co_leader_id = user_id
        else:
            # If the column doesn't exist yet, we need to run the migration
            return jsonify({'error': 'Co-leader feature not available. Please run database migration.'}), 500

        # Update membership role if user is a member
        if membership:
            membership.role = 'co-leader'

        db.session.commit()
        return jsonify({'success': True, 'message': 'User promoted to co-leader successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to promote user: {str(e)}'}), 500

@app.route('/api/clubs/<int:club_id>/remove-co-leader', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def remove_co_leader(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Only club leaders can remove co-leaders
    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can remove co-leaders'}), 403

    if not hasattr(club, 'co_leader_id') or not club.co_leader_id:
        return jsonify({'error': 'Club does not have a co-leader'}), 400

    try:
        co_leader_id = club.co_leader_id
        club.co_leader_id = None

        # Update membership role back to member
        membership = ClubMembership.query.filter_by(club_id=club_id, user_id=co_leader_id).first()
        if membership:
            membership.role = 'member'

        db.session.commit()
        return jsonify({'success': True, 'message': 'Co-leader removed successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to remove co-leader: {str(e)}'}), 500

@app.route('/api/clubs/<int:club_id>/settings', methods=['PUT'])
@login_required
@limiter.limit("50 per hour")
def update_club_settings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False

    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can update settings'}), 403

    data = request.get_json()
    
    # Update local club data
    if 'name' in data:
        filtered_name = filter_profanity_comprehensive(data['name'])
        club.name = sanitize_string(filtered_name, max_length=100)
    if 'description' in data:
        filtered_description = filter_profanity_comprehensive(data['description'])
        club.description = sanitize_string(filtered_description, max_length=1000)
    if 'location' in data:
        club.location = sanitize_string(data['location'], max_length=255)
    
    club.updated_at = datetime.now(timezone.utc)
    
    # Sync with Airtable if club has airtable_data
    airtable_data = club.get_airtable_data()
    if airtable_data and airtable_data.get('airtable_id'):
        try:
            # Update Airtable record
            airtable_record_id = airtable_data['airtable_id']
            update_url = f"{airtable_service.clubs_base_url}/{airtable_record_id}"
            
            airtable_fields = {}
            if 'name' in data:
                airtable_fields['Venue'] = club.name
            if 'description' in data:
                airtable_fields['Description'] = club.description
            if 'location' in data:
                airtable_fields['Location'] = club.location
            
            if airtable_fields:
                payload = {'fields': airtable_fields}
                response = requests.patch(update_url, headers=airtable_service.headers, json=payload)
                
                if response.status_code == 200:
                    app.logger.info(f"Successfully synced club {club_id} changes to Airtable")
                else:
                    app.logger.warning(f"Failed to sync club {club_id} to Airtable: {response.status_code} - {response.text}")
        except Exception as e:
            app.logger.error(f"Error syncing club {club_id} to Airtable: {str(e)}")
    
    db.session.commit()
    return jsonify({'message': 'Club settings updated successfully'})

@app.route('/api/clubs/<int:club_id>/grant-submissions', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def club_grant_submissions(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'GET':
        # Fetch actual grant submissions for this club
        try:
            all_submissions = airtable_service.get_pizza_grant_submissions()
            # Filter submissions by club name
            club_submissions = [
                submission for submission in all_submissions 
                if submission.get('club_name', '').lower() == club.name.lower()
            ]
            return jsonify({'submissions': club_submissions})
        except Exception as e:
            app.logger.error(f"Error fetching grant submissions for club {club_id}: {str(e)}")
            return jsonify({'submissions': []})

    data = request.get_json()
    member_id = data.get('member_id')

    # Only leaders can submit on behalf of others
    if member_id != str(current_user.id) and not is_leader:
        return jsonify({'error': 'You can only submit grants for yourself'}), 403

    # Get member info
    member = User.query.get(member_id)
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    # Prepare submission data for Airtable
    submission_data = {
        'project_name': data.get('project_name', ''),
        'project_hours': data.get('project_hours', '0'),
        'first_name': data.get('first_name', ''),
        'last_name': data.get('last_name', ''),
        'username': member.username,
        'email': data.get('email', ''),
        'birthday': data.get('birthday', ''),
        'age': data.get('age', ''),
        'project_description': data.get('project_description', ''),
        'github_url': data.get('github_url', ''),
        'github_username': data.get('github_username', ''),
        'live_url': data.get('live_url', ''),
        'learning': data.get('learning', ''),
        'doing_well': data.get('doing_well', ''),
        'improve': data.get('improve', ''),
        'address_1': data.get('address_1', ''),
        'address_2': data.get('address_2', ''),
        'city': data.get('city', ''),
        'state': data.get('state', ''),
        'zip': data.get('zip', ''),
        'country': data.get('country', ''),
        'screenshot_url': data.get('screenshot_url', ''),
        'club_name': club.name,
        'leader_email': club.leader.email,
        'grant_type': data.get('grant_type', ''),
        'vendor': data.get('vendor', ''),
        'fund_destination': data.get('fund_destination', '')
    }

    # Submit to Airtable
    result = airtable_service.log_pizza_grant(submission_data)
    if result:
        return jsonify({'message': 'Grant submitted successfully!'})
    else:
        return jsonify({'error': 'Failed to submit grant. Please try again.'}), 500

@app.route('/api/clubs/<int:club_id>/purchase-requests', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def club_purchase_requests(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = club.co_leader_id == current_user.id if club.co_leader_id else False
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        # Only leaders and co-leaders can submit purchase requests
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can submit purchase requests'}), 403

        data = request.get_json()
        
        # Validate required fields
        required_fields = ['purchase_type', 'description', 'reason', 'fulfillment_method', 'amount']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        # Validate amount
        try:
            amount = float(data.get('amount', 0))
            if amount <= 0:
                return jsonify({'error': 'Amount must be greater than 0'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount format'}), 400

        # Check if amount exceeds club balance
        if amount > float(club.balance):
            return jsonify({'error': f'Amount cannot exceed club balance of ${club.balance}'}), 400

        # Prepare data for Grant Fulfillment table
        purchase_data = {
            'leader_first_name': data.get('leader_first_name', ''),
            'leader_last_name': data.get('leader_last_name', ''),
            'leader_email': data.get('leader_email', ''),
            'purchase_type': data.get('purchase_type'),
            'description': data.get('description'),
            'reason': data.get('reason'),
            'fulfillment_method': data.get('fulfillment_method'),
            'amount': amount,
            'club_name': data.get('club_name', club.name)
        }

        # Submit to Airtable Grant Fulfillment table
        result = airtable_service.submit_purchase_request(purchase_data)
        
        if result:
            # Deduct amount from club balance
            club.balance = float(club.balance) - amount
            db.session.commit()
            
            return jsonify({
                'message': 'Purchase request submitted successfully!',
                'new_balance': float(club.balance)
            })
        else:
            return jsonify({'error': 'Failed to submit purchase request. Please try again.'}), 500

    else:
        # GET request - return empty list for now since we don't have a method to fetch from Grant Fulfillment
        return jsonify({'requests': []})

@app.route('/api/upload-screenshot', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def upload_screenshot():
    app.logger.info("Screenshot upload endpoint called")
    
    if 'screenshot' not in request.files:
        app.logger.error("No screenshot file in request")
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400

    file = request.files['screenshot']
    app.logger.info(f"File received: {file.filename}, content_type: {file.content_type}")
    
    if file.filename == '':
        app.logger.error("Empty filename")
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    if not file.content_type.startswith('image/'):
        app.logger.error(f"Invalid content type: {file.content_type}")
        return jsonify({'success': False, 'error': 'File must be an image'}), 400

    try:
        # Generate a unique filename
        import uuid
        import os
        file_extension = os.path.splitext(file.filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file locally for now (in production, upload to CDN)
        file_path = os.path.join(upload_dir, unique_filename)
        file.save(file_path)
        
        # Generate accessible URL
        file_url = f"{request.url_root}static/uploads/{unique_filename}"
        
        app.logger.info(f"Screenshot saved successfully: {file_path}")
        app.logger.info(f"Generated URL: {file_url}")
        
        return jsonify({'success': True, 'url': file_url})
    except Exception as e:
        app.logger.error(f"Error uploading screenshot: {str(e)}")
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/user/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_user_info(user_id):
    current_user = get_current_user()

    # Only allow users to access their own info or club leaders to access member info
    if user_id != current_user.id:
        # Check if current user is a leader of any club where this user is a member
        is_leader = False
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        for club in led_clubs:
            membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first()
            if membership or club.leader_id == user_id:
                is_leader = True
                break

        if not is_leader:
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'birthday': user.birthday.isoformat() if user.birthday else None
    })

@app.route('/api/hackatime/projects/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_hackatime_projects(user_id):
    current_user = get_current_user()

    # Only allow users to access their own data or club leaders to access member data
    if user_id != current_user.id:
        is_leader = False
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        for club in led_clubs:
            membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first()
            if membership or club.leader_id == user_id:
                is_leader = True
                break

        if not is_leader:
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)

    if not user.hackatime_api_key:
        return jsonify({'error': 'User has not configured Hackatime API key'}), 400

    projects = hackatime_service.get_user_projects(user.hackatime_api_key)

    return jsonify({
        'username': user.username,
        'projects': projects
    })

@app.route('/api/admin/users', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_users():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '').strip()
    
    # Limit per_page to reasonable values
    per_page = min(per_page, 100)
    
    # Build query
    query = User.query
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                User.username.ilike(search_term),
                User.email.ilike(search_term)
            )
        )
    
    # Apply pagination
    users_paginated = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    } for user in users_paginated.items]

    return jsonify({
        'items': users_data,
        'total': users_paginated.total,
        'page': page,
        'per_page': per_page,
        'pages': users_paginated.pages,
        'has_next': users_paginated.has_next,
        'has_prev': users_paginated.has_prev
    })

@app.route('/api/admin/clubs', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_clubs():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '').strip()
    
    # Limit per_page to reasonable values
    per_page = min(per_page, 100)
    
    # Build query
    query = Club.query
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Club.name.ilike(search_term),
                Club.description.ilike(search_term),
                Club.location.ilike(search_term)
            )
        )
    
    # Apply pagination
    clubs_paginated = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': club.leader.username,
        'leader_email': club.leader.email,
        'member_count': len(club.members) + 1,  # +1 for leader
        'balance': float(club.balance),
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'join_code': club.join_code
    } for club in clubs_paginated.items]

    return jsonify({
        'items': clubs_data,
        'total': clubs_paginated.total,
        'page': page,
        'per_page': per_page,
        'pages': clubs_paginated.pages,
        'has_next': clubs_paginated.has_next,
        'has_prev': clubs_paginated.has_prev
    })

@app.route('/api/admin/administrators', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_administrators():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    admins = User.query.filter_by(is_admin=True).all()
    admins_data = [{
        'id': admin.id,
        'username': admin.username,
        'email': admin.email,
        'is_admin': admin.is_admin,
        'is_super_admin': admin.email == 'ethan@hackclub.com',  # Super admin check
        'is_suspended': False,  # Add suspended field when implemented
        'created_at': admin.created_at.isoformat() if admin.created_at else None,
        'last_login': admin.last_login.isoformat() if admin.last_login else None,
        'clubs_led': len(admin.led_clubs)
    } for admin in admins]

    return jsonify({'admins': admins_data})

@app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_user(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)

    if request.method == 'DELETE':
        try:
            # Don't allow deleting super admin
            if user.email == 'ethan@hackclub.com':
                return jsonify({'error': 'Cannot delete super admin'}), 400

            # Delete related data in correct order to avoid foreign key violations
            # Delete club assignments for clubs led by this user
            led_clubs = Club.query.filter_by(leader_id=user_id).all()
            for club in led_clubs:
                ClubAssignment.query.filter_by(club_id=club.id).delete()
                ClubPost.query.filter_by(club_id=club.id).delete()
                ClubMeeting.query.filter_by(club_id=club.id).delete()
                ClubResource.query.filter_by(club_id=club.id).delete()
                ClubProject.query.filter_by(club_id=club.id).delete()
                ClubMembership.query.filter_by(club_id=club.id).delete()
                db.session.delete(club)

            # Delete user's own posts, projects, etc.
            ClubPost.query.filter_by(user_id=user_id).delete()
            ClubProject.query.filter_by(user_id=user_id).delete()

            # Delete user's memberships
            ClubMembership.query.filter_by(user_id=user_id).delete()

            # Finally delete the user
            db.session.delete(user)
            db.session.commit()

            app.logger.info(f"Admin {current_user.username} deleted user {user.username} (ID: {user_id})")
            return jsonify({'message': 'User deleted successfully'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting user {user_id}: {str(e)}")
            return jsonify({'error': 'Failed to delete user due to database constraints'}), 500

    if request.method == 'PUT':
        try:
            data = request.get_json()

            if 'username' in data:
                valid, result = validate_username(data['username'])
                if not valid:
                    return jsonify({'error': result}), 400

                existing_user = User.query.filter_by(username=result).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({'error': 'Username already taken'}), 400
                user.username = result

            if 'email' in data:
                valid, result = validate_email(data['email'])
                if not valid:
                    return jsonify({'error': result}), 400

                existing_user = User.query.filter_by(email=result).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({'error': 'Email already registered'}), 400
                user.email = result

            if 'is_admin' in data:
                # Don't allow removing super admin privileges
                if user.email == 'ethan@hackclub.com' and not data['is_admin']:
                    return jsonify({'error': 'Cannot remove super admin privileges'}), 400
                user.is_admin = bool(data['is_admin'])

            db.session.commit()
            return jsonify({'message': 'User updated successfully'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user {user_id}: {str(e)}")
            return jsonify({'error': 'Failed to update user'}), 500

@app.route('/api/admin/clubs', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_create_club():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    
    name = sanitize_string(data.get('name', '').strip(), max_length=100)
    filtered_name = filter_profanity_comprehensive(name)
    description = sanitize_string(data.get('description', '').strip(), max_length=1000)
    filtered_description = filter_profanity_comprehensive(description)
    location = sanitize_string(data.get('location', '').strip(), max_length=255)
    leader_email = data.get('leader_email', '').strip().lower()
    balance = data.get('balance', 0)

    if not name:
        return jsonify({'error': 'Club name is required'}), 400

    if not leader_email:
        return jsonify({'error': 'Leader email is required'}), 400

    # Validate email format
    valid, email_result = validate_email(leader_email)
    if not valid:
        return jsonify({'error': email_result}), 400

    # Find the leader user
    leader = User.query.filter_by(email=email_result).first()
    if not leader:
        return jsonify({'error': 'User with that email not found'}), 404

    # Check if user is already leading a club
    existing_club = Club.query.filter_by(leader_id=leader.id).first()
    if existing_club:
        return jsonify({'error': f'User is already leading club: {existing_club.name}'}), 400

    try:
        # Create the club
        default_desc = f"Admin-created club: {filtered_name}"
        final_description = filtered_description or default_desc
        club = Club(
            name=filtered_name,
            description=final_description,
            location=location,
            leader_id=leader.id,
            balance=balance
        )
        club.generate_join_code()

        db.session.add(club)
        db.session.commit()

        app.logger.info(f"Admin {current_user.username} created club {name} for user {leader.username}")

        return jsonify({
            'message': 'Club created successfully',
            'club': {
                'id': club.id,
                'name': club.name,
                'leader': leader.username,
                'join_code': club.join_code
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating club: {str(e)}")
        return jsonify({'error': 'Failed to create club'}), 500

@app.route('/api/admin/clubs/<int:club_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_club(club_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    club = Club.query.get_or_404(club_id)

    if request.method == 'DELETE':
        # Delete all memberships first
        ClubMembership.query.filter_by(club_id=club_id).delete()

        # Delete all related data
        ClubPost.query.filter_by(club_id=club_id).delete()
        ClubAssignment.query.filter_by(club_id=club_id).delete()
        ClubMeeting.query.filter_by(club_id=club_id).delete()
        ClubResource.query.filter_by(club_id=club_id).delete()
        ClubProject.query.filter_by(club_id=club_id).delete()

        db.session.delete(club)
        db.session.commit()
        return jsonify({'message': 'Club deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()

        if 'name' in data:
            filtered_name = filter_profanity_comprehensive(data['name'])
            club.name = filtered_name
        if 'description' in data:
            filtered_description = filter_profanity_comprehensive(data['description'])
            club.description = filtered_description
        if 'location' in data:
            club.location = data['location']
        if 'balance' in data:
            club.balance = data['balance']

        db.session.commit()
        return jsonify({'message': 'Club updated successfully'})

@app.route('/api/admin/users/search', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_search_users():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 50)), 200)  # Max 200 results

    if not query:
        return jsonify({'error': 'Search query required'}), 400

    # Search users by username, email, first name, or last name
    search_term = f"%{query}%"
    users = User.query.filter(
        db.or_(
            User.username.ilike(search_term),
            User.email.ilike(search_term),
            User.first_name.ilike(search_term),
            User.last_name.ilike(search_term)
        )
    ).limit(limit).all()

    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    } for user in users]

    return jsonify({'users': users_data})

@app.route('/api/admin/clubs/search', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_search_clubs():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 50)), 200)  # Max 200 results

    if not query:
        return jsonify({'error': 'Search query required'}), 400

    # Search clubs by name, location, description, or leader info
    search_term = f"%{query}%"
    clubs = Club.query.join(User, Club.leader_id == User.id).filter(
        db.or_(
            Club.name.ilike(search_term),
            Club.location.ilike(search_term),
            Club.description.ilike(search_term),
            User.username.ilike(search_term),
            User.email.ilike(search_term)
        )
    ).limit(limit).all()

    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': club.leader.username,
        'leader_email': club.leader.email,
        'member_count': len(club.members) + 1,  # +1 for leader
        'balance': float(club.balance),
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'join_code': club.join_code
    } for club in clubs]

    return jsonify({'clubs': clubs_data})

@app.route('/api/admin/administrators', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_add_administrator():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_admin:
        return jsonify({'error': 'User is already an administrator'}), 400

    user.is_admin = True
    db.session.commit()

    return jsonify({'message': 'Administrator added successfully'})

@app.route('/api/admin/administrators/<int:admin_id>', methods=['DELETE'])
@login_required
@limiter.limit("20 per hour")
def admin_remove_administrator(admin_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    admin = User.query.get_or_404(admin_id)

    # Don't allow removing super admin
    if admin.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot remove super admin privileges'}), 400

    admin.is_admin = False
    db.session.commit()

    return jsonify({'message': 'Administrator privileges removed successfully'})

@app.route('/api/admin/login-as-user/<int:user_id>', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def admin_login_as_user(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)

    # Don't allow logging in as super admin
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot login as super admin'}), 400

    # Log out current user and log in as the target user
    logout_user()
    login_user(user, remember=False)

    app.logger.info(f"Admin logged in as user {user.username} (ID: {user.id})")

    return jsonify({'message': f'Successfully logged in as {user.username}'})

@app.route('/api/admin/reset-password/<int:user_id>', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def admin_reset_password(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400

    # Don't allow resetting super admin password
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot reset super admin password'}), 400

    user.set_password(new_password)
    db.session.commit()

    app.logger.info(f"Admin reset password for user {user.username} (ID: {user.id})")

    return jsonify({'message': 'Password reset successfully'})

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['PUT'])
@login_required
@limiter.limit("20 per hour")
def admin_suspend_user(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    # Don't allow suspending super admin
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot suspend super admin'}), 400

    new_suspension_status = data.get('is_suspended', not user.is_suspended)
    suspend_club_members = data.get('suspend_club_members', False)
    suspend_club = data.get('suspend_club', False)

    try:
        user.is_suspended = new_suspension_status
        
        actions_taken = []
        
        if new_suspension_status:  # Suspending user
            actions_taken.append(f"User {user.username} suspended")
            
            # Handle club leader suspension options
            led_clubs = Club.query.filter_by(leader_id=user.id).all()
            
            if led_clubs and (suspend_club_members or suspend_club):
                for club in led_clubs:
                    if suspend_club:
                        club.is_suspended = True
                        actions_taken.append(f"Club '{club.name}' suspended")
                    
                    if suspend_club_members:
                        # Suspend all club members
                        for membership in club.members:
                            if membership.user.email != 'ethan@hackclub.com':  # Don't suspend super admin
                                membership.user.is_suspended = True
                                actions_taken.append(f"Club member {membership.user.username} suspended")
        else:  # Unsuspending user
            actions_taken.append(f"User {user.username} unsuspended")
        
        db.session.commit()
        
        action_verb = "suspended" if new_suspension_status else "unsuspended"
        app.logger.info(f"Admin {current_user.username} {action_verb} user {user.username} (ID: {user.id}). Actions: {'; '.join(actions_taken)}")
        
        message = f"User {action_verb} successfully"
        if len(actions_taken) > 1:
            message += f". Additional actions: {'; '.join(actions_taken[1:])}"
        
        return jsonify({'message': message})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error suspending/unsuspending user {user_id}: {str(e)}")
        return jsonify({'error': 'Failed to update suspension status'}), 500

@app.route('/api/admin/sync-clubs-airtable', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def admin_sync_clubs_airtable():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        result = airtable_service.sync_all_clubs_with_airtable()
        
        if result['success']:
            message = f"Sync completed: {result['created']} clubs created, {result['updated']} clubs updated from {result['total_airtable_clubs']} Airtable records"
            app.logger.info(f"Admin {current_user.username} synced clubs with Airtable: {message}")
            return jsonify({
                'success': True,
                'message': message,
                'stats': {
                    'created': result['created'],
                    'updated': result['updated'],
                    'total_airtable_clubs': result['total_airtable_clubs']
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error during sync')
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error in admin club sync: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to sync clubs with Airtable'
        }), 500

@app.route('/api/admin/clubs/airtable-preview', methods=['GET'])
@login_required
@limiter.limit("10 per hour")
def admin_preview_airtable_clubs():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_clubs = airtable_service.get_all_clubs_from_airtable()
        
        return jsonify({
            'success': True,
            'clubs': airtable_clubs[:50],  # Limit to first 50 for preview
            'total_count': len(airtable_clubs)
        })
        
    except Exception as e:
        app.logger.error(f"Error previewing Airtable clubs: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch clubs from Airtable'
        }), 500

# API Key Management
@app.route('/api/admin/api-keys', methods=['GET'])
@app.route('/api/admin/apikeys', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_api_keys():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    api_keys = APIKey.query.all()
    api_keys_data = [{
        'id': key.id,
        'name': key.name,
        'description': key.description,
        'user': key.user.username,
        'user_email': key.user.email,
        'scopes': key.get_scopes(),
        'is_active': key.is_active,
        'rate_limit': key.rate_limit,
        'created_at': key.created_at.isoformat() if key.created_at else None,
        'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None
    } for key in api_keys]

    return jsonify({'api_keys': api_keys_data})

@app.route('/api/admin/api-keys', methods=['POST'])
@app.route('/api/admin/apikeys', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_create_api_key():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    user_email = data.get('user_email', current_user.email).strip()
    rate_limit = data.get('rate_limit', 1000)
    scopes = data.get('scopes', [])

    if not name:
        return jsonify({'error': 'Name is required'}), 400

    if not scopes:
        return jsonify({'error': 'At least one scope is required'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate scopes - map frontend values to backend values
    scope_mapping = {
        'read:clubs': 'clubs:read',
        'write:clubs': 'clubs:write', 
        'read:users': 'users:read',
        'write:users': 'users:write',
        'clubs:read': 'clubs:read',
        'clubs:write': 'clubs:write',
        'users:read': 'users:read',
        'projects:read': 'projects:read',
        'assignments:read': 'assignments:read',
        'meetings:read': 'meetings:read',
        'analytics:read': 'analytics:read'
    }
    
    # Convert scopes using mapping
    converted_scopes = []
    for scope in scopes:
        if scope in scope_mapping:
            converted_scopes.append(scope_mapping[scope])
        else:
            return jsonify({'error': f'Invalid scope: {scope}'}), 400

    api_key = APIKey(
        name=name,
        description=description,
        user_id=user.id,
        rate_limit=rate_limit
    )
    api_key.generate_key()
    api_key.set_scopes(converted_scopes)

    db.session.add(api_key)
    db.session.commit()

    return jsonify({
        'message': 'API key created successfully',
        'api_key': api_key.key
    })

@app.route('/api/admin/api-keys/<int:key_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_api_key(key_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    api_key = APIKey.query.get_or_404(key_id)

    if request.method == 'DELETE':
        db.session.delete(api_key)
        db.session.commit()
        return jsonify({'message': 'API key deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            api_key.name = data['name']
        if 'description' in data:
            api_key.description = data['description']
        if 'is_active' in data:
            api_key.is_active = bool(data['is_active'])
        if 'rate_limit' in data:
            api_key.rate_limit = int(data['rate_limit'])
        if 'scopes' in data:
            api_key.set_scopes(data['scopes'])

        db.session.commit()
        return jsonify({'message': 'API key updated successfully'})

# OAuth Application Management
@app.route('/api/admin/oauth-applications', methods=['GET'])
@app.route('/api/admin/oauthapps', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_oauth_apps():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    oauth_apps = OAuthApplication.query.all()
    oauth_apps_data = [{
        'id': app.id,
        'name': app.name,
        'description': app.description,
        'client_id': app.client_id,
        'user': app.user.username,
        'user_email': app.user.email,
        'redirect_uris': app.get_redirect_uris(),
        'scopes': app.get_scopes(),
        'is_active': app.is_active,
        'created_at': app.created_at.isoformat() if app.created_at else None
    } for app in oauth_apps]

    return jsonify({'oauth_apps': oauth_apps_data, 'oauth_applications': oauth_apps_data})

@app.route('/api/admin/oauth-applications', methods=['POST'])
@app.route('/api/admin/oauthapps', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_create_oauth_app():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    user_email = data.get('user_email', current_user.email).strip()
    redirect_uris = data.get('redirect_uris', [])
    scopes = data.get('scopes', [])

    if not name:
        return jsonify({'error':'Name is required'}), 400

    if not redirect_uris:
        return jsonify({'error': 'At least one redirect URI is required'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate scopes
    valid_scopes = ['clubs:read', 'clubs:write', 'users:read', 'projects:read', 
                   'assignments:read', 'meetings:read', 'analytics:read']
    invalid_scopes = [s for s in scopes if s not in valid_scopes]
    if invalid_scopes:
        return jsonify({'error': f'Invalid scopes: {", ".join(invalid_scopes)}'}), 400

    oauth_app = OAuthApplication(
        name=name,
        description=description,
        user_id=user.id
    )
    oauth_app.generate_credentials()
    oauth_app.set_redirect_uris(redirect_uris)
    oauth_app.set_scopes(scopes)

    db.session.add(oauth_app)
    db.session.commit()

    return jsonify({
        'message': 'OAuth application created successfully',
        'client_id': oauth_app.client_id,
        'client_secret': oauth_app.client_secret
    })

@app.route('/api/admin/oauth-applications/<int:app_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_oauth_app(app_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    oauth_app = OAuthApplication.query.get_or_404(app_id)

    if request.method == 'DELETE':
        # Delete related tokens and authorization codes
        OAuthToken.query.filter_by(application_id=app_id).delete()
        OAuthAuthorizationCode.query.filter_by(application_id=app_id).delete()

        db.session.delete(oauth_app)
        db.session.commit()
        return jsonify({'message': 'OAuth application deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            oauth_app.name = data['name']
        if 'description' in data:
            oauth_app.description = data['description']
        if 'is_active' in data:
            oauth_app.is_active = bool(data['is_active'])
        if 'redirect_uris' in data:
            oauth_app.set_redirect_uris(data['redirect_uris'])
        if 'scopes' in data:
            oauth_app.set_scopes(data['scopes'])

        db.session.commit()
        return jsonify({'message': 'OAuth application updated successfully'})

# Admin Pizza Grant Management
@app.route('/api/admin/pizza-grants', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_pizza_grants():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_service = AirtableService()
        submissions = airtable_service.get_pizza_grant_submissions()
        return jsonify({'submissions': submissions})
    except Exception as e:
        app.logger.error(f"Error fetching pizza grant submissions: {str(e)}")
        return jsonify({'error': 'Failed to fetch submissions'}), 500

@app.route('/api/admin/pizza-grants/review', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def admin_review_pizza_grant():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    submission_id = data.get('submission_id')
    action = data.get('action')  # 'approve' or 'reject'

    if not submission_id or not action:
        return jsonify({'error': 'submission_id and action are required'}), 400

    if action not in ['approve', 'reject']:
        return jsonify({'error': 'action must be approve or reject'}), 400

    try:
        airtable_service = AirtableService()
        
        # If approving, we need to add funds to the club balance
        if action == 'approve':
            # Get the full submission with all fields including email and grant amount
            submissions = airtable_service.get_pizza_grant_submissions()
            full_submission = next((s for s in submissions if s['id'] == submission_id), None)
            
            if not full_submission:
                return jsonify({'error': 'Submission not found'}), 404
            
            # Check if already approved to prevent double-payment
            current_status = full_submission.get('status', '').lower()
            if current_status == 'approved':
                return jsonify({'error': 'Grant has already been approved'}), 400
            
            grant_amount_raw = full_submission.get('grant_amount')
            submitter_email = full_submission.get('email')
            
            if not submitter_email:
                return jsonify({'error': 'Submitter email not found'}), 400
            
            # Parse grant amount - handle various formats
            if not grant_amount_raw:
                return jsonify({'error': 'Grant amount not found'}), 400
            
            try:
                # Convert to string and clean up
                grant_amount_str = str(grant_amount_raw).strip()
                
                # Remove currency symbols and common formatting
                import re
                grant_amount_str = re.sub(r'[^\d.-]', '', grant_amount_str)
                
                if not grant_amount_str:
                    return jsonify({'error': 'Grant amount is empty after cleaning'}), 400
                
                from decimal import Decimal
                grant_amount = Decimal(grant_amount_str)
                
                if grant_amount <= 0:
                    return jsonify({'error': 'Grant amount must be positive'}), 400
                    
            except (ValueError, TypeError) as e:
                app.logger.error(f"Error parsing grant amount '{grant_amount_raw}': {str(e)}")
                return jsonify({'error': f'Invalid grant amount format: {grant_amount_raw}'}), 400
            
            # Find the user and their club
            submitter = User.query.filter_by(email=submitter_email).first()
            if not submitter:
                return jsonify({'error': 'Submitter not found in system'}), 404
            
            # Check if user leads a club or is a member of one
            club = None
            if submitter.led_clubs:
                club = submitter.led_clubs[0]  # User leads a club
            elif submitter.clubs:
                club = submitter.clubs[0]  # User is a member of a club
            
            if not club:
                return jsonify({'error': 'User is not associated with any club'}), 404
            
            # Add the grant amount to the club balance
            club.balance += grant_amount
            db.session.commit()
            
            app.logger.info(f"Added ${grant_amount} to club '{club.name}' (ID: {club.id}) for approved grant {submission_id}")
        
        # Update the submission status in Airtable
        result = airtable_service.update_submission_status(submission_id, action)
        
        if result:
            if action == 'approve':
                return jsonify({
                    'message': f'Grant approved successfully and ${float(grant_amount)} added to {club.name}\'s balance'
                })
            else:
                return jsonify({'message': f'Grant {action}d successfully'})
        else:
            return jsonify({'error': f'Failed to update grant status in Airtable'}), 500
    except Exception as e:
        app.logger.error(f"Error {action}ing submission {submission_id}: {str(e)}")
        return jsonify({'error': f'Failed to {action} grant'}), 500

@app.route('/api/admin/pizza-grants/<string:submission_id>', methods=['DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_delete_pizza_grant(submission_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_service = AirtableService()
        result = airtable_service.delete_submission(submission_id)
        
        if result:
            return jsonify({'message': 'Submission deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete submission'}), 500
    except Exception as e:
        app.logger.error(f"Error deleting submission {submission_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete submission'}), 500

# Public API Endpoints
@app.route('/api/v1/clubs', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("100 per hour")
def api_get_clubs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '').strip()
    all_clubs = request.args.get('all', '').lower() == 'true'

    query = Club.query

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Club.name.ilike(search_term),
                Club.location.ilike(search_term),
                Club.description.ilike(search_term)
            )
        )

    if all_clubs:
        # Return all clubs without pagination
        clubs = query.all()
        clubs_data = []
        for club in clubs:
            airtable_data = club.get_airtable_data()
            clubs_data.append({
                'id': club.id,
                'name': club.name,
                'description': club.description,
                'location': club.location,
                'leader': {
                    'id': club.leader.id,
                    'username': club.leader.username,
                    'email': club.leader.email
                },
                'member_count': len(club.members) + 1,
                'balance': float(club.balance),
                'created_at': club.created_at.isoformat() if club.created_at else None,
                'updated_at': club.updated_at.isoformat() if club.updated_at else None,
                'airtable_data': airtable_data
            })

        return jsonify({
            'clubs': clubs_data,
            'total': len(clubs_data)
        })
    else:
        # Use pagination with no upper limit on per_page
        clubs_paginated = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )

        clubs_data = []
        for club in clubs_paginated.items:
            airtable_data = club.get_airtable_data()
            clubs_data.append({
                'id': club.id,
                'name': club.name,
                'description': club.description,
                'location': club.location,
                'leader': {
                    'id': club.leader.id,
                    'username': club.leader.username,
                    'email': club.leader.email
                },
                'member_count': len(club.members) + 1,
                'balance': float(club.balance),
                'created_at': club.created_at.isoformat() if club.created_at else None,
                'updated_at': club.updated_at.isoformat() if club.updated_at else None,
                'airtable_data': airtable_data
            })

        return jsonify({
            'clubs': clubs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': clubs_paginated.total,
                'pages': clubs_paginated.pages,
                'has_next': clubs_paginated.has_next,
                'has_prev': clubs_paginated.has_prev
            }
        })

@app.route('/api/v1/clubs/<int:club_id>', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club(club_id):
    club = Club.query.get(club_id)

    if not club:
        # Try Airtable lookup as fallback
        try:
            # Search for club in Airtable
            airtable_url = f'https://api.airtable.com/v0/{airtable_service.clubs_base_id}/{urllib.parse.quote(airtable_service.clubs_table_name)}'
            headers = {'Authorization': f'Bearer {airtable_service.api_token}'}
            params = {'filterByFormula': f'{{ID}} = "{club_id}"'}

            response = requests.get(airtable_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                if records:
                    record = records[0]
                    fields = record.get('fields', {})
                    return jsonify({
                        'club': {
                            'id': club_id,
                            'name': fields.get('Venue', 'Unknown Club'),
                            'description': 'Club found in Hack Club directory',
                            'location': fields.get('Location', ''),
                            'leader': {
                                'email': fields.get("Current Leaders' Emails", '').split(',')[0].strip()
                            },
                            'member_count': 0,
                            'balance': 0.0,
                            'created_at': None,
                            'source': 'airtable',
                            'airtable_data': {
                                'status': fields.get('Status', ''),
                                'meeting_day': fields.get('Meeting Day', ''),
                                'meeting_time': fields.get('Meeting Time', ''),
                                'website': fields.get('Website', ''),
                                'country': fields.get('Country', ''),
                                'region': fields.get('Region', ''),
                            }
                        }
                    })
        except:
            pass

        return jsonify({'error': 'Club not found'}), 404

    airtable_data = club.get_airtable_data()
    
    club_data = {
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': {
            'id': club.leader.id,
            'username': club.leader.username,
            'email': club.leader.email
        },
        'member_count': len(club.members) + 1,
        'balance': float(club.balance),
        'join_code': club.join_code,
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'updated_at': club.updated_at.isoformat() if club.updated_at else None,
        'source': 'database',
        'airtable_data': airtable_data
    }

    return jsonify({'club': club_data})

@app.route('/api/v1/clubs/<int:club_id>/members', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club_members(club_id):
    club = Club.query.get_or_404(club_id)

    members_data = []

    # Add leader
    members_data.append({
        'id': club.leader.id,
        'username': club.leader.username,
        'email': club.leader.email,
        'role': 'leader',
        'joined_at': club.created_at.isoformat() if club.created_at else None
    })

    # Add members
    for membership in club.members:
        members_data.append({
            'id': membership.user.id,
            'username': membership.user.username,
            'email': membership.user.email,
            'role': membership.role,
            'joined_at': membership.joined_at.isoformat() if membership.joined_at else None
        })

    return jsonify({'members': members_data})

@app.route('/api/v1/clubs/<int:club_id>/projects', methods=['GET'])
@api_key_required(['projects:read'])
@limiter.limit("200 per hour")
def api_get_club_projects(club_id):
    club = Club.query.get_or_404(club_id)

    projects = ClubProject.query.filter_by(club_id=club_id).order_by(ClubProject.updated_at.desc()).all()

    projects_data = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'url': project.url,
        'github_url': project.github_url,
        'featured': project.featured,
        'author': {
            'id': project.user.id,
            'username': project.user.username
        },
        'created_at': project.created_at.isoformat() if project.created_at else None,
        'updated_at': project.updated_at.isoformat() if project.updated_at else None
    } for project in projects]

    return jsonify({'projects': projects_data})

@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
@api_key_required(['users:read'])
@limiter.limit("200 per hour")
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)

    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    }

    return jsonify({'user': user_data})

@app.route('/api/v1/clubs/search', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_search_clubs():
    """Search clubs by name, location, or description. Returns basic info to help find club IDs."""
    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 20)), 100)  # Max 100 results
    
    if not query:
        return jsonify({
            'error': 'Search query required',
            'message': 'Use ?q=search_term to search for clubs',
            'example': '/api/v1/clubs/search?q=tech'
        }), 400
    
    # Search clubs by name, location, or description
    search_term = f"%{query}%"
    clubs = Club.query.filter(
        db.or_(
            Club.name.ilike(search_term),
            Club.location.ilike(search_term),
            Club.description.ilike(search_term)
        )
    ).limit(limit).all()
    
    clubs_data = []
    for club in clubs:
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'location': club.location,
            'description': club.description[:100] + ('...' if len(club.description or '') > 100 else ''),
            'leader': {
                'id': club.leader.id,
                'username': club.leader.username,
                'email': club.leader.email
            },
            'member_count': len(club.members) + 1,
            'created_at': club.created_at.isoformat() if club.created_at else None
        })
    
    return jsonify({
        'clubs': clubs_data,
        'total_results': len(clubs_data),
        'search_query': query,
        'limit': limit
    })

@app.route('/api/v1/users/search', methods=['GET'])
@api_key_required(['users:read'])
@limiter.limit("200 per hour")
def api_search_users():
    """Search users by username, email, or name. Returns basic info to help find user IDs."""
    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 20)), 100)  # Max 100 results
    
    if not query:
        return jsonify({
            'error': 'Search query required',
            'message': 'Use ?q=search_term to search for users',
            'example': '/api/v1/users/search?q=john'
        }), 400
    
    # Search users by username, email, first name, or last name
    search_term = f"%{query}%"
    users = User.query.filter(
        db.or_(
            User.username.ilike(search_term),
            User.email.ilike(search_term),
            User.first_name.ilike(search_term),
            User.last_name.ilike(search_term)
        )
    ).limit(limit).all()
    
    users_data = []
    for user in users:
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': full_name if full_name else None,
            'is_admin': user.is_admin,
            'clubs_led': len(user.led_clubs),
            'clubs_joined': len(user.club_memberships),
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
    
    return jsonify({
        'users': users_data,
        'total_results': len(users_data),
        'search_query': query,
        'limit': limit
    })

@app.route('/api/v1/analytics/overview', methods=['GET'])
@api_key_required(['analytics:read'])
@limiter.limit("100 per hour")
def api_get_analytics():
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    total_meetings = ClubMeeting.query.count()
    total_projects = ClubProject.query.count()

    # Calculate 30-day stats
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    new_users_30d = User.query.filter(User.created_at >= thirty_days_ago).count()
    new_clubs_30d = Club.query.filter(Club.created_at >= thirty_days_ago).count()
    active_users_30d = User.query.filter(User.last_login >= thirty_days_ago).count()

    analytics_data = {
        'totals': {
            'users': total_users,
            'clubs': total_clubs,
            'posts': total_posts,
            'assignments': total_assignments,
            'meetings': total_meetings,
            'projects': total_projects
        },
        'recent': {
            'new_users_30d': new_users_30d,
            'new_clubs_30d': new_clubs_30d,
            'active_users_30d': active_users_30d
        }
    }

    return jsonify({'analytics': analytics_data})

# OAuth Endpoints
@app.route('/oauth/authorize', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def oauth_authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')

    # Validate required parameters
    if not client_id:
        return jsonify({
            'error': 'Missing client_id parameter',
            'error_code': 'MISSING_CLIENT_ID',
            'message': 'The client_id parameter is required for OAuth authorization',
            'how_to_fix': 'Include client_id in your authorization URL query parameters'
        }), 400

    if not redirect_uri:
        return jsonify({
            'error': 'Missing redirect_uri parameter',
            'error_code': 'MISSING_REDIRECT_URI',
            'message': 'The redirect_uri parameter is required for OAuth authorization',
            'how_to_fix': 'Include redirect_uri in your authorization URL query parameters'
        }), 400

    if not response_type or response_type != 'code':
        return jsonify({
            'error': 'Invalid response_type parameter',
            'error_code': 'INVALID_RESPONSE_TYPE',
            'message': 'Only "code" response_type is supported for OAuth authorization',
            'received': response_type,
            'how_to_fix': 'Set response_type=code in your authorization URL'
        }), 400

    try:
        oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
    except Exception as e:
        app.logger.error(f"Database error in oauth_authorize: {e}")
        try:
            db.session.rollback()
            oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
        except Exception as e2:
            app.logger.error(f"Database retry failed in oauth_authorize: {e2}")
            return jsonify({
                'error': 'Database connection error',
                'error_code': 'DATABASE_ERROR',
                'message': 'Temporary database issue, please try again',
                'how_to_fix': 'Wait a moment and retry your request'
            }), 500
    
    if not oauth_app:
        # Check if client exists but is inactive
        inactive_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=False).first()
        if inactive_app:
            return jsonify({
                'error': 'OAuth application disabled',
                'error_code': 'CLIENT_DISABLED',
                'message': 'This OAuth application has been disabled',
                'how_to_fix': 'Contact the application administrator to reactivate the OAuth application'
            }), 400
        else:
            return jsonify({
                'error': 'Invalid client_id',
                'error_code': 'INVALID_CLIENT_ID',
                'message': 'The provided client_id does not exist',
                'how_to_fix': 'Verify your client_id is correct or register a new OAuth application'
            }), 400

    # Check if redirect_uri is allowed
    allowed_redirect_uris = oauth_app.get_redirect_uris()
    if redirect_uri not in allowed_redirect_uris:
        return jsonify({
            'error': 'Invalid redirect_uri',
            'error_code': 'INVALID_REDIRECT_URI',
            'message': 'The redirect_uri is not registered for this OAuth application',
            'provided_uri': redirect_uri,
            'allowed_uris': allowed_redirect_uris,
            'how_to_fix': 'Use one of the registered redirect URIs or update your OAuth application configuration'
        }), 400

    # Check if user is authenticated
    if not is_authenticated():
        # Store OAuth params in session and redirect to login
        session['oauth_params'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'scope': scope,
            'state': state
        }
        return redirect(url_for('login'))

    # Validate requested scopes
    requested_scopes = []
    if scope:
        # Handle both space-separated and comma-separated scopes
        scope_clean = scope.strip()
        if scope_clean:
            if ',' in scope_clean:
                requested_scopes = [s.strip() for s in scope_clean.split(',') if s.strip()]
            else:
                requested_scopes = [s.strip() for s in scope_clean.split() if s.strip()]
    
    allowed_scopes = oauth_app.get_scopes()
    
    # If no scopes requested, use basic default scopes
    if not requested_scopes:
        requested_scopes = ['basic_info']  # Default basic scope
    
    # Validate scopes - be more lenient with common OAuth scopes
    valid_oauth_scopes = [
        'basic_info', 'address', 'openid', 'profile', 'email',
        'clubs:read', 'clubs:write', 'users:read', 'projects:read', 
        'assignments:read', 'meetings:read', 'analytics:read'
    ]
    
    invalid_scopes = [s for s in requested_scopes if s not in allowed_scopes and s not in valid_oauth_scopes]
    if invalid_scopes:
        return jsonify({
            'error': 'Invalid scopes requested',
            'error_code': 'INVALID_SCOPES',
            'message': f'The following scopes are not allowed for this application: {", ".join(invalid_scopes)}',
            'invalid_scopes': invalid_scopes,
            'allowed_scopes': allowed_scopes,
            'valid_oauth_scopes': valid_oauth_scopes,
            'how_to_fix': 'Request only scopes that are configured for this OAuth application or use standard OAuth scopes'
        }), 400

    current_user = get_current_user()

    # Handle POST request (user approved/denied)
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'deny':
            # Redirect back with error
            error_url = f"{redirect_uri}?error=access_denied"
            if state:
                error_url += f"&state={state}"
            return redirect(error_url)
        
        elif action == 'approve':
            # Always require identity verification to get the most up-to-date information
            # Store OAuth params and redirect to identity verification
            session['pending_oauth'] = {
                'application_id': oauth_app.id,
                'redirect_uri': redirect_uri,
                'state': state,
                'scopes': requested_scopes
            }
            
            # Get identity authorization URL
            identity_redirect_uri = url_for('hackclub_identity_callback', _external=True, _scheme='https')
            identity_state = secrets.token_urlsafe(32)
            session['hackclub_identity_state'] = identity_state
            
            identity_auth_url = hackclub_identity_service.get_auth_url(identity_redirect_uri, identity_state)
            return redirect(identity_auth_url)

    # Show consent page
    scope_descriptions = {
        'basic_info': 'Access your basic profile information',
        'address': 'Access your verified address information',
        'openid': 'Verify your identity',
        'profile': 'Access your profile information',
        'email': 'Access your email address',
        'clubs:read': 'View your clubs and club information',
        'clubs:write': 'Create and manage clubs on your behalf',
        'users:read': 'View your profile information',
        'projects:read': 'View your projects and club projects',
        'assignments:read': 'View club assignments',
        'meetings:read': 'View club meetings',
        'analytics:read': 'View analytics and statistics'
    }

    scopes_with_descriptions = []
    for scope_name in requested_scopes:
        scopes_with_descriptions.append({
            'name': scope_name,
            'description': scope_descriptions.get(scope_name, f'Access {scope_name}')
        })

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Determine template to use
    template_name = 'oauth_consent_mobile.html' if (is_mobile or force_mobile) and not force_desktop else 'oauth_consent.html'

    return render_template(template_name, 
                         app=oauth_app, 
                         scopes=scopes_with_descriptions,
                         client_id=client_id,
                         redirect_uri=redirect_uri,
                         response_type=response_type,
                         scope=scope,
                         state=state)

@app.route('/oauth/token', methods=['POST'])
@limiter.limit("60 per minute")
def oauth_token():
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')

    if not grant_type:
        return jsonify({
            'error': 'Missing grant_type parameter',
            'error_code': 'MISSING_GRANT_TYPE',
            'message': 'The grant_type parameter is required',
            'how_to_fix': 'Include grant_type=authorization_code in your POST request'
        }), 400

    if grant_type != 'authorization_code':
        return jsonify({
            'error': 'Unsupported grant_type',
            'error_code': 'UNSUPPORTED_GRANT_TYPE',
            'message': 'Only "authorization_code" grant type is supported',
            'received': grant_type,
            'supported_types': ['authorization_code'],
            'how_to_fix': 'Use grant_type=authorization_code in your request'
        }), 400

    missing_params = []
    if not client_id:
        missing_params.append('client_id')
    if not client_secret:
        missing_params.append('client_secret')
    if not code:
        missing_params.append('code')
    if not redirect_uri:
        missing_params.append('redirect_uri')

    if missing_params:
        return jsonify({
            'error': 'Missing required parameters',
            'error_code': 'MISSING_PARAMETERS',
            'message': f'The following parameters are required: {", ".join(missing_params)}',
            'missing_parameters': missing_params,
            'how_to_fix': 'Include all required parameters in your POST request body'
        }), 400

    # Verify client credentials
    oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
    
    if not oauth_app:
        return jsonify({
            'error': 'Invalid client_id',
            'error_code': 'INVALID_CLIENT_ID',
            'message': 'The provided client_id does not exist or is disabled',
            'how_to_fix': 'Verify your client_id is correct and the OAuth application is active'
        }), 401

    if oauth_app.client_secret != client_secret:
        return jsonify({
            'error': 'Invalid client credentials',
            'error_code': 'INVALID_CLIENT_SECRET',
            'message': 'The provided client_secret is incorrect',
            'how_to_fix': 'Verify your client_secret is correct'
        }), 401

    # Verify authorization code
    auth_code = OAuthAuthorizationCode.query.filter_by(
        code=code,
        application_id=oauth_app.id,
        redirect_uri=redirect_uri,
        used=False
    ).first()

    if not auth_code:
        # Check for more specific error cases
        used_code = OAuthAuthorizationCode.query.filter_by(
            code=code,
            application_id=oauth_app.id,
            used=True
        ).first()
        
        if used_code:
            return jsonify({
                'error': 'Authorization code already used',
                'error_code': 'CODE_ALREADY_USED',
                'message': 'This authorization code has already been exchanged for tokens',
                'how_to_fix': 'Authorization codes can only be used once. Start a new OAuth flow to get a fresh code'
            }), 400

        wrong_redirect = OAuthAuthorizationCode.query.filter_by(
            code=code,
            application_id=oauth_app.id,
            used=False
        ).first()
        
        if wrong_redirect and wrong_redirect.redirect_uri != redirect_uri:
            return jsonify({
                'error': 'Redirect URI mismatch',
                'error_code': 'REDIRECT_URI_MISMATCH',
                'message': 'The redirect_uri does not match the one used during authorization',
                'expected': wrong_redirect.redirect_uri,
                'received': redirect_uri,
                'how_to_fix': 'Use the same redirect_uri that was used in the authorization request'
            }), 400

        return jsonify({
            'error': 'Invalid authorization code',
            'error_code': 'INVALID_AUTHORIZATION_CODE',
            'message': 'The provided authorization code is invalid or does not exist',
            'how_to_fix': 'Verify the authorization code is correct and has not expired'
        }), 400

    # Check if code is expired
    if auth_code.expires_at < datetime.now(timezone.utc):
        return jsonify({
            'error': 'Authorization code expired',
            'error_code': 'CODE_EXPIRED',
            'message': f'Authorization code expired at {auth_code.expires_at.isoformat()}',
            'expires_at': auth_code.expires_at.isoformat(),
            'how_to_fix': 'Authorization codes expire after 10 minutes. Start a new OAuth flow to get a fresh code'
        }), 400

    # Mark code as used
    auth_code.used = True

    # Generate access token
    oauth_token = OAuthToken(
        user_id=auth_code.user_id,
        application_id=oauth_app.id
    )
    oauth_token.generate_tokens()
    oauth_token.set_scopes(auth_code.get_scopes())

    db.session.add(oauth_token)
    db.session.commit()

    return jsonify({
        'access_token': oauth_token.access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': oauth_token.refresh_token,
        'scope': ' '.join(oauth_token.get_scopes())
    })

@app.route('/oauth/user', methods=['GET'])
@oauth_required()
@limiter.limit("200 per hour")
def oauth_user():
    user = request.oauth_user

    # Get current identity verification status and address information
    identity_status = 'unverified'
    rejection_reason = None
    address_info = None
    
    if user.identity_token:
        identity_info = hackclub_identity_service.get_user_identity(user.identity_token)
        if identity_info and 'identity' in identity_info:
            identity_status = identity_info['identity'].get('verification_status', 'unverified')
            rejection_reason = identity_info['identity'].get('rejection_reason')
            
            # Extract address information from various possible locations in response
            address_info = None
            
            app.logger.info(f"Full identity_info structure for address extraction: {json.dumps(identity_info, indent=2) if identity_info else 'None'}")
            
            # Check for address in different locations in the response
            if 'address' in identity_info:
                app.logger.info(f"Found address at root level: {identity_info['address']}")
                address_info = {
                    'street_address': identity_info['address'].get('street_address'),
                    'locality': identity_info['address'].get('locality'),
                    'region': identity_info['address'].get('region'),
                    'postal_code': identity_info['address'].get('postal_code'),
                    'country': identity_info['address'].get('country')
                }
            elif 'identity' in identity_info and 'address' in identity_info['identity']:
                # Sometimes address is nested under identity
                addr = identity_info['identity']['address']
                app.logger.info(f"Found address under identity: {addr}")
                address_info = {
                    'street_address': addr.get('street_address') or addr.get('line1'),
                    'locality': addr.get('locality') or addr.get('city'),
                    'region': addr.get('region') or addr.get('state'),
                    'postal_code': addr.get('postal_code') or addr.get('zip'),
                    'country': addr.get('country')
                }
            elif 'user' in identity_info and 'address' in identity_info['user']:
                # Check under user object
                addr = identity_info['user']['address']
                app.logger.info(f"Found address under user: {addr}")
                address_info = {
                    'street_address': addr.get('street_address') or addr.get('line1'),
                    'locality': addr.get('locality') or addr.get('city'),
                    'region': addr.get('region') or addr.get('state'),
                    'postal_code': addr.get('postal_code') or addr.get('zip'),
                    'country': addr.get('country')
                }
            else:
                app.logger.info("No address field found in any expected location")
                # Log all top-level keys to help debug structure
                if identity_info:
                    app.logger.info(f"Available top-level keys: {list(identity_info.keys())}")
                    if 'identity' in identity_info:
                        app.logger.info(f"Available identity keys: {list(identity_info['identity'].keys())}")
            
            # Filter out None/empty values
            if address_info:
                address_info = {k: v for k, v in address_info.items() if v}
                if not address_info:  # If all values were None/empty
                    address_info = None
            
            app.logger.info(f"Final extracted address info: {address_info}")
            
            # Update database if status changed
            verified = (identity_status == 'verified')
            if user.identity_verified != verified:
                user.identity_verified = verified
                db.session.commit()

    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'identity_verified': user.identity_verified,
        'identity_verification_status': identity_status,
        'identity_rejection_reason': rejection_reason,
        'address': address_info
    }

    return jsonify({'user': user_data})

@app.route('/oauth/user/clubs', methods=['GET'])
@oauth_required(['clubs:read'])
@limiter.limit("200 per hour")
def oauth_user_clubs():
    user = request.oauth_user
    
    # Get clubs where user is leader
    led_clubs = Club.query.filter_by(leader_id=user.id).all()
    
    # Get clubs where user is member
    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    member_clubs = [m.club for m in memberships]
    
    clubs_data = []
    
    # Add led clubs
    for club in led_clubs:
        airtable_data = club.get_airtable_data()
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'location': club.location,
            'role': 'leader',
            'member_count': len(club.members) + 1,
            'balance': float(club.balance),
            'join_code': club.join_code,
            'created_at': club.created_at.isoformat() if club.created_at else None,
            'airtable_data': airtable_data
        })
    
    # Add member clubs
    for club in member_clubs:
        airtable_data = club.get_airtable_data()
        membership = next(m for m in memberships if m.club_id == club.id)
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'location': club.location,
            'role': membership.role,
            'member_count': len(club.members) + 1,
            'joined_at': membership.joined_at.isoformat() if membership.joined_at else None,
            'airtable_data': airtable_data
        })
    
    return jsonify({
        'clubs': clubs_data,
        'total_clubs': len(clubs_data),
        'clubs_led': len(led_clubs),
        'clubs_joined': len(member_clubs)
    })

@app.route('/oauth/user/projects', methods=['GET'])
@oauth_required(['projects:read'])
@limiter.limit("200 per hour")
def oauth_user_projects():
    user = request.oauth_user
    
    # Get all projects by this user
    projects = ClubProject.query.filter_by(user_id=user.id).order_by(ClubProject.updated_at.desc()).all()
    
    projects_data = []
    for project in projects:
        projects_data.append({
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'url': project.url,
            'github_url': project.github_url,
            'featured': project.featured,
            'club': {
                'id': project.club.id,
                'name': project.club.name
            },
            'created_at': project.created_at.isoformat() if project.created_at else None,
            'updated_at': project.updated_at.isoformat() if project.updated_at else None
        })
    
    return jsonify({
        'projects': projects_data,
        'total_projects': len(projects_data)
    })

@app.route('/oauth/user/assignments', methods=['GET'])
@oauth_required(['assignments:read'])
@limiter.limit("200 per hour")
def oauth_user_assignments():
    user = request.oauth_user
    
    # Get clubs where user is member or leader
    led_club_ids = [club.id for club in Club.query.filter_by(leader_id=user.id).all()]
    member_club_ids = [m.club_id for m in ClubMembership.query.filter_by(user_id=user.id).all()]
    all_club_ids = list(set(led_club_ids + member_club_ids))
    
    # Get assignments from all user's clubs
    assignments = ClubAssignment.query.filter(ClubAssignment.club_id.in_(all_club_ids)).order_by(ClubAssignment.created_at.desc()).all()
    
    assignments_data = []
    for assignment in assignments:
        assignments_data.append({
            'id': assignment.id,
            'title': assignment.title,
            'description': assignment.description,
            'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
            'status': assignment.status,
            'club': {
                'id': assignment.club.id,
                'name': assignment.club.name
            },
            'created_at': assignment.created_at.isoformat() if assignment.created_at else None
        })
    
    return jsonify({
        'assignments': assignments_data,
        'total_assignments': len(assignments_data)
    })

@app.route('/oauth/user/meetings', methods=['GET'])
@oauth_required(['meetings:read'])
@limiter.limit("200 per hour")
def oauth_user_meetings():
    user = request.oauth_user
    
    # Get clubs where user is member or leader
    led_club_ids = [club.id for club in Club.query.filter_by(leader_id=user.id).all()]
    member_club_ids = [m.club_id for m in ClubMembership.query.filter_by(user_id=user.id).all()]
    all_club_ids = list(set(led_club_ids + member_club_ids))
    
    # Get meetings from all user's clubs
    meetings = ClubMeeting.query.filter(ClubMeeting.club_id.in_(all_club_ids)).order_by(ClubMeeting.meeting_date.desc()).all()
    
    meetings_data = []
    for meeting in meetings:
        meetings_data.append({
            'id': meeting.id,
            'title': meeting.title,
            'description': meeting.description,
            'meeting_date': meeting.meeting_date.isoformat(),
            'start_time': meeting.start_time,
            'end_time': meeting.end_time,
            'location': meeting.location,
            'meeting_link': meeting.meeting_link,
            'club': {
                'id': meeting.club.id,
                'name': meeting.club.name
            },
            'created_at': meeting.created_at.isoformat() if meeting.created_at else None
        })
    
    return jsonify({
        'meetings': meetings_data,
        'total_meetings': len(meetings_data)
    })



@app.route('/oauth/debug')
def oauth_debug():
    return render_template('oauth_debug.html')

@app.route('/oauth/debug/callback')
def oauth_debug_callback():
    # This is just a callback endpoint for the debug page
    # It will show the authorization code in the URL for testing
    return render_template('oauth_debug.html')

@app.route('/api/docs')
def api_documentation():
    return render_template('api_docs.html')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return render_template('429.html'), 429

if __name__ == '__main__':
    import logging

    # Configure logging for production
    if os.getenv('FLASK_ENV') == 'production':
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(name)s %(message)s',
            handlers=[logging.StreamHandler()]
        )
        app.logger.setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
        app.logger.setLevel(logging.DEBUG)

    try:
        with app.app_context():
            db.create_all()

            # Create super admin if doesn't exist
            super_admin = User.query.filter_by(email='ethan@hackclub.com').first()
            if not super_admin:
                super_admin = User(
                    username='ethan',
                    email='ethan@hackclub.com',
                    first_name='Ethan',
                    last_name='Davidson',
                    is_admin=True
                )
                super_admin.set_password('hackclub2024')
                db.session.add(super_admin)
                db.session.commit()
                app.logger.info("Created super admin account: ethan@hackclub.com / hackclub2024")
            else:
                super_admin.is_admin = True
                db.session.commit()
                app.logger.info("Super admin account exists and is active")

    except Exception as e:
        app.logger.error(f"Database setup error: {e}")

    port = int(os.getenv('PORT', 5000))
    app.logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)