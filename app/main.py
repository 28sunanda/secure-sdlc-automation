"""
Enterprise Application - Main Module

This is a realistic Flask application demonstrating both secure patterns
and common security issues for DevSecOps scanning demonstration.

Author: Sunanda Mandal
"""

import os
import logging
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS


# ============================================================================
# APPLICATION SETUP
# ============================================================================

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('ENV') == 'production'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['DATABASE'] = os.environ.get('DATABASE_PATH', 'app.db')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# CORS - Restrict in production
CORS(app, origins=os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(','))

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# DATABASE UTILITIES
# ============================================================================

def get_db():
    """Get database connection with row factory."""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database schema."""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        );
        
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL,
            name TEXT,
            scopes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    db.commit()


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

def hash_password(password: str) -> str:
    """
    Hash password using SHA-256 with salt.
    
    NOTE: In production, use bcrypt or argon2 instead.
    This is simplified for demonstration.
    """
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}${password_hash}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, password_hash = stored_hash.split('$')
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == password_hash
    except ValueError:
        return False


def generate_session_token() -> str:
    """Generate cryptographically secure session token."""
    return secrets.token_urlsafe(32)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password meets requirements"


def sanitize_log_data(data: dict) -> dict:
    """Remove sensitive fields from data before logging."""
    sensitive_fields = {'password', 'token', 'api_key', 'secret', 'credit_card', 'ssn'}
    return {k: '[REDACTED]' if k.lower() in sensitive_fields else v 
            for k, v in data.items()}


# ============================================================================
# AUTHENTICATION DECORATORS
# ============================================================================

def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header[7:]
        
        db = get_db()
        session = db.execute(
            '''SELECT s.*, u.id as user_id, u.username, u.role 
               FROM sessions s 
               JOIN users u ON s.user_id = u.id 
               WHERE s.id = ? AND s.expires_at > ?''',
            (token, datetime.now())
        ).fetchone()
        
        if not session:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        g.current_user = dict(session)
        return f(*args, **kwargs)
    
    return decorated


def require_role(role: str):
    """Decorator to require specific role."""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated(*args, **kwargs):
            if g.current_user['role'] != role:
                logger.warning(
                    f"Access denied for user {g.current_user['username']} "
                    f"to role-protected resource requiring {role}"
                )
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================================
# AUDIT LOGGING
# ============================================================================

def audit_log(action: str, resource: str = None, details: str = None):
    """Record action in audit log."""
    db = get_db()
    user_id = getattr(g, 'current_user', {}).get('user_id')
    
    db.execute(
        '''INSERT INTO audit_log (user_id, action, resource, ip_address, user_agent, details)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (
            user_id,
            action,
            resource,
            request.remote_addr,
            request.user_agent.string[:255] if request.user_agent else None,
            details
        )
    )
    db.commit()


# ============================================================================
# API ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/api/v1/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """
    Register a new user.
    
    SECURE: Uses parameterized queries, password validation, rate limiting.
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # Input validation
    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password required'}), 400
    
    if len(username) < 3 or len(username) > 50:
        return jsonify({'error': 'Username must be 3-50 characters'}), 400
    
    # Password strength validation
    is_valid, message = validate_password_strength(password)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    db = get_db()
    
    # Check if user exists (parameterized query - SECURE)
    existing = db.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    
    if existing:
        return jsonify({'error': 'Username or email already exists'}), 409
    
    # Create user
    password_hash = hash_password(password)
    
    try:
        cursor = db.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        db.commit()
        
        audit_log('USER_REGISTERED', f'user:{cursor.lastrowid}')
        logger.info(f"New user registered: {sanitize_log_data({'username': username})}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': cursor.lastrowid
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """
    Authenticate user and create session.
    
    SECURE: Account lockout, rate limiting, secure session generation.
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    db = get_db()
    
    # Get user (parameterized query - SECURE)
    user = db.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    
    if not user:
        # Don't reveal if username exists
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check account lockout
    if user['locked_until'] and datetime.fromisoformat(user['locked_until']) > datetime.now():
        return jsonify({'error': 'Account temporarily locked. Try again later.'}), 423
    
    # Verify password
    if not verify_password(password, user['password_hash']):
        # Increment failed attempts
        failed_attempts = user['failed_login_attempts'] + 1
        
        if failed_attempts >= 5:
            # Lock account for 15 minutes
            lock_until = datetime.now() + timedelta(minutes=15)
            db.execute(
                'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
                (failed_attempts, lock_until.isoformat(), user['id'])
            )
            db.commit()
            
            audit_log('ACCOUNT_LOCKED', f'user:{user["id"]}', f'Failed attempts: {failed_attempts}')
            logger.warning(f"Account locked due to failed attempts: user_id={user['id']}")
            
            return jsonify({'error': 'Account locked due to too many failed attempts'}), 423
        
        db.execute(
            'UPDATE users SET failed_login_attempts = ? WHERE id = ?',
            (failed_attempts, user['id'])
        )
        db.commit()
        
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Reset failed attempts on successful login
    db.execute(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
        (user['id'],)
    )
    
    # Create session
    session_token = generate_session_token()
    expires_at = datetime.now() + timedelta(hours=24)
    
    db.execute(
        '''INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent)
           VALUES (?, ?, ?, ?, ?)''',
        (
            session_token,
            user['id'],
            expires_at.isoformat(),
            request.remote_addr,
            request.user_agent.string[:255] if request.user_agent else None
        )
    )
    db.commit()
    
    audit_log('USER_LOGIN', f'user:{user["id"]}')
    
    return jsonify({
        'token': session_token,
        'expires_at': expires_at.isoformat(),
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
    })


@app.route('/api/v1/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Invalidate current session."""
    token = request.headers.get('Authorization', '')[7:]
    
    db = get_db()
    db.execute('DELETE FROM sessions WHERE id = ?', (token,))
    db.commit()
    
    audit_log('USER_LOGOUT')
    
    return jsonify({'message': 'Logged out successfully'})


@app.route('/api/v1/auth/sessions', methods=['GET'])
@require_auth
def list_sessions():
    """List all active sessions for current user."""
    db = get_db()
    
    sessions = db.execute(
        '''SELECT id, created_at, expires_at, ip_address, user_agent
           FROM sessions 
           WHERE user_id = ? AND expires_at > ?''',
        (g.current_user['user_id'], datetime.now())
    ).fetchall()
    
    return jsonify({
        'sessions': [dict(s) for s in sessions]
    })


@app.route('/api/v1/auth/sessions/<session_id>', methods=['DELETE'])
@require_auth
def revoke_session(session_id):
    """Revoke a specific session."""
    db = get_db()
    
    # Verify session belongs to current user (IDOR protection)
    session = db.execute(
        'SELECT * FROM sessions WHERE id = ? AND user_id = ?',
        (session_id, g.current_user['user_id'])
    ).fetchone()
    
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    db.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
    db.commit()
    
    audit_log('SESSION_REVOKED', f'session:{session_id}')
    
    return jsonify({'message': 'Session revoked'})


# ============================================================================
# API ROUTES - USER MANAGEMENT
# ============================================================================

@app.route('/api/v1/users/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user profile."""
    db = get_db()
    
    user = db.execute(
        'SELECT id, username, email, role, created_at FROM users WHERE id = ?',
        (g.current_user['user_id'],)
    ).fetchone()
    
    return jsonify(dict(user))


@app.route('/api/v1/users/me', methods=['PATCH'])
@require_auth
@limiter.limit("10 per hour")
def update_current_user():
    """Update current user profile."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    allowed_fields = {'email'}
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    
    if not updates:
        return jsonify({'error': 'No valid fields to update'}), 400
    
    db = get_db()
    
    # Build parameterized update query
    set_clause = ', '.join(f'{k} = ?' for k in updates.keys())
    values = list(updates.values()) + [g.current_user['user_id']]
    
    db.execute(
        f'UPDATE users SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        values
    )
    db.commit()
    
    audit_log('USER_UPDATED', f'user:{g.current_user["user_id"]}')
    
    return jsonify({'message': 'Profile updated'})


@app.route('/api/v1/users/me/password', methods=['PUT'])
@require_auth
@limiter.limit("3 per hour")
def change_password():
    """Change current user's password."""
    data = request.get_json()
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password required'}), 400
    
    # Validate new password strength
    is_valid, message = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    db = get_db()
    
    # Verify current password
    user = db.execute(
        'SELECT password_hash FROM users WHERE id = ?',
        (g.current_user['user_id'],)
    ).fetchone()
    
    if not verify_password(current_password, user['password_hash']):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update password
    new_hash = hash_password(new_password)
    db.execute(
        'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (new_hash, g.current_user['user_id'])
    )
    
    # Invalidate all other sessions (security best practice)
    current_token = request.headers.get('Authorization', '')[7:]
    db.execute(
        'DELETE FROM sessions WHERE user_id = ? AND id != ?',
        (g.current_user['user_id'], current_token)
    )
    db.commit()
    
    audit_log('PASSWORD_CHANGED', f'user:{g.current_user["user_id"]}')
    
    return jsonify({'message': 'Password changed successfully'})


# ============================================================================
# API ROUTES - ADMIN
# ============================================================================

@app.route('/api/v1/admin/users', methods=['GET'])
@require_role('admin')
def list_users():
    """List all users (admin only)."""
    db = get_db()
    
    users = db.execute(
        '''SELECT id, username, email, role, created_at, 
                  failed_login_attempts, locked_until 
           FROM users'''
    ).fetchall()
    
    return jsonify({
        'users': [dict(u) for u in users]
    })


@app.route('/api/v1/admin/audit-log', methods=['GET'])
@require_role('admin')
def get_audit_log():
    """Get audit log entries (admin only)."""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    # Prevent excessive queries
    limit = min(limit, 1000)
    
    db = get_db()
    
    logs = db.execute(
        '''SELECT a.*, u.username 
           FROM audit_log a
           LEFT JOIN users u ON a.user_id = u.id
           ORDER BY a.timestamp DESC
           LIMIT ? OFFSET ?''',
        (limit, offset)
    ).fetchall()
    
    return jsonify({
        'logs': [dict(log) for log in logs],
        'limit': limit,
        'offset': offset
    })


# ============================================================================
# HEALTH CHECK & METRICS
# ============================================================================

@app.route('/health')
def health_check():
    """Application health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/v1/metrics')
@require_role('admin')
def metrics():
    """Application metrics (admin only)."""
    db = get_db()
    
    user_count = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    session_count = db.execute(
        'SELECT COUNT(*) as count FROM sessions WHERE expires_at > ?',
        (datetime.now(),)
    ).fetchone()['count']
    
    return jsonify({
        'users': user_count,
        'active_sessions': session_count,
        'timestamp': datetime.now().isoformat()
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429


@app.errorhandler(500)
def internal_error(error):
    # Log the actual error internally
    logger.error(f"Internal error: {error}")
    # Return generic message to user
    return jsonify({'error': 'An internal error occurred'}), 500


# ============================================================================
# APPLICATION STARTUP
# ============================================================================

@app.before_request
def before_request():
    """Pre-request processing."""
    # Security headers
    pass


@app.after_request
def after_request(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    if os.environ.get('ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response


def create_app():
    """Application factory."""
    with app.app_context():
        init_db()
    return app


if __name__ == '__main__':
    create_app()
    
    # Only for development - use gunicorn in production
    debug_mode = os.environ.get('ENV') != 'production'
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 8080)),
        debug=debug_mode
    )
