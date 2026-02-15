import os
import json
import uuid
import random
import time
import sys
from datetime import datetime, timedelta, timezone
from functools import wraps

# ========== FLASK & EXTENSIONS ==========
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_, func, desc
from sqlalchemy.orm import joinedload

# ========== TWILIO FOR SMS ==========
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

print("=" * 50)
print("🔍 DIAGNOSTIC MODE")
print(f"Current directory: {os.getcwd()}")
print(f"Files in directory: {os.listdir('.')}")

if os.path.exists('runtime.txt'):
    with open('runtime.txt', 'r') as f:
        content = f.read().strip()
        print(f"✅ runtime.txt found! Content: '{content}'")
else:
    print("❌ runtime.txt NOT found in current directory")
    print("Files in parent directory:", os.listdir('..') if os.path.exists('..') else "No parent")

print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print("=" * 50)

# ========== INITIALIZE APP ==========
app = Flask(__name__)

# ========== CONFIGURATION ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'hpz-production-secret-key-2024')
    
    # Database - FIXED for Render PostgreSQL
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    
    # Handle Render's PostgreSQL URL (starts with postgres:// instead of postgresql://)
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = database_url or f'sqlite:///{os.path.join(BASEDIR, "hpz_database.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'pool_size': 20,
        'max_overflow': 40
    }
    
    # Upload
    UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 
                          'webm', 'mp3', 'wav', 'ogg', 'pdf', 'doc', 'docx', 'txt'}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    
    # Session - FIXED for production
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # True in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_REFRESH_EACH_REQUEST = True
    
    # Features
    ONLINE_TIMEOUT = 300
    TYPING_TIMEOUT = 3
    MAX_SEARCH_RESULTS = 30
    MAX_MESSAGES_LOAD = 50

app.config.from_object(Config)

# ========== INITIALIZE EXTENSIONS ==========
db = SQLAlchemy(app)
CORS(app, supports_credentials=True)

# SocketIO - FIXED for production
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=True,
    engineio_logger=True
)

# ========== TWILIO CLIENT INITIALIZATION ==========
def get_twilio_client():
    """Initialize and return Twilio client"""
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    
    if not account_sid or not auth_token:
        print("⚠️ WARNING: Twilio credentials not configured")
        return None
    
    return Client(account_sid, auth_token)

# ========== DATABASE MODELS ==========
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    profile = db.relationship('UserProfile', back_populates='user', uselist=False, cascade='all, delete-orphan')
    sent_messages = db.relationship('ChatMessage', foreign_keys='ChatMessage.sender_id', back_populates='sender')
    friendships_1 = db.relationship('Friendship', foreign_keys='Friendship.user1_id', back_populates='user1')
    friendships_2 = db.relationship('Friendship', foreign_keys='Friendship.user2_id', back_populates='user2')
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.from_user_id', back_populates='from_user')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.to_user_id', back_populates='to_user')
    blocked = db.relationship('BlockedUser', foreign_keys='BlockedUser.blocker_id', back_populates='blocker')
    blocked_by = db.relationship('BlockedUser', foreign_keys='BlockedUser.blocked_id', back_populates='blocked')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False, index=True)
    bio = db.Column(db.String(500), default='')
    avatar_url = db.Column(db.String(500))
    status = db.Column(db.String(100), default='Available')
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    theme = db.Column(db.String(20), default='light')
    notification_sound = db.Column(db.String(50), default='default')
    message_preview = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    _privacy_settings = db.Column('privacy_settings', db.Text, default='{}')
    
    @property
    def privacy_settings(self):
        if self._privacy_settings:
            return json.loads(self._privacy_settings)
        return {
            'last_seen': 'everyone',
            'profile_photo': 'everyone',
            'status': 'everyone',
            'read_receipts': True,
            'typing_indicator': True
        }
    
    @privacy_settings.setter
    def privacy_settings(self, value):
        self._privacy_settings = json.dumps(value)
    
    user = db.relationship('User', back_populates='profile')
    
    def to_dict(self, include_private=False):
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'status': self.status,
            'theme': self.theme,
            'notification_sound': self.notification_sound,
            'message_preview': self.message_preview
        }
        if include_private:
            data['privacy_settings'] = self.privacy_settings
        return data

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    message_type = db.Column(db.String(20), default='text')
    content = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(200))
    file_url = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    file_duration = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    delivered_at = db.Column(db.DateTime)
    read_at = db.Column(db.DateTime)
    is_edited = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('chat_messages.id'))
    
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    replies = db.relationship('ChatMessage', backref=db.backref('parent', remote_side=[id]))
    
    def to_dict(self):
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'sender_id': self.sender_id,
            'sender_username': self.sender.username if self.sender else None,
            'sender_avatar': UserProfile.query.filter_by(user_id=self.sender_id).first().avatar_url if self.sender else None,
            'message_type': self.message_type,
            'content': self.content if not self.is_deleted else '[Message deleted]',
            'filename': self.filename,
            'file_url': self.file_url,
            'file_size': self.file_size,
            'file_duration': self.file_duration,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'delivered_at': self.delivered_at.isoformat() if self.delivered_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'is_edited': self.is_edited,
            'is_deleted': self.is_deleted,
            'reply_to_id': self.reply_to_id
        }

class Friendship(db.Model):
    __tablename__ = 'friendships'
    
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    __table_args__ = (
        db.UniqueConstraint('user1_id', 'user2_id', name='unique_friendship'),
        db.CheckConstraint('user1_id < user2_id', name='check_user_order'),
    )
    
    user1 = db.relationship('User', foreign_keys=[user1_id], back_populates='friendships_1')
    user2 = db.relationship('User', foreign_keys=[user2_id], back_populates='friendships_2')

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    message = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    __table_args__ = (
        db.UniqueConstraint('from_user_id', 'to_user_id', name='unique_request'),
    )
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], back_populates='sent_requests')
    to_user = db.relationship('User', foreign_keys=[to_user_id], back_populates='received_requests')

class BlockedUser(db.Model):
    __tablename__ = 'blocked_users'
    
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    blocked_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    reason = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    __table_args__ = (
        db.UniqueConstraint('blocker_id', 'blocked_id', name='unique_block'),
    )
    
    blocker = db.relationship('User', foreign_keys=[blocker_id], back_populates='blocked')
    blocked = db.relationship('User', foreign_keys=[blocked_id], back_populates='blocked_by')

# ========== HELPER FUNCTIONS ==========

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file, folder):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
        os.makedirs(upload_path, exist_ok=True)
        
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        file.save(os.path.join(upload_path, unique_filename))
        
        url = f"/static/uploads/{folder}/{unique_filename}"
        return url, filename, file_size
    return None, None, None

def get_time_ago(dt):
    if not dt:
        return 'Never'
    
    now = datetime.now(timezone.utc)
    diff = now - dt
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return 'Just now'
    elif seconds < 3600:
        return f'{int(seconds / 60)}m ago'
    elif seconds < 86400:
        return f'{int(seconds / 3600)}h ago'
    elif seconds < 604800:
        return f'{int(seconds / 86400)}d ago'
    elif seconds < 2592000:
        return f'{int(seconds / 604800)}w ago'
    else:
        return dt.strftime('%b %d, %Y')

def get_chat_id(user1_id, user2_id):
    return f"{min(user1_id, user2_id)}-{max(user1_id, user2_id)}"

def is_online(user_id):
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    if profile and profile.last_seen:
        diff = datetime.now(timezone.utc) - profile.last_seen
        return diff.total_seconds() < app.config['ONLINE_TIMEOUT']
    return False

# ========== VERIFICATION HELPERS ==========

# Store verification codes temporarily (use Redis in production)
verification_codes = {}

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def cleanup_expired_codes():
    """Remove expired verification codes (older than 10 minutes)"""
    current_time = time.time()
    expired = [k for k, v in verification_codes.items() 
               if current_time - v['timestamp'] > 600]
    for key in expired:
        del verification_codes[key]
        print(f"🗑️ Cleaned up expired code for: {key}")

# ========== ERROR HANDLERS ==========

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'success': False, 'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# ========== PAGE ROUTES ==========

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return render_template('register.html')

@app.route('/chat')
@login_required
def chat_page():
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
    
    return render_template('chat.html',
                          user=user,
                          profile=profile,
                          user_id=user.id,
                          username=user.username)

# ========== 🔐 AUTHENTICATION ROUTES ==========

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')
        
        if not identifier or not password:
            return jsonify({'success': False, 'error': 'Username/Email/Phone and password required'}), 400
        
        user = User.query.filter(
            (User.username == identifier) |
            (User.email == identifier) |
            (User.phone == identifier)
        ).first()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 401
        
        if not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid password'}), 401
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        if profile:
            profile.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'message': 'Login successful!',
            'user': user.to_dict()
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed. Please try again.'}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip() or None
        phone = data.get('phone', '').strip() or None
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already taken'}), 400
        
        if email and User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        if phone and User.query.filter_by(phone=phone).first():
            return jsonify({'success': False, 'error': 'Phone number already registered'}), 400
        
        user = User(
            username=username,
            email=email,
            phone=phone
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        
        profile = UserProfile(
            user_id=user.id,
            status='Available',
            bio=''
        )
        db.session.add(profile)
        db.session.commit()
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'message': 'Registration successful!',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed. Please try again.'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    user_id = session.get('user_id')
    
    if user_id:
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        socketio.emit('user_offline', {
            'user_id': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room='hpz_global')
    
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/check', methods=['GET'])
def check_auth():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            return jsonify({
                'success': True,
                'authenticated': True,
                'user': user.to_dict()
            })
    
    return jsonify({
        'success': True,
        'authenticated': False
    })

# ========== 📱 PHONE/EMAIL VERIFICATION ROUTES ==========

@app.route('/api/verification/send-phone', methods=['POST'])
def send_phone_verification():
    """Send verification code via SMS using Twilio"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number', '').strip()
        dial_code = data.get('dial_code', '').strip()
        
        if not phone_number:
            return jsonify({'success': False, 'error': 'Phone number required'}), 400
        
        # Format phone number to E.164 format
        full_phone = f"{dial_code}{phone_number}"
        
        # Validate format (basic check)
        if not full_phone.startswith('+'):
            return jsonify({'success': False, 'error': 'Invalid phone format. Must include country code'}), 400
        
        # Check if phone already registered
        if User.query.filter_by(phone=full_phone).first():
            return jsonify({'success': False, 'error': 'Phone number already registered'}), 400
        
        # Generate verification code
        code = generate_verification_code()
        
        # Get Twilio client
        twilio_client = get_twilio_client()
        
        if twilio_client:
            # Send SMS via Twilio
            try:
                twilio_phone = os.environ.get('TWILIO_PHONE_NUMBER')
                
                if not twilio_phone:
                    return jsonify({'success': False, 'error': 'SMS service not configured'}), 500
                
                message = twilio_client.messages.create(
                    body=f"Your HPZ verification code is: {code}\n\nThis code will expire in 10 minutes.",
                    from_=twilio_phone,
                    to=full_phone
                )
                
                print(f"✅ SMS sent to {full_phone} (SID: {message.sid})")
                
                # Store code with timestamp
                cleanup_expired_codes()
                verification_codes[full_phone] = {
                    'code': code,
                    'timestamp': time.time(),
                    'method': 'phone',
                    'attempts': 0
                }
                
                return jsonify({
                    'success': True,
                    'message': 'Verification code sent to your phone',
                    'phone': full_phone  # Return formatted phone for frontend
                })
                
            except TwilioRestException as e:
                print(f"❌ Twilio error: {e}")
                
                # Handle specific Twilio errors
                if e.code == 21408:  # Permission to send to this number
                    return jsonify({'success': False, 'error': 'Cannot send to this number. If using trial account, verify number first.'}), 400
                elif e.code == 21211:  # Invalid phone number
                    return jsonify({'success': False, 'error': 'Invalid phone number format'}), 400
                else:
                    return jsonify({'success': False, 'error': f'SMS service error: {str(e)}'}), 500
        
        else:
            # Fallback for development (no Twilio credentials)
            print(f"📱 DEVELOPMENT MODE - Verification code for {full_phone}: {code}")
            
            verification_codes[full_phone] = {
                'code': code,
                'timestamp': time.time(),
                'method': 'phone',
                'attempts': 0
            }
            
            # Return code in development mode only
            return jsonify({
                'success': True,
                'message': 'Verification code sent (dev mode)',
                'phone': full_phone,
                'dev_code': code  # Only in development!
            })
            
    except Exception as e:
        print(f"❌ Phone verification error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Failed to send verification code'}), 500

@app.route('/api/verification/send-email', methods=['POST'])
def send_email_verification():
    """Send verification code via email (placeholder - implement with SendGrid/AWS SES)"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({'success': False, 'error': 'Email required'}), 400
        
        # Basic email validation
        if '@' not in email or '.' not in email:
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        # Check if email already registered
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Generate code
        code = generate_verification_code()
        
        # TODO: Implement actual email sending with SendGrid/AWS SES
        # For now, just log it
        print(f"📧 Verification code for {email}: {code}")
        
        cleanup_expired_codes()
        verification_codes[email] = {
            'code': code,
            'timestamp': time.time(),
            'method': 'email',
            'attempts': 0
        }
        
        return jsonify({
            'success': True,
            'message': 'Verification code sent to your email',
            'email': email,
            'dev_code': code  # Remove in production!
        })
        
    except Exception as e:
        print(f"❌ Email verification error: {e}")
        return jsonify({'success': False, 'error': 'Failed to send verification code'}), 500

@app.route('/api/verification/verify-code', methods=['POST'])
def verify_code():
    """Verify the code entered by user"""
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()  # phone or email
        code = data.get('code', '').strip()
        
        if not identifier or not code:
            return jsonify({'success': False, 'error': 'Code and identifier required'}), 400
        
        cleanup_expired_codes()
        
        # Check if code exists
        if identifier not in verification_codes:
            return jsonify({'success': False, 'error': 'Verification code expired or not found'}), 400
        
        stored_data = verification_codes[identifier]
        
        # Check expiration (10 minutes)
        if time.time() - stored_data['timestamp'] > 600:
            del verification_codes[identifier]
            return jsonify({'success': False, 'error': 'Verification code expired'}), 400
        
        # Rate limiting - max 5 attempts
        if stored_data['attempts'] >= 5:
            del verification_codes[identifier]
            return jsonify({'success': False, 'error': 'Too many failed attempts. Request a new code.'}), 429
        
        # Verify code
        if stored_data['code'] == code:
            # Code is valid - mark as verified but don't delete yet
            # We'll delete it after successful registration
            verification_codes[identifier]['verified'] = True
            
            return jsonify({
                'success': True,
                'message': 'Code verified successfully',
                'verified': True
            })
        else:
            # Increment attempts
            stored_data['attempts'] += 1
            remaining = 5 - stored_data['attempts']
            
            return jsonify({
                'success': False,
                'error': f'Invalid code. {remaining} attempts remaining',
                'attempts_remaining': remaining
            }), 400
            
    except Exception as e:
        print(f"❌ Verify code error: {e}")
        return jsonify({'success': False, 'error': 'Verification failed'}), 500

@app.route('/api/verification/complete-registration', methods=['POST'])
def complete_registration():
    """Complete registration after verification"""
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()  # phone or email
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not all([identifier, username, password]):
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        
        # Validation
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        # Check if code was verified
        if identifier not in verification_codes:
            return jsonify({'success': False, 'error': 'Please verify your code first'}), 400
        
        stored_data = verification_codes[identifier]
        
        if not stored_data.get('verified'):
            return jsonify({'success': False, 'error': 'Please verify your code first'}), 400
        
        # Check username availability
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already taken'}), 400
        
        # Create user
        if stored_data['method'] == 'phone':
            new_user = User(username=username, phone=identifier)
        else:
            new_user = User(username=username, email=identifier)
        
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()
        
        # Create profile
        profile = UserProfile(
            user_id=new_user.id,
            status='Available',
            bio=''
        )
        db.session.add(profile)
        db.session.commit()
        
        # Clean up verification code
        del verification_codes[identifier]
        
        # Auto-login
        session.permanent = True
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        
        print(f"✅ New user registered: {username} ({identifier})")
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'message': 'Registration successful!',
            'user': new_user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Complete registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

@app.route('/api/verification/resend', methods=['POST'])
def resend_verification():
    """Resend verification code"""
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()
        method = data.get('method', 'phone')  # 'phone' or 'email'
        
        if not identifier:
            return jsonify({'success': False, 'error': 'Identifier required'}), 400
        
        # Rate limiting - allow resend only after 60 seconds
        if identifier in verification_codes:
            time_since = time.time() - verification_codes[identifier]['timestamp']
            if time_since < 60:
                wait_time = int(60 - time_since)
                return jsonify({
                    'success': False,
                    'error': f'Please wait {wait_time} seconds before requesting a new code'
                }), 429
        
        # Resend based on method
        if method == 'phone':
            # Extract parts from full phone number
            if identifier.startswith('+'):
                # Assume dial code is first 1-4 characters after +
                dial_code = identifier[:4] if len(identifier) > 4 else identifier[:2]
                phone_number = identifier[len(dial_code):]
                
                # Create new request data
                new_data = {
                    'phone_number': phone_number,
                    'dial_code': dial_code
                }
                
                # Manually call send_phone_verification logic
                return send_phone_verification()
        else:
            # Create new request data
            new_data = {'email': identifier}
            return send_email_verification()
            
    except Exception as e:
        print(f"❌ Resend error: {e}")
        return jsonify({'success': False, 'error': 'Failed to resend code'}), 500

# ========== LEGACY VERIFICATION ROUTES (KEEP FOR BACKWARD COMPATIBILITY) ==========

@app.route('/register_phone', methods=['POST'])
def register_phone():
    """Legacy endpoint - redirects to new verification system"""
    return send_phone_verification()

@app.route('/register_email', methods=['POST'])
def register_email():
    """Legacy endpoint - redirects to new verification system"""
    return send_email_verification()

@app.route('/complete_registration', methods=['POST'])
def legacy_complete_registration():
    """Legacy endpoint - redirects to new verification system"""
    try:
        data = request.get_json()
        code = data.get('code')
        username = data.get('username')
        password = data.get('password')
        
        if not all([code, username, password]):
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        
        # Find identifier by code
        found = None
        identifier = None
        
        for key, value in verification_codes.items():
            if value['code'] == code:
                if time.time() - value['timestamp'] < 600:
                    found = value
                    identifier = key
                break
        
        if not found:
            return jsonify({'success': False, 'error': 'Invalid or expired code'}), 400
        
        # Mark as verified
        verification_codes[identifier]['verified'] = True
        
        # Call complete registration
        return complete_registration()
        
    except Exception as e:
        print(f"❌ Legacy complete registration error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

# ========== 🔍 FIXED TELEGRAM-STYLE USER SEARCH ==========

@app.route('/api/users/search', methods=['GET'])
@login_required
def search_users():
    """🔍 FIXED: Search ALL users - Shows EVERYONE except yourself"""
    current_user_id = session.get('user_id')
    query = request.args.get('q', '').strip()
    
    print(f"🔍 SEARCH: User {current_user_id} searching for '{query}'")
    
    if not query or len(query) < 1:
        return jsonify({'success': True, 'results': [], 'count': 0})
    
    try:
        # Get ALL users except current user - SIMPLE AND FAST!
        users = User.query.filter(
            User.id != current_user_id,
            User.username.ilike(f'%{query}%')
        ).limit(app.config['MAX_SEARCH_RESULTS']).all()
        
        print(f"📊 Found {len(users)} users matching '{query}'")
        
        results = []
        for user in users:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            
            # Check if friends
            is_friend = Friendship.query.filter(
                ((Friendship.user1_id == current_user_id) & (Friendship.user2_id == user.id)) |
                ((Friendship.user1_id == user.id) & (Friendship.user2_id == current_user_id))
            ).first() is not None
            
            # Check pending requests
            request_sent = FriendRequest.query.filter_by(
                from_user_id=current_user_id, to_user_id=user.id, status='pending'
            ).first() is not None
            
            request_received = FriendRequest.query.filter_by(
                from_user_id=user.id, to_user_id=current_user_id, status='pending'
            ).first() is not None
            
            # Online status
            online_status = is_online(user.id)
            last_seen = 'Online' if online_status else get_time_ago(profile.last_seen) if profile and profile.last_seen else 'Offline'
            
            # Avatar
            avatar = profile.avatar_url if profile and profile.avatar_url else \
                     f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff&size=128"
            
            # Relationship status
            if is_friend:
                relationship = 'friend'
                action_text = 'Message'
                action_icon = '💬'
                action_color = '#0088cc'
                action_disabled = False
            elif request_sent:
                relationship = 'request_sent'
                action_text = 'Pending'
                action_icon = '⏳'
                action_color = '#ff9800'
                action_disabled = True
            elif request_received:
                relationship = 'request_received'
                action_text = 'Accept'
                action_icon = '✅'
                action_color = '#4CAF50'
                action_disabled = False
            else:
                relationship = 'none'
                action_text = 'Add Friend'
                action_icon = '➕'
                action_color = '#747F8D'
                action_disabled = False
            
            results.append({
                'id': user.id,
                'username': user.username,
                'avatar': avatar,
                'avatar_url': avatar,
                'status': profile.status if profile else 'Available',
                'bio': profile.bio if profile else '',
                'is_online': online_status,
                'last_seen': last_seen,
                'relationship': relationship,
                'is_friend': is_friend,
                'action': {
                    'text': action_text,
                    'icon': action_icon,
                    'color': action_color,
                    'disabled': action_disabled
                }
            })
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results),
            'query': query
        })
        
    except Exception as e:
        print(f"❌ SEARCH ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Search failed'}), 500

# ========== PROFILE ROUTES ==========

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    user = get_current_user()
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    
    if not profile:
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
    
    return jsonify({
        'success': True,
        'user': user.to_dict(),
        'profile': profile.to_dict(include_private=True)
    })

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    user = get_current_user()
    data = request.get_json()
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    
    if not profile:
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
    
    try:
        if 'username' in data and data['username'] != user.username:
            existing = User.query.filter_by(username=data['username']).first()
            if existing and existing.id != user.id:
                return jsonify({'success': False, 'error': 'Username taken'}), 400
            user.username = data['username']
            session['username'] = data['username']
        
        if 'email' in data:
            user.email = data['email'] if data['email'] else None
        
        if 'bio' in data:
            profile.bio = data['bio'][:500]
        
        if 'status' in data:
            profile.status = data['status'][:100]
        
        if 'theme' in data:
            profile.theme = data['theme']
        
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Update failed'}), 500

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    user_id = session.get('user_id')
    
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    
    file = request.files['avatar']
    url, filename, size = save_uploaded_file(file, 'avatars')
    
    if not url:
        return jsonify({'success': False, 'error': 'Invalid file'}), 400
    
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    profile.avatar_url = url
    db.session.commit()
    
    return jsonify({'success': True, 'url': url})

# ========== 👥 FRIEND MANAGEMENT ==========

@app.route('/api/friends', methods=['GET'])
@login_required
def get_friends():
    user_id = session.get('user_id')
    
    friendships = Friendship.query.filter(
        (Friendship.user1_id == user_id) | (Friendship.user2_id == user_id)
    ).all()
    
    friends = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.get(friend_id)
        profile = UserProfile.query.filter_by(user_id=friend_id).first()
        
        chat_id = get_chat_id(user_id, friend_id)
        last_message = ChatMessage.query.filter_by(chat_id=chat_id).order_by(
            ChatMessage.created_at.desc()
        ).first()
        
        unread = ChatMessage.query.filter_by(
            chat_id=chat_id
        ).filter(
            ChatMessage.sender_id == friend_id,
            ChatMessage.read_at.is_(None)
        ).count()
        
        friends.append({
            'id': friend.id,
            'username': friend.username,
            'avatarUrl': profile.avatar_url if profile else None,
            'status': profile.status if profile else None,
            'isOnline': is_online(friend_id),
            'lastSeen': get_time_ago(profile.last_seen) if profile and profile.last_seen else 'Never',
            'lastMessage': last_message.to_dict() if last_message else None,
            'unreadCount': unread,
            'chat_id': chat_id
        })
    
    return jsonify({'success': True, 'contacts': friends})

@app.route('/api/friends/pending', methods=['GET'])
@login_required
def get_pending_requests():
    user_id = session.get('user_id')
    
    received = FriendRequest.query.filter_by(
        to_user_id=user_id, status='pending'
    ).order_by(FriendRequest.created_at.desc()).all()
    
    sent = FriendRequest.query.filter_by(
        from_user_id=user_id, status='pending'
    ).order_by(FriendRequest.created_at.desc()).all()
    
    received_list = []
    for req in received:
        user = User.query.get(req.from_user_id)
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        received_list.append({
            'request_id': req.id,
            'user_id': user.id,
            'username': user.username,
            'avatar_url': profile.avatar_url if profile else None,
            'created_at': req.created_at.isoformat(),
            'time_ago': get_time_ago(req.created_at)
        })
    
    sent_list = []
    for req in sent:
        user = User.query.get(req.to_user_id)
        sent_list.append({
            'id': req.id,
            'user_id': user.id,
            'username': user.username,
            'created_at': req.created_at.isoformat()
        })
    
    return jsonify({
        'success': True,
        'received': received_list,
        'sent': sent_list
    })

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    user_id = session.get('user_id')
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    
    if not to_user_id or user_id == to_user_id:
        return jsonify({'success': False, 'error': 'Invalid user'}), 400
    
    existing = Friendship.query.filter(
        ((Friendship.user1_id == user_id) & (Friendship.user2_id == to_user_id)) |
        ((Friendship.user1_id == to_user_id) & (Friendship.user2_id == user_id))
    ).first()
    
    if existing:
        return jsonify({'success': False, 'error': 'Already friends'}), 400
    
    existing_req = FriendRequest.query.filter(
        ((FriendRequest.from_user_id == user_id) & (FriendRequest.to_user_id == to_user_id)) |
        ((FriendRequest.from_user_id == to_user_id) & (FriendRequest.to_user_id == user_id)),
        FriendRequest.status == 'pending'
    ).first()
    
    if existing_req:
        if existing_req.from_user_id == user_id:
            return jsonify({'success': False, 'error': 'Request already sent'}), 400
        else:
            existing_req.status = 'accepted'
            user1 = min(user_id, to_user_id)
            user2 = max(user_id, to_user_id)
            friendship = Friendship(user1_id=user1, user2_id=user2)
            db.session.add(friendship)
            db.session.commit()
            
            socketio.emit('friend_added', {
                'friend_id': to_user_id,
                'friend_username': User.query.get(to_user_id).username
            }, room=f'user_{user_id}')
            
            return jsonify({'success': True, 'auto_accepted': True})
    
    friend_req = FriendRequest(from_user_id=user_id, to_user_id=to_user_id)
    db.session.add(friend_req)
    db.session.commit()
    
    socketio.emit('friend_request_received', {
        'from_user_id': user_id,
        'from_username': session.get('username')
    }, room=f'user_{to_user_id}')
    
    return jsonify({'success': True})

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    user_id = session.get('user_id')
    data = request.get_json()
    request_id = data.get('request_id')
    
    friend_req = FriendRequest.query.filter_by(
        id=request_id, to_user_id=user_id, status='pending'
    ).first()
    
    if not friend_req:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    friend_req.status = 'accepted'
    
    user1 = min(friend_req.from_user_id, user_id)
    user2 = max(friend_req.from_user_id, user_id)
    friendship = Friendship(user1_id=user1, user2_id=user2)
    db.session.add(friendship)
    db.session.commit()
    
    from_user = User.query.get(friend_req.from_user_id)
    socketio.emit('friend_added', {
        'friend_id': from_user.id,
        'friend_username': from_user.username
    }, room=f'user_{user_id}')
    
    return jsonify({'success': True})

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend_request():
    user_id = session.get('user_id')
    data = request.get_json()
    request_id = data.get('request_id')
    
    friend_req = FriendRequest.query.filter_by(
        id=request_id, to_user_id=user_id, status='pending'
    ).first()
    
    if not friend_req:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    db.session.delete(friend_req)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/friends/remove', methods=['POST'])
@login_required
def remove_friend():
    user_id = session.get('user_id')
    data = request.get_json()
    friend_id = data.get('friend_id')
    
    friendship = Friendship.query.filter(
        ((Friendship.user1_id == user_id) & (Friendship.user2_id == friend_id)) |
        ((Friendship.user1_id == friend_id) & (Friendship.user2_id == user_id))
    ).first()
    
    if not friendship:
        return jsonify({'success': False, 'error': 'Friendship not found'}), 404
    
    db.session.delete(friendship)
    db.session.commit()
    
    return jsonify({'success': True})

# ========== 💬 MESSAGING ROUTES ==========

@app.route('/api/messages/<chat_id>', methods=['GET'])
@login_required
def get_messages(chat_id):
    user_id = session.get('user_id')
    limit = request.args.get('limit', 50, type=int)
    
    messages = ChatMessage.query.filter_by(
        chat_id=chat_id, is_deleted=False
    ).order_by(
        ChatMessage.created_at.desc()
    ).limit(limit).all()
    
    messages.reverse()
    
    if chat_id != 'global':
        ChatMessage.query.filter(
            ChatMessage.chat_id == chat_id,
            ChatMessage.sender_id != user_id,
            ChatMessage.delivered_at.is_(None)
        ).update({'delivered_at': datetime.now(timezone.utc)})
        db.session.commit()
    
    return jsonify({
        'success': True,
        'messages': [m.to_dict() for m in messages]
    })

@app.route('/api/messages/read', methods=['POST'])
@login_required
def mark_messages_read():
    user_id = session.get('user_id')
    data = request.get_json()
    chat_id = data.get('chat_id')
    
    ChatMessage.query.filter_by(
        chat_id=chat_id
    ).filter(
        ChatMessage.sender_id != user_id,
        ChatMessage.read_at.is_(None)
    ).update({'read_at': datetime.now(timezone.utc)})
    
    db.session.commit()
    
    socketio.emit('messages_read', {
        'chat_id': chat_id,
        'user_id': user_id
    }, room=f'chat_{chat_id}')
    
    return jsonify({'success': True})

# ========== 📁 FILE UPLOAD ==========

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    
    file = request.files['file']
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
        folder = 'images'
        file_type = 'image'
    elif ext in ['mp4', 'mov', 'avi', 'webm']:
        folder = 'videos'
        file_type = 'video'
    elif ext in ['mp3', 'wav', 'ogg', 'm4a']:
        folder = 'audio'
        file_type = 'audio'
    else:
        folder = 'files'
        file_type = 'file'
    
    url, filename, size = save_uploaded_file(file, folder)
    
    if url:
        return jsonify({
            'success': True,
            'url': url,
            'filename': filename,
            'size': size,
            'type': file_type
        })
    
    return jsonify({'success': False, 'error': 'Upload failed'}), 500

# ========== 🔌 SOCKET.IO EVENTS - REAL-TIME ==========

connected_users = {}
user_sockets = {}

@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id and username:
        sid = request.sid
        connected_users[sid] = user_id
        
        if user_id not in user_sockets:
            user_sockets[user_id] = []
        user_sockets[user_id].append(sid)
        
        join_room('hpz_global')
        join_room(f'user_{user_id}')
        
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        socketio.emit('user_online', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room='hpz_global', skip_sid=sid)
        
        print(f"✅ Connected: {username}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    
    if sid in connected_users:
        user_id = connected_users[sid]
        del connected_users[sid]
        
        if user_id in user_sockets:
            if sid in user_sockets[user_id]:
                user_sockets[user_id].remove(sid)
            
            if not user_sockets[user_id]:
                del user_sockets[user_id]
                
                profile = UserProfile.query.filter_by(user_id=user_id).first()
                if profile:
                    profile.last_seen = datetime.now(timezone.utc)
                    db.session.commit()
                
                socketio.emit('user_offline', {
                    'user_id': user_id,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, room='hpz_global')
                
                print(f"❌ Offline: {user_id}")

@socketio.on('join')
def handle_join(data):
    chat_id = data.get('chatId')
    if chat_id and chat_id != 'global':
        join_room(f'chat_{chat_id}')

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id or not username:
        return
    
    try:
        chat_id = data.get('chatId')
        
        message = ChatMessage(
            chat_id=chat_id,
            sender_id=user_id,
            message_type=data.get('type', 'text'),
            content=data.get('content', ''),
            filename=data.get('filename'),
            file_url=data.get('fileUrl'),
            file_size=data.get('fileSize'),
            reply_to_id=data.get('replyToId')
        )
        db.session.add(message)
        db.session.commit()
        
        message_data = message.to_dict()
        message_data['sender_username'] = username
        
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        message_data['sender_avatar'] = profile.avatar_url if profile else None
        
        if chat_id == 'global':
            socketio.emit('new_message', message_data, room='hpz_global')
        else:
            socketio.emit('new_message', message_data, room=f'chat_{chat_id}')
            
            if '-' in chat_id:
                user_ids = chat_id.split('-')
                for uid in user_ids:
                    if int(uid) != user_id:
                        socketio.emit('new_message', message_data, room=f'user_{uid}')
            
            message.delivered_at = datetime.now(timezone.utc)
            db.session.commit()
        
        print(f"📨 Message: {username} -> {chat_id}")
        
    except Exception as e:
        print(f"Error: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    username = session.get('username')
    chat_id = data.get('chatId')
    
    if username and chat_id:
        typing_data = {'username': username, 'chatId': chat_id}
        
        if chat_id == 'global':
            socketio.emit('typing_start', typing_data, room='hpz_global', skip_sid=request.sid)
        else:
            socketio.emit('typing_start', typing_data, room=f'chat_{chat_id}', skip_sid=request.sid)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    username = session.get('username')
    chat_id = data.get('chatId')
    
    if username and chat_id:
        typing_data = {'username': username, 'chatId': chat_id}
        
        if chat_id == 'global':
            socketio.emit('typing_stop', typing_data, room='hpz_global', skip_sid=request.sid)
        else:
            socketio.emit('typing_stop', typing_data, room=f'chat_{chat_id}', skip_sid=request.sid)

# ========== 🚀 INITIALIZATION ==========

def create_upload_folders():
    folders = ['avatars', 'images', 'videos', 'audio', 'files']
    base_path = app.config['UPLOAD_FOLDER']
    
    for folder in folders:
        folder_path = os.path.join(base_path, folder)
        os.makedirs(folder_path, exist_ok=True)
        print(f"📁 Created: {folder_path}")

def init_database():
    with app.app_context():
        db.create_all()
        
        # Only create test users in development
        if os.environ.get('FLASK_ENV') != 'production' and User.query.count() == 0:
            print("👤 Creating test users...")
            
            test_users = [
                {'username': 'admin', 'email': 'admin@hpz.com', 'password': 'admin123', 'status': 'Administrator'},
                {'username': 'alice', 'email': 'alice@hpz.com', 'password': 'password123', 'status': '🌸 Coding'},
                {'username': 'bob', 'email': 'bob@hpz.com', 'password': 'password123', 'status': '🎮 Gaming'},
                {'username': 'charlie', 'email': 'charlie@hpz.com', 'password': 'password123', 'status': '📚 Reading'},
                {'username': 'diana', 'email': 'diana@hpz.com', 'password': 'password123', 'status': '🎵 Music'}
            ]
            
            for u in test_users:
                user = User(username=u['username'], email=u['email'])
                user.set_password(u['password'])
                db.session.add(user)
                db.session.flush()
                
                profile = UserProfile(user_id=user.id, status=u['status'])
                db.session.add(profile)
            
            db.session.commit()
            print(f"✅ Created {len(test_users)} users")
            
            admin = User.query.filter_by(username='admin').first()
            alice = User.query.filter_by(username='alice').first()
            bob = User.query.filter_by(username='bob').first()
            
            if admin and alice:
                f1 = Friendship(user1_id=min(admin.id, alice.id), user2_id=max(admin.id, alice.id))
                db.session.add(f1)
            
            if admin and bob:
                f2 = Friendship(user1_id=min(admin.id, bob.id), user2_id=max(admin.id, bob.id))
                db.session.add(f2)
            
            if alice and bob:
                req = FriendRequest(from_user_id=alice.id, to_user_id=bob.id)
                db.session.add(req)
            
            db.session.commit()
            print("✅ Created test friendships")

# ========== 🔧 DEBUG ROUTES ==========
# Only enable debug routes in development
if os.environ.get('FLASK_ENV') != 'production':
    @app.route('/debug/users')
    def debug_users():
        users = User.query.all()
        return jsonify({
            'total': len(users),
            'users': [u.to_dict() for u in users]
        })

    @app.route('/debug/status')
    def debug_status():
        return jsonify({
            'status': 'running',
            'users': User.query.count(),
            'messages': ChatMessage.query.count(),
            'friendships': Friendship.query.count(),
            'connected': len(connected_users),
            'sessions': len(user_sockets)
        })
    
    @app.route('/debug/verification-codes')
    def debug_verification_codes():
        """Debug endpoint to see current verification codes"""
        codes_info = {}
        for identifier, data in verification_codes.items():
            codes_info[identifier] = {
                'code': data['code'],
                'method': data['method'],
                'age_seconds': int(time.time() - data['timestamp']),
                'attempts': data.get('attempts', 0),
                'verified': data.get('verified', False)
            }
        return jsonify({
            'active_codes': len(verification_codes),
            'codes': codes_info
        })

# ========== 🎯 MAIN ==========
if __name__ == '__main__':
    create_upload_folders()
    init_database()
    
    # Get port from environment variable (for Render) or use default
    port = int(os.environ.get('PORT', 5000))
    
    socketio.run(
        app,
        debug=os.environ.get('FLASK_ENV') != 'production',
        host='0.0.0.0',
        port=port,
        allow_unsafe_werkzeug=True
    )
