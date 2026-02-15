import os
import json
import uuid
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

# ========== INITIALIZE APP ==========
app = Flask(__name__)

# ========== CONFIGURATION ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'hpz-secret-key-2024')
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    
    # Database
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = database_url or f'sqlite:///{os.path.join(BASEDIR, "hpz.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'echo': False,
    }
    
    # FIX: Prevent session detachment
    SQLALCHEMY_EXPIRE_ON_COMMIT = False
    
    # Upload
    UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'mp3', 'wav'}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

app.config.from_object(Config)

# ========== INITIALIZE EXTENSIONS ==========
db = SQLAlchemy(app)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# ========== DATABASE MODELS ==========

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships with lazy loading
    profile = db.relationship('UserProfile', back_populates='user', uselist=False, 
                            cascade='all, delete-orphan', lazy='joined')
    sent_messages = db.relationship('ChatMessage', back_populates='sender', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone': self.phone
        }

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, index=True)
    bio = db.Column(db.String(500), default='')
    avatar_url = db.Column(db.String(500))
    status = db.Column(db.String(100), default='Available')
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', back_populates='profile')
    
    def to_dict(self):
        return {
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'status': self.status
        }

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Eager load sender to prevent detachment
    sender = db.relationship('User', back_populates='sent_messages', lazy='joined')
    
    def to_dict(self):
        # Access all data within session context
        sender_username = self.sender.username if self.sender else 'Unknown'
        sender_id = self.sender_id
        
        # Get profile separately to avoid detachment
        profile = UserProfile.query.filter_by(user_id=sender_id).first()
        sender_avatar = profile.avatar_url if profile else None
        
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'sender_id': sender_id,
            'sender_username': sender_username,
            'sender_avatar': sender_avatar,
            'content': self.content,
            'message_type': self.message_type,
            'created_at': self.created_at.isoformat()
        }

class Friendship(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        db.UniqueConstraint('user1_id', 'user2_id'),
    )

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ========== HELPER FUNCTIONS ==========

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated

def get_chat_id(user1_id, user2_id):
    return f"{min(user1_id, user2_id)}-{max(user1_id, user2_id)}"

# ========== ERROR HANDLERS ==========

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    db.session.rollback()
    return jsonify({'success': False, 'error': 'Server error'}), 500

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
    user = User.query.options(joinedload(User.profile)).get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    if not user.profile:
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
        db.session.refresh(user)
    
    return render_template('chat.html', user=user, profile=user.profile)

# ========== AUTHENTICATION ==========

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print(f"📝 Registration: {data}")
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        phone = data.get('phone', '').strip() or None
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username too short'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password too short'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username taken'}), 400
        
        if phone and User.query.filter_by(phone=phone).first():
            return jsonify({'success': False, 'error': 'Phone already registered'}), 400
        
        user = User(username=username, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
        
        # Refresh to load relationships
        db.session.refresh(user)
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        print(f"✅ User created: {username}")
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')
        
        if not identifier or not password:
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        
        user = User.query.filter(
            (User.username == identifier) |
            (User.email == identifier) |
            (User.phone == identifier)
        ).first()
        
        if not user or not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'user': user.to_dict()
        })
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'success': True})

# ========== USER SEARCH ==========

@app.route('/api/users/search', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('q', '').strip()
    user_id = session['user_id']
    
    if not query:
        return jsonify({'success': True, 'results': []})
    
    users = User.query.options(joinedload(User.profile)).filter(
        User.id != user_id,
        User.username.ilike(f'%{query}%')
    ).limit(20).all()
    
    results = []
    for user in users:
        is_friend = Friendship.query.filter(
            ((Friendship.user1_id == user_id) & (Friendship.user2_id == user.id)) |
            ((Friendship.user1_id == user.id) & (Friendship.user2_id == user_id))
        ).first() is not None
        
        results.append({
            'id': user.id,
            'username': user.username,
            'avatar': user.profile.avatar_url if user.profile else None,
            'status': user.profile.status if user.profile else 'Available',
            'is_friend': is_friend
        })
    
    return jsonify({'success': True, 'results': results})

# ========== FRIENDS ==========

@app.route('/api/friends', methods=['GET'])
@login_required
def get_friends():
    user_id = session['user_id']
    
    friendships = Friendship.query.filter(
        (Friendship.user1_id == user_id) | (Friendship.user2_id == user_id)
    ).all()
    
    friends = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.options(joinedload(User.profile)).get(friend_id)
        
        if friend:
            friends.append({
                'id': friend.id,
                'username': friend.username,
                'avatarUrl': friend.profile.avatar_url if friend.profile else None,
                'status': friend.profile.status if friend.profile else 'Available',
                'chat_id': get_chat_id(user_id, friend_id)
            })
    
    return jsonify({'success': True, 'contacts': friends})

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    data = request.get_json()
    user_id = session['user_id']
    to_user_id = data.get('to_user_id')
    
    if not to_user_id or user_id == to_user_id:
        return jsonify({'success': False, 'error': 'Invalid user'}), 400
    
    existing = Friendship.query.filter(
        ((Friendship.user1_id == user_id) & (Friendship.user2_id == to_user_id)) |
        ((Friendship.user1_id == to_user_id) & (Friendship.user2_id == user_id))
    ).first()
    
    if existing:
        return jsonify({'success': False, 'error': 'Already friends'}), 400
    
    req = FriendRequest(from_user_id=user_id, to_user_id=to_user_id)
    db.session.add(req)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend():
    data = request.get_json()
    request_id = data.get('request_id')
    
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != session['user_id']:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    
    friendship = Friendship(
        user1_id=min(req.from_user_id, req.to_user_id),
        user2_id=max(req.from_user_id, req.to_user_id)
    )
    db.session.add(friendship)
    db.session.delete(req)
    db.session.commit()
    
    return jsonify({'success': True})

# ========== MESSAGES ==========

@app.route('/api/messages/<chat_id>', methods=['GET'])
@login_required
def get_messages(chat_id):
    # Use joinedload to prevent detachment
    messages = ChatMessage.query.options(
        joinedload(ChatMessage.sender)
    ).filter_by(chat_id=chat_id).order_by(
        ChatMessage.created_at.desc()
    ).limit(50).all()
    
    messages.reverse()
    
    # Convert to dict within session context
    message_dicts = [m.to_dict() for m in messages]
    
    return jsonify({
        'success': True,
        'messages': message_dicts
    })

# ========== SOCKET.IO ==========

@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        print(f"✅ User {user_id} connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("❌ User disconnected")

@socketio.on('send_message')
def handle_message(data):
    user_id = session.get('user_id')
    if not user_id:
        return
    
    message = ChatMessage(
        chat_id=data['chatId'],
        sender_id=user_id,
        content=data['content'],
        message_type=data.get('type', 'text')
    )
    db.session.add(message)
    db.session.commit()
    
    # Refresh to load relationships
    db.session.refresh(message)
    
    socketio.emit('new_message', message.to_dict(), room=f"chat_{data['chatId']}")

# ========== DEBUG ==========

@app.route('/health')
def health():
    try:
        count = User.query.count()
        return jsonify({'status': 'ok', 'users': count})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ========== INIT ==========

def init_db():
    with app.app_context():
        db.create_all()
        print("✅ Database initialized")

# FIX: Add teardown to properly close sessions
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()
    
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
