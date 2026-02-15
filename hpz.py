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
from sqlalchemy import or_, and_, func, desc, inspect
from sqlalchemy.orm import joinedload

# ========== INITIALIZE APP ==========
app = Flask(__name__)

# ========== CONFIGURATION ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'hpz-secret-key-2024')
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = database_url or f'sqlite:///{os.path.join(BASEDIR, "hpz.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    SQLALCHEMY_EXPIRE_ON_COMMIT = False
    
    UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'mp3', 'wav', 'pdf', 'doc', 'docx'}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    
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
        # Make sure last_seen is timezone-aware
        last_seen = self.last_seen
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        
        return {
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'status': self.status,
            'last_seen': last_seen.isoformat() if last_seen else None
        }

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    filename = db.Column(db.String(200))
    file_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    sender = db.relationship('User', back_populates='sent_messages', lazy='joined')
    
    def to_dict(self):
        sender_username = self.sender.username if self.sender else 'Unknown'
        sender_id = self.sender_id
        profile = UserProfile.query.filter_by(user_id=sender_id).first()
        
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'sender_id': sender_id,
            'sender_username': sender_username,
            'sender_avatar': profile.avatar_url if profile else None,
            'content': self.content,
            'message_type': self.message_type,
            'filename': self.filename,
            'file_url': self.file_url,
            'created_at': self.created_at.isoformat()
        }

class Friendship(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id'),)

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ========== AUTO-INITIALIZE DATABASE ==========
def ensure_database():
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if not tables:
            print("⚠️ No tables found, creating database...")
            with app.app_context():
                db.create_all()
            print("✅ Database tables created")
        else:
            print(f"✅ Database ready with {len(tables)} tables")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        try:
            with app.app_context():
                db.create_all()
            print("✅ Database tables created (recovery)")
        except:
            pass

ensure_database()

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_time_ago(dt):
    """Helper function to calculate time ago text"""
    if not dt:
        return 'Offline'
    
    try:
        # Make timezone-aware if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        diff = now - dt
        seconds = diff.total_seconds()
        
        # Consider online if last seen within 5 minutes
        if seconds < 300:
            return 'Online'
        elif seconds < 60:
            return 'Just now'
        elif seconds < 3600:
            return f'{int(seconds / 60)}m ago'
        elif seconds < 86400:
            return f'{int(seconds / 3600)}h ago'
        else:
            return f'{int(seconds / 86400)}d ago'
    except Exception as e:
        print(f"⚠️ Error calculating time ago: {e}")
        return 'Offline'

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
    
    return render_template('chat.html', user=user, profile=user.profile, user_id=user.id)

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
    try:
        query = request.args.get('q', '').strip()
        user_id = session['user_id']
        
        print(f"🔍 Search: '{query}' by user {user_id}")
        
        if not query:
            return jsonify({'success': True, 'results': [], 'count': 0})
        
        users = User.query.options(joinedload(User.profile)).filter(
            User.id != user_id,
            User.username.ilike(f'%{query}%')
        ).limit(20).all()
        
        print(f"📊 Found {len(users)} users")
        
        results = []
        for user in users:
            # Check friendship
            is_friend = Friendship.query.filter(
                or_(
                    and_(Friendship.user1_id == user_id, Friendship.user2_id == user.id),
                    and_(Friendship.user1_id == user.id, Friendship.user2_id == user_id)
                )
            ).first() is not None
            
            # Check pending requests
            request_sent = FriendRequest.query.filter_by(
                from_user_id=user_id, 
                to_user_id=user.id, 
                status='pending'
            ).first() is not None
            
            request_received = FriendRequest.query.filter_by(
                from_user_id=user.id, 
                to_user_id=user_id, 
                status='pending'
            ).first() is not None
            
            # Avatar
            avatar = user.profile.avatar_url if user.profile and user.profile.avatar_url else \
                     f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff&size=128"
            
            # Determine relationship
            if is_friend:
                relationship = 'friend'
            elif request_sent:
                relationship = 'request_sent'
            elif request_received:
                relationship = 'request_received'
            else:
                relationship = 'none'
            
            # Calculate last seen using helper function
            last_seen_text = get_time_ago(user.profile.last_seen if user.profile else None)
            
            results.append({
                'id': user.id,
                'username': user.username,
                'avatar': avatar,
                'status': user.profile.status if user.profile else 'Available',
                'bio': user.profile.bio if user.profile else '',
                'is_friend': is_friend,
                'is_online': last_seen_text == 'Online',
                'last_seen': last_seen_text,
                'relationship': relationship
            })
            
            print(f"   ✅ {user.username} - {relationship}")
        
        return jsonify({'success': True, 'results': results, 'count': len(results)})
    except Exception as e:
        print(f"❌ Search error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== PROFILE ==========
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    try:
        user = User.query.options(joinedload(User.profile)).get(session['user_id'])
        profile = user.profile if user else None
        
        if not profile:
            profile = UserProfile(user_id=user.id)
            db.session.add(profile)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'profile': {
                'bio': profile.bio,
                'status': profile.status,
                'avatar_url': profile.avatar_url
            }
        })
    except Exception as e:
        print(f"❌ Get profile error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    try:
        data = request.get_json()
        user = User.query.get(session['user_id'])
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        
        if not profile:
            profile = UserProfile(user_id=user.id)
            db.session.add(profile)
        
        if 'username' in data and data['username'] != user.username:
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'success': False, 'error': 'Username taken'}), 400
            user.username = data['username']
            session['username'] = data['username']
        
        if 'bio' in data:
            profile.bio = data['bio'][:500]
        
        if 'status' in data:
            profile.status = data['status'][:100]
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Update profile error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    try:
        if 'avatar' not in request.files:
            return jsonify({'success': False, 'error': 'No file'}), 400
        
        file = request.files['avatar']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars')
            os.makedirs(upload_path, exist_ok=True)
            
            file_path = os.path.join(upload_path, unique_filename)
            file.save(file_path)
            
            url = f"/static/uploads/avatars/{unique_filename}"
            
            profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
            if profile:
                profile.avatar_url = url
                db.session.commit()
            
            return jsonify({'success': True, 'url': url})
        
        return jsonify({'success': False, 'error': 'Invalid file'}), 400
    except Exception as e:
        print(f"❌ Avatar upload error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== FILE UPLOAD ==========
@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file'}), 400
        
        file = request.files['file']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            
            ext = filename.rsplit('.', 1)[1].lower()
            if ext in ['png', 'jpg', 'jpeg', 'gif']:
                folder = 'images'
                file_type = 'image'
            elif ext in ['mp4', 'webm']:
                folder = 'videos'
                file_type = 'video'
            elif ext in ['mp3', 'wav']:
                folder = 'audio'
                file_type = 'audio'
            else:
                folder = 'files'
                file_type = 'file'
            
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
            os.makedirs(upload_path, exist_ok=True)
            
            file_path = os.path.join(upload_path, unique_filename)
            file.save(file_path)
            
            file_size = os.path.getsize(file_path)
            url = f"/static/uploads/{folder}/{unique_filename}"
            
            return jsonify({
                'success': True,
                'url': url,
                'filename': filename,
                'size': file_size,
                'type': file_type
            })
        
        return jsonify({'success': False, 'error': 'Invalid file'}), 400
    except Exception as e:
        print(f"❌ File upload error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== FRIENDS ==========
@app.route('/api/friends', methods=['GET'])
@login_required
def get_friends():
    try:
        user_id = session['user_id']
        
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
        ).all()
        
        friends = []
        for f in friendships:
            friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
            friend = User.query.options(joinedload(User.profile)).get(friend_id)
            
            if friend:
                avatar_url = friend.profile.avatar_url if friend.profile and friend.profile.avatar_url else \
                             f"https://ui-avatars.com/api/?name={friend.username}&background=0088cc&color=fff&size=96"
                
                friends.append({
                    'id': friend.id,
                    'username': friend.username,
                    'avatar_url': avatar_url,
                    'avatarUrl': avatar_url,
                    'status': friend.profile.status if friend.profile else 'Available',
                    'is_online': False,
                    'chat_id': get_chat_id(user_id, friend_id)
                })
        
        return jsonify({'success': True, 'friends': friends, 'contacts': friends})
    except Exception as e:
        print(f"❌ Get friends error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/requests', methods=['GET'])
@login_required
def get_friend_requests():
    try:
        user_id = session['user_id']
        
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
            
            avatar_url = profile.avatar_url if profile and profile.avatar_url else \
                         f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff&size=96"
            
            received_list.append({
                'request_id': req.id,
                'user_id': user.id,
                'username': user.username,
                'avatar_url': avatar_url,
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
    except Exception as e:
        print(f"❌ Get requests error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    try:
        data = request.get_json()
        user_id = session['user_id']
        to_user_id = data.get('to_user_id')
        
        if not to_user_id or user_id == to_user_id:
            return jsonify({'success': False, 'error': 'Invalid user'}), 400
        
        existing = Friendship.query.filter(
            or_(
                and_(Friendship.user1_id == user_id, Friendship.user2_id == to_user_id),
                and_(Friendship.user1_id == to_user_id, Friendship.user2_id == user_id)
            )
        ).first()
        
        if existing:
            return jsonify({'success': False, 'error': 'Already friends'}), 400
        
        existing_request = FriendRequest.query.filter_by(
            from_user_id=user_id, to_user_id=to_user_id, status='pending'
        ).first()
        
        if existing_request:
            return jsonify({'success': False, 'error': 'Request already sent'}), 400
        
        req = FriendRequest(from_user_id=user_id, to_user_id=to_user_id)
        db.session.add(req)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Send request error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend():
    try:
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
    except Exception as e:
        db.session.rollback()
        print(f"❌ Accept friend error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend():
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        
        req = FriendRequest.query.get(request_id)
        if not req or req.to_user_id != session['user_id']:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        db.session.delete(req)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Reject friend error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== MESSAGES ==========
@app.route('/api/messages/<chat_id>', methods=['GET'])
@login_required
def get_messages(chat_id):
    try:
        messages = ChatMessage.query.options(
            joinedload(ChatMessage.sender)
        ).filter_by(chat_id=chat_id).order_by(
            ChatMessage.created_at.desc()
        ).limit(50).all()
        
        messages.reverse()
        message_dicts = [m.to_dict() for m in messages]
        
        return jsonify({
            'success': True,
            'messages': message_dicts
        })
    except Exception as e:
        print(f"❌ Get messages error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== SOCKET.IO ==========
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id:
        join_room(f'user_{user_id}')
        join_room('global')
        print(f"✅ User {username} ({user_id}) connected")

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id:
        print(f"❌ User {user_id} disconnected")

@socketio.on('join')
def handle_join(data):
    chat_id = data.get('chatId')
    if chat_id:
        join_room(chat_id)
        print(f"👥 User joined chat: {chat_id}")

@socketio.on('send_message')
def handle_message(data):
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id:
        return
    
    try:
        chat_id = data.get('chatId')
        
        message = ChatMessage(
            chat_id=chat_id,
            sender_id=user_id,
            content=data.get('content', ''),
            message_type=data.get('type', 'text'),
            filename=data.get('filename'),
            file_url=data.get('fileUrl')
        )
        db.session.add(message)
        db.session.commit()
        db.session.refresh(message)
        
        message_dict = message.to_dict()
        
        # Emit to chat room
        if chat_id == 'global':
            socketio.emit('new_message', message_dict, room='global')
        else:
            socketio.emit('new_message', message_dict, room=chat_id)
            
            # Also emit to individual users
            if '-' in chat_id:
                user_ids = chat_id.split('-')
                for uid in user_ids:
                    socketio.emit('new_message', message_dict, room=f'user_{uid}')
        
        print(f"📨 Message from {username}: {data.get('content', '')[:50]}")
    except Exception as e:
        print(f"❌ Send message error: {e}")
        import traceback
        traceback.print_exc()

@socketio.on('typing_start')
def handle_typing_start(data):
    username = session.get('username')
    chat_id = data.get('chatId')
    
    if username and chat_id:
        socketio.emit('typing_start', {
            'username': username,
            'chatId': chat_id
        }, room=chat_id, include_self=False)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    username = session.get('username')
    chat_id = data.get('chatId')
    
    if username and chat_id:
        socketio.emit('typing_stop', {
            'username': username,
            'chatId': chat_id
        }, room=chat_id, include_self=False)

# ========== DEBUG ==========
@app.route('/health')
def health():
    try:
        count = User.query.count()
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        return jsonify({
            'status': 'ok', 
            'users': count,
            'tables': tables
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/debug/init-db')
def init_db_route():
    try:
        db.create_all()
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        return jsonify({
            'success': True,
            'message': 'Database initialized',
            'tables': tables
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/debug/test-search')
def test_search():
    """Test search functionality"""
    try:
        users = User.query.all()
        user_data = []
        
        for user in users:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            user_data.append({
                'id': user.id,
                'username': user.username,
                'has_profile': profile is not None,
                'last_seen': profile.last_seen.isoformat() if profile and profile.last_seen else None,
                'last_seen_type': str(type(profile.last_seen)) if profile and profile.last_seen else None
            })
        
        return jsonify({
            'success': True,
            'total_users': len(users),
            'users': user_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/debug/users')
def debug_users():
    try:
        users = User.query.all()
        return jsonify({
            'success': True,
            'count': len(users),
            'users': [u.to_dict() for u in users]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== TEARDOWN ==========
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# ========== START ==========
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'images'), exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'files'), exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting HPZ Messenger on port {port}")
    
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=False, 
        allow_unsafe_werkzeug=True
    )
