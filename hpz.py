
import os
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_

# ============================================================
# APP CONFIGURATION
# ============================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'hpz-secret-2025')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30  # 30 days
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Database configuration
database_url = os.environ.get('DATABASE_URL', '')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============================================================
# EXTENSIONS
# ============================================================
db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=False,
    engineio_logger=False
)

# Online users tracking: {user_id: {'sid': socket_id, 'last_seen': datetime}}
online_users = {}

# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):
    """User account model"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar_url = db.Column(db.String(500))
    bio = db.Column(db.String(500), default='')
    status = db.Column(db.String(100), default='Available')
    relationship_status = db.Column(db.String(50), default='Prefer not to say')
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'avatar_url': self.avatar_url,
            'bio': self.bio,
            'status': self.status,
            'relationship_status': self.relationship_status
        }


class Friendship(db.Model):
    """Friend connections between users"""
    __tablename__ = 'friendships'
    
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id'),)


class FriendRequest(db.Model):
    """Pending friend requests"""
    __tablename__ = 'friend_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Message(db.Model):
    """Chat messages with support for text, images, replies, and more"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')  # text, image
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    is_edited = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    is_pinned = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')


class MessageReaction(db.Model):
    """Emoji reactions to messages"""
    __tablename__ = 'message_reactions'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji'),)


class MessageRead(db.Model):
    """Track which users have read which messages"""
    __tablename__ = 'message_reads'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    read_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id'),)


class Story(db.Model):
    """24-hour ephemeral stories"""
    __tablename__ = 'stories'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.String(500))  # Text content
    media_url = db.Column(db.String(500))  # Image URL
    media_type = db.Column(db.String(20), default='text')  # text or image
    privacy = db.Column(db.String(20), default='friends')  # public, friends, custom
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)  # Auto-set to 24 hours from creation
    
    user = db.relationship('User', backref='stories')


class StoryView(db.Model):
    """Track who has viewed each story"""
    __tablename__ = 'story_views'
    
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('stories.id'), nullable=False, index=True)
    viewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('story_id', 'viewer_id'),)


class StoryPrivacy(db.Model):
    """Custom privacy settings for stories"""
    __tablename__ = 'story_privacy'
    
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('stories.id'), nullable=False)
    allowed_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class BlockedUser(db.Model):
    """User blocklist"""
    __tablename__ = 'blocked_users'
    
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    blocked_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('blocker_id', 'blocked_id'),)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================
with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def login_required(f):
    """Decorator to require user login"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_chat_id(user1_id, user2_id):
    """Generate consistent chat ID for two users"""
    return f"{min(user1_id, user2_id)}-{max(user1_id, user2_id)}"


def are_friends(user1_id, user2_id):
    """Check if two users are friends"""
    return Friendship.query.filter(
        or_(
            and_(Friendship.user1_id == user1_id, Friendship.user2_id == user2_id),
            and_(Friendship.user1_id == user2_id, Friendship.user2_id == user1_id)
        )
    ).first() is not None


def is_blocked(user_id, other_user_id):
    """Check if either user has blocked the other"""
    return BlockedUser.query.filter(
        or_(
            and_(BlockedUser.blocker_id == user_id, BlockedUser.blocked_id == other_user_id),
            and_(BlockedUser.blocker_id == other_user_id, BlockedUser.blocked_id == user_id)
        )
    ).first() is not None


def is_user_online(user_id):
    """Check if user is currently online"""
    if user_id in online_users:
        last_seen = online_users[user_id].get('last_seen')
        if last_seen and (datetime.now(timezone.utc) - last_seen).seconds < 30:
            return True
    return False


def get_time_ago(dt):
    """Convert datetime to relative time string"""
    if not dt:
        return 'Never'
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    seconds = (datetime.now(timezone.utc) - dt).total_seconds()
    
    if seconds < 60:
        return 'Just now'
    elif seconds < 3600:
        return f'{int(seconds/60)}m ago'
    elif seconds < 86400:
        return f'{int(seconds/3600)}h ago'
    else:
        return f'{int(seconds/86400)}d ago'


def format_message(msg, user_id):
    """Format message with reactions, reads, and reply info"""
    reactions = MessageReaction.query.filter_by(message_id=msg.id).all()
    reads = MessageRead.query.filter_by(message_id=msg.id).all()
    
    # Count reactions by emoji
    reaction_counts = {}
    user_reactions = []
    for r in reactions:
        reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1
        if r.user_id == user_id:
            user_reactions.append(r.emoji)
    
    # Get reply info
    reply_msg = None
    if msg.reply_to_id:
        reply = Message.query.get(msg.reply_to_id)
        if reply and not reply.is_deleted:
            reply_msg = {
                'id': reply.id,
                'sender_username': reply.sender.username if reply.sender else 'Unknown',
                'content': reply.content[:50] + ('...' if len(reply.content) > 50 else '')
            }
    
    return {
        'id': msg.id,
        'chat_id': msg.chat_id,
        'sender_id': msg.sender_id,
        'sender_username': msg.sender.username if msg.sender else 'Unknown',
        'content': msg.content if not msg.is_deleted else '[Message deleted]',
        'message_type': msg.message_type,
        'is_edited': msg.is_edited,
        'is_deleted': msg.is_deleted,
        'is_pinned': msg.is_pinned,
        'created_at': msg.created_at.isoformat(),
        'edited_at': msg.edited_at.isoformat() if msg.edited_at else None,
        'reactions': reaction_counts,
        'user_reactions': user_reactions,
        'read_by': len(reads),
        'reply_to': reply_msg
    }


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return jsonify({'success': False, 'error': 'Server error'}), 500


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route('/')
def index():
    """Landing/login page"""
    return render_template('login.html')


@app.route('/register')
def register_page():
    """Registration page"""
    return render_template('register.html')


@app.route('/chat')
@login_required
def chat():
    """Main chat interface"""
    user = User.query.get(session['user_id'])
    if not user:
        return redirect('/')
    return render_template('chat.html', user=user, user_id=user.id)


@app.route('/logo')
def serve_logo():
    """Serve logo image"""
    logo_path = os.path.join(BASE_DIR, 'static', 'logo.png')
    if os.path.exists(logo_path):
        return send_from_directory(os.path.join(BASE_DIR, 'static'), 'logo.png')
    return '', 404


# ============================================================
# AUTHENTICATION API
# ============================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user account"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'Username already taken'}), 409
    
    try:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        session.permanent = True
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': user.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
    
    session['user_id'] = user.id
    session.permanent = True
    
    return jsonify({
        'success': True,
        'message': 'Login successful',
        'user': user.to_dict()
    })


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout"""
    user_id = session.get('user_id')
    if user_id and user_id in online_users:
        del online_users[user_id]
    
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})


# ============================================================
# USER & PROFILE API
# ============================================================

@app.route('/api/users/search')
@login_required
def search_users():
    """Search for users"""
    query = request.args.get('q', '').strip()
    user_id = session['user_id']
    
    if not query:
        return jsonify({'success': False, 'error': 'Search query required'}), 400
    
    # Search users
    users = User.query.filter(
        User.username.ilike(f'%{query}%'),
        User.id != user_id
    ).limit(10).all()
    
    results = []
    for u in users:
        # Skip blocked users
        if is_blocked(user_id, u.id):
            continue
        
        # Check relationship
        relationship = 'none'
        if are_friends(user_id, u.id):
            relationship = 'friend'
        else:
            req_sent = FriendRequest.query.filter_by(
                from_user_id=user_id, to_user_id=u.id, status='pending'
            ).first()
            req_received = FriendRequest.query.filter_by(
                from_user_id=u.id, to_user_id=user_id, status='pending'
            ).first()
            
            if req_sent:
                relationship = 'request_sent'
            elif req_received:
                relationship = 'request_received'
        
        results.append({
            **u.to_dict(),
            'relationship': relationship,
            'is_online': is_user_online(u.id)
        })
    
    return jsonify({'success': True, 'results': results})


@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user's profile"""
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    return jsonify({'success': True, 'user': user.to_dict()})


@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    data = request.get_json()
    
    # Update fields
    if 'username' in data and data['username'].strip():
        new_username = data['username'].strip()
        if new_username != user.username:
            existing = User.query.filter_by(username=new_username).first()
            if existing:
                return jsonify({'success': False, 'error': 'Username already taken'}), 409
            user.username = new_username
    
    if 'status' in data:
        user.status = data['status'][:100]
    
    if 'bio' in data:
        user.bio = data['bio'][:500]
    
    if 'relationship_status' in data:
        user.relationship_status = data['relationship_status']
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'user': user.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    """Upload user avatar"""
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    
    try:
        # Generate unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"avatar_{session['user_id']}_{uuid.uuid4().hex[:8]}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        
        # Update user
        user = User.query.get(session['user_id'])
        user.avatar_url = f'/static/uploads/{filename}'
        db.session.commit()
        
        return jsonify({'success': True, 'avatar_url': user.avatar_url})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# FRIENDS API
# ============================================================

@app.route('/api/friends')
@login_required
def get_friends():
    """Get user's friends list with last message info"""
    user_id = session['user_id']
    
    # Get all friendships
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    
    friends = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.get(friend_id)
        
        if not friend:
            continue
        
        # Get chat info
        chat_id = get_chat_id(user_id, friend_id)
        last_msg = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at.desc()).first()
        
        # Count unread messages
        unread = 0
        if last_msg:
            unread_msgs = Message.query.filter(
                Message.chat_id == chat_id,
                Message.sender_id == friend_id,
                ~Message.id.in_(
                    db.session.query(MessageRead.message_id).filter_by(user_id=user_id)
                )
            ).count()
            unread = unread_msgs
        
        friends.append({
            **friend.to_dict(),
            'chat_id': chat_id,
            'is_online': is_user_online(friend_id),
            'last_message': last_msg.content[:50] if last_msg else None,
            'last_message_time': last_msg.created_at.isoformat() if last_msg else None,
            'unread_count': unread
        })
    
    # Sort by last message time
    friends.sort(key=lambda x: x['last_message_time'] or '', reverse=True)
    
    return jsonify({'success': True, 'friends': friends})


@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    """Get pending friend requests"""
    user_id = session['user_id']
    
    # Get received requests
    received = FriendRequest.query.filter_by(to_user_id=user_id, status='pending').all()
    received_list = []
    for req in received:
        user = User.query.get(req.from_user_id)
        if user:
            received_list.append({
                'request_id': req.id,
                'user_id': user.id,
                'username': user.username,
                'avatar_url': user.avatar_url,
                'time_ago': get_time_ago(req.created_at)
            })
    
    return jsonify({'success': True, 'received': received_list})


@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    """Send friend request"""
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    from_user_id = session['user_id']
    
    if from_user_id == to_user_id:
        return jsonify({'success': False, 'error': 'Cannot add yourself'}), 400
    
    if are_friends(from_user_id, to_user_id):
        return jsonify({'success': False, 'error': 'Already friends'}), 400
    
    # Check for existing request
    existing = FriendRequest.query.filter_by(
        from_user_id=from_user_id, to_user_id=to_user_id, status='pending'
    ).first()
    
    if existing:
        return jsonify({'success': False, 'error': 'Request already sent'}), 400
    
    try:
        req = FriendRequest(from_user_id=from_user_id, to_user_id=to_user_id)
        db.session.add(req)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request sent'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    """Accept friend request"""
    data = request.get_json()
    request_id = data.get('request_id')
    user_id = session['user_id']
    
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != user_id:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    try:
        # Create friendship
        friendship = Friendship(user1_id=req.from_user_id, user2_id=req.to_user_id)
        db.session.add(friendship)
        
        # Update request status
        req.status = 'accepted'
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request accepted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend_request():
    """Reject friend request"""
    data = request.get_json()
    request_id = data.get('request_id')
    user_id = session['user_id']
    
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != user_id:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    try:
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request rejected'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# MESSAGES API
# ============================================================

@app.route('/api/messages/<chat_id>')
@login_required
def get_messages(chat_id):
    """Get messages for a chat"""
    user_id = session['user_id']
    
    # Verify user is part of this chat
    parts = chat_id.split('-')
    if len(parts) != 2:
        return jsonify({'success': False, 'error': 'Invalid chat ID'}), 400
    
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    # Get messages
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at).all()
    
    return jsonify({
        'success': True,
        'messages': [format_message(m, user_id) for m in messages]
    })


@app.route('/api/messages/search/<chat_id>')
@login_required
def search_messages(chat_id):
    """Search messages in a chat"""
    query = request.args.get('q', '').strip()
    user_id = session['user_id']
    
    if not query:
        return jsonify({'success': False, 'error': 'Search query required'}), 400
    
    # Verify access
    parts = chat_id.split('-')
    if len(parts) != 2:
        return jsonify({'success': False, 'error': 'Invalid chat ID'}), 400
    
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    # Search
    messages = Message.query.filter(
        Message.chat_id == chat_id,
        Message.content.ilike(f'%{query}%'),
        Message.is_deleted == False
    ).order_by(Message.created_at.desc()).limit(50).all()
    
    return jsonify({
        'success': True,
        'messages': [format_message(m, user_id) for m in messages]
    })


@app.route('/api/messages/pinned/<chat_id>')
@login_required
def get_pinned_messages(chat_id):
    """Get pinned messages in a chat"""
    user_id = session['user_id']
    
    # Verify access
    parts = chat_id.split('-')
    if len(parts) != 2:
        return jsonify({'success': False, 'error': 'Invalid chat ID'}), 400
    
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    messages = Message.query.filter_by(chat_id=chat_id, is_pinned=True).all()
    
    return jsonify({
        'success': True,
        'messages': [format_message(m, user_id) for m in messages]
    })


@app.route('/api/messages/<int:msg_id>/edit', methods=['PUT'])
@login_required
def edit_message(msg_id):
    """Edit a message"""
    user_id = session['user_id']
    data = request.get_json()
    new_content = data.get('content', '').strip()
    
    if not new_content:
        return jsonify({'success': False, 'error': 'Content required'}), 400
    
    msg = Message.query.get(msg_id)
    if not msg or msg.sender_id != user_id:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    if msg.is_deleted:
        return jsonify({'success': False, 'error': 'Cannot edit deleted message'}), 400
    
    try:
        msg.content = new_content
        msg.is_edited = True
        msg.edited_at = datetime.now(timezone.utc)
        db.session.commit()
        
        # Emit update via socket
        socketio.emit('message_edited', format_message(msg, user_id), room=msg.chat_id)
        
        return jsonify({'success': True, 'message': format_message(msg, user_id)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/delete', methods=['DELETE'])
@login_required
def delete_message(msg_id):
    """Delete a message"""
    user_id = session['user_id']
    
    msg = Message.query.get(msg_id)
    if not msg or msg.sender_id != user_id:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    try:
        msg.is_deleted = True
        msg.content = '[Message deleted]'
        db.session.commit()
        
        # Emit update via socket
        socketio.emit('message_deleted', {'id': msg.id, 'chat_id': msg.chat_id}, room=msg.chat_id)
        
        return jsonify({'success': True, 'message': 'Message deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/pin', methods=['POST'])
@login_required
def toggle_pin_message(msg_id):
    """Toggle message pin status"""
    user_id = session['user_id']
    
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    # Verify user is part of chat
    parts = msg.chat_id.split('-')
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        msg.is_pinned = not msg.is_pinned
        db.session.commit()
        
        # Emit update via socket
        socketio.emit('message_pinned', {
            'id': msg.id,
            'chat_id': msg.chat_id,
            'is_pinned': msg.is_pinned
        }, room=msg.chat_id)
        
        return jsonify({
            'success': True,
            'is_pinned': msg.is_pinned,
            'message': format_message(msg, user_id)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/react', methods=['POST'])
@login_required
def react_to_message(msg_id):
    """Add or remove reaction to message"""
    user_id = session['user_id']
    data = request.get_json()
    emoji = data.get('emoji', '').strip()
    
    if not emoji:
        return jsonify({'success': False, 'error': 'Emoji required'}), 400
    
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    try:
        # Check if reaction exists
        existing = MessageReaction.query.filter_by(
            message_id=msg_id, user_id=user_id, emoji=emoji
        ).first()
        
        if existing:
            # Remove reaction
            db.session.delete(existing)
        else:
            # Add reaction
            reaction = MessageReaction(message_id=msg_id, user_id=user_id, emoji=emoji)
            db.session.add(reaction)
        
        db.session.commit()
        
        # Emit update via socket
        socketio.emit('message_reaction', {
            'message': format_message(msg, user_id),
            'chat_id': msg.chat_id
        }, room=msg.chat_id)
        
        return jsonify({'success': True, 'message': format_message(msg, user_id)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# BLOCKLIST API
# ============================================================

@app.route('/api/blocklist')
@login_required
def get_blocklist():
    """Get user's blocked users"""
    user_id = session['user_id']
    
    blocked = BlockedUser.query.filter_by(blocker_id=user_id).all()
    blocked_users = []
    
    for b in blocked:
        user = User.query.get(b.blocked_id)
        if user:
            blocked_users.append({
                'id': user.id,
                'username': user.username,
                'avatar_url': user.avatar_url,
                'blocked_at': b.created_at.isoformat()
            })
    
    return jsonify({'success': True, 'blocked_users': blocked_users})


@app.route('/api/blocklist/add', methods=['POST'])
@login_required
def block_user():
    """Block a user"""
    user_id = session['user_id']
    data = request.get_json()
    blocked_id = data.get('user_id')
    
    if user_id == blocked_id:
        return jsonify({'success': False, 'error': 'Cannot block yourself'}), 400
    
    # Check if already blocked
    existing = BlockedUser.query.filter_by(blocker_id=user_id, blocked_id=blocked_id).first()
    if existing:
        return jsonify({'success': False, 'error': 'User already blocked'}), 400
    
    try:
        block = BlockedUser(blocker_id=user_id, blocked_id=blocked_id)
        db.session.add(block)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User blocked'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/blocklist/remove', methods=['POST'])
@login_required
def unblock_user():
    """Unblock a user"""
    user_id = session['user_id']
    data = request.get_json()
    blocked_id = data.get('user_id')
    
    block = BlockedUser.query.filter_by(blocker_id=user_id, blocked_id=blocked_id).first()
    if not block:
        return jsonify({'success': False, 'error': 'User not blocked'}), 404
    
    try:
        db.session.delete(block)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User unblocked'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# STORIES API
# ============================================================

@app.route('/api/stories/create', methods=['POST'])
@login_required
def create_story():
    """Create a new story"""
    user_id = session['user_id']
    data = request.get_json()
    
    content = data.get('content', '')
    media_url = data.get('media_url', '')
    media_type = data.get('media_type', 'text')
    privacy = data.get('privacy', 'friends')
    custom_users = data.get('custom_users', [])
    
    if not content and not media_url:
        return jsonify({'success': False, 'error': 'Content or media required'}), 400
    
    try:
        # Create story with 24-hour expiration
        story = Story(
            user_id=user_id,
            content=content,
            media_url=media_url,
            media_type=media_type,
            privacy=privacy,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.session.add(story)
        db.session.flush()
        
        # Add custom privacy settings
        if privacy == 'custom' and custom_users:
            for allowed_user_id in custom_users:
                privacy_setting = StoryPrivacy(story_id=story.id, allowed_user_id=allowed_user_id)
                db.session.add(privacy_setting)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'story_id': story.id,
            'message': 'Story created'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stories/friends')
@login_required
def get_friends_stories():
    """Get stories from friends"""
    user_id = session['user_id']
    now = datetime.now(timezone.utc)
    
    # Get friends
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    
    friend_ids = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend_ids.append(friend_id)
    
    # Add own ID to see own stories
    friend_ids.append(user_id)
    
    # Get active stories from friends
    stories_by_user = {}
    
    for friend_id in friend_ids:
        # Get all non-expired stories
        user_stories = Story.query.filter(
            Story.user_id == friend_id,
            Story.expires_at > now
        ).order_by(Story.created_at.desc()).all()
        
        # Filter by privacy
        visible_stories = []
        for story in user_stories:
            # Own stories always visible
            if story.user_id == user_id:
                visible_stories.append(story)
                continue
            
            # Check privacy
            if story.privacy == 'public':
                visible_stories.append(story)
            elif story.privacy == 'friends':
                visible_stories.append(story)
            elif story.privacy == 'custom':
                allowed = StoryPrivacy.query.filter_by(
                    story_id=story.id, allowed_user_id=user_id
                ).first()
                if allowed:
                    visible_stories.append(story)
        
        if visible_stories:
            user = User.query.get(friend_id)
            # Check which stories are unviewed
            unviewed = False
            for story in visible_stories:
                viewed = StoryView.query.filter_by(story_id=story.id, viewer_id=user_id).first()
                if not viewed:
                    unviewed = True
                    break
            
            stories_by_user[friend_id] = {
                'user_id': friend_id,
                'username': user.username,
                'avatar_url': user.avatar_url,
                'has_unviewed': unviewed,
                'stories': [{
                    'id': s.id,
                    'content': s.content,
                    'media_url': s.media_url,
                    'media_type': s.media_type,
                    'created_at': s.created_at.isoformat(),
                    'expires_at': s.expires_at.isoformat(),
                    'is_own': s.user_id == user_id,
                    'username': user.username
                } for s in visible_stories]
            }
    
    return jsonify({
        'success': True,
        'stories': list(stories_by_user.values())
    })


@app.route('/api/stories/<int:story_id>/view', methods=['POST'])
@login_required
def view_story(story_id):
    """Mark story as viewed"""
    user_id = session['user_id']
    
    story = Story.query.get(story_id)
    if not story:
        return jsonify({'success': False, 'error': 'Story not found'}), 404
    
    # Don't track views for own stories
    if story.user_id == user_id:
        return jsonify({'success': True, 'message': 'Own story'})
    
    # Check if already viewed
    existing = StoryView.query.filter_by(story_id=story_id, viewer_id=user_id).first()
    if existing:
        return jsonify({'success': True, 'message': 'Already viewed'})
    
    try:
        view = StoryView(story_id=story_id, viewer_id=user_id)
        db.session.add(view)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Story viewed'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stories/<int:story_id>/viewers')
@login_required
def get_story_viewers(story_id):
    """Get viewers of a story"""
    user_id = session['user_id']
    
    story = Story.query.get(story_id)
    if not story or story.user_id != user_id:
        return jsonify({'success': False, 'error': 'Story not found'}), 404
    
    views = StoryView.query.filter_by(story_id=story_id).all()
    viewers = []
    
    for view in views:
        user = User.query.get(view.viewer_id)
        if user:
            viewers.append({
                'user_id': user.id,
                'username': user.username,
                'avatar_url': user.avatar_url,
                'viewed_at': view.viewed_at.isoformat()
            })
    
    return jsonify({
        'success': True,
        'count': len(viewers),
        'viewers': viewers
    })


@app.route('/api/stories/<int:story_id>/delete', methods=['DELETE'])
@login_required
def delete_story(story_id):
    """Delete a story"""
    user_id = session['user_id']
    
    story = Story.query.get(story_id)
    if not story or story.user_id != user_id:
        return jsonify({'success': False, 'error': 'Story not found'}), 404
    
    try:
        # Delete associated views and privacy settings
        StoryView.query.filter_by(story_id=story_id).delete()
        StoryPrivacy.query.filter_by(story_id=story_id).delete()
        
        db.session.delete(story)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Story deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# FILE UPLOAD API
# ============================================================

@app.route('/api/upload/image', methods=['POST'])
@login_required
def upload_image():
    """Upload image for messages or stories"""
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    
    try:
        # Generate unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"img_{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'url': f'/static/uploads/{filename}',
            'filename': filename
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# SOCKET.IO EVENTS
# ============================================================

@socketio.on('connect')
def handle_connect():
    """Handle socket connection"""
    if 'user_id' not in session:
        return False
    
    user_id = session['user_id']
    online_users[user_id] = {
        'sid': request.sid,
        'last_seen': datetime.now(timezone.utc)
    }
    
    # Notify friends that user is online
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        if friend_id in online_users:
            emit('user_online', {
                'user_id': user_id,
                'online': True
            }, room=online_users[friend_id]['sid'])
    
    print(f"✅ User {user_id} connected")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle socket disconnection"""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    
    # Notify friends that user is offline
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        if friend_id in online_users:
            emit('user_online', {
                'user_id': user_id,
                'online': False
            }, room=online_users[friend_id]['sid'])
    
    # Remove from online users
    if user_id in online_users:
        del online_users[user_id]
    
    print(f"❌ User {user_id} disconnected")


@socketio.on('join_chat')
def handle_join_chat(data):
    """Join a chat room"""
    chat_id = data.get('chat_id')
    if chat_id:
        join_room(chat_id)
        print(f"User joined chat: {chat_id}")


@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending a message"""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    chat_id = data.get('chat_id')
    content = data.get('content', '').strip()
    message_type = data.get('message_type', 'text')
    reply_to_id = data.get('reply_to_id')
    
    if not content or not chat_id:
        return
    
    # Verify access to chat
    parts = chat_id.split('-')
    if len(parts) != 2:
        return
    
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return
    
    # Check if blocked
    other_user_id = user2_id if user_id == user1_id else user1_id
    if is_blocked(user_id, other_user_id):
        emit('error', {'message': 'Cannot send message to blocked user'})
        return
    
    try:
        msg = Message(
            chat_id=chat_id,
            sender_id=user_id,
            content=content,
            message_type=message_type,
            reply_to_id=reply_to_id
        )
        db.session.add(msg)
        db.session.commit()
        
        # Emit to chat room
        emit('new_message', format_message(msg, user_id), room=chat_id)
        
    except Exception as e:
        db.session.rollback()
        print(f"Error sending message: {e}")


@socketio.on('typing_start')
def handle_typing_start(data):
    """Handle user starting to type"""
    if 'user_id' not in session:
        return
    
    user = User.query.get(session['user_id'])
    if not user:
        return
    
    chat_id = data.get('chatId')
    if chat_id:
        emit('typing_start', {'username': user.username}, room=chat_id, include_self=False)


@socketio.on('typing_stop')
def handle_typing_stop(data):
    """Handle user stopping typing"""
    chat_id = data.get('chatId')
    if chat_id:
        emit('typing_stop', {}, room=chat_id, include_self=False)


# ============================================================
# UTILITY ROUTES
# ============================================================

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


@app.teardown_appcontext
def shutdown_session(exception=None):
    """Clean up database session"""
    db.session.remove()


# ============================================================
# RUN SERVER
# ============================================================
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)


