import os
import uuid
import json
import openai
from flask import Flask, render_template, request, jsonify, session, redirect, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from sqlalchemy import or_, and_
from functools import wraps

# ============================================================
# APP CONFIG
# ============================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'hpz-secret-2025')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# ============================================================
# DATABASE
# ============================================================
database_url = os.environ.get('DATABASE_URL', '')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# ============================================================
# AI CONFIGURATION
# ============================================================
AI_PROVIDER = os.environ.get('AI_PROVIDER', 'openai')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
AI_DAILY_LIMIT = int(os.environ.get('AI_DAILY_LIMIT', 50))
AI_MODELS = {
    'gpt-3.5-turbo': {'name': 'GPT-3.5 Turbo', 'cost_per_token': 0.000002},
    'gpt-4': {'name': 'GPT-4', 'cost_per_token': 0.00003},
    'gemini-pro': {'name': 'Gemini Pro', 'cost_per_token': 0}
}
DEFAULT_AI_MODEL = 'gpt-3.5-turbo'

# ============================================================
# PATHS
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

# ============================================================
# ONLINE USERS TRACKING
# ============================================================
online_users = {}

# ============================================================
# MODELS (ALL IN ONE PLACE)
# ============================================================

class User(db.Model):
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
    # AI FIELDS
    ai_enabled = db.Column(db.Boolean, default=False)
    ai_model_preference = db.Column(db.String(50), default='gpt-3.5-turbo')

    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)
    def to_dict(self):
        return {
            'id': self.id, 'username': self.username,
            'avatar_url': self.avatar_url, 'bio': self.bio, 'status': self.status,
            'relationship_status': self.relationship_status,
            'ai_enabled': self.ai_enabled
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    is_edited = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    is_pinned = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender = db.relationship('User', foreign_keys=[sender_id])
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')

class MessageReaction(db.Model):
    __tablename__ = 'message_reactions'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji'),)

class MessageRead(db.Model):
    __tablename__ = 'message_reads'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    read_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id'),)

class Story(db.Model):
    __tablename__ = 'stories'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.String(500))
    media_url = db.Column(db.String(500))
    media_type = db.Column(db.String(20), default='image')
    privacy = db.Column(db.String(20), default='friends')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)
    user = db.relationship('User', backref='stories')

class StoryView(db.Model):
    __tablename__ = 'story_views'
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('stories.id'), nullable=False, index=True)
    viewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('story_id', 'viewer_id'),)

class StoryPrivacy(db.Model):
    __tablename__ = 'story_privacy'
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('stories.id'), nullable=False)
    allowed_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class BlockedUser(db.Model):
    __tablename__ = 'blocked_users'
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    blocked_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('blocker_id', 'blocked_id'),)

class Friendship(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id'),)

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ============================================================
# AI MODELS
# ============================================================
class AIConversation(db.Model):
    __tablename__ = 'ai_conversations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(200), default='New Conversation')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user = db.relationship('User', backref='ai_conversations')

class AIMessage(db.Model):
    __tablename__ = 'ai_messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('ai_conversations.id'), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    model_used = db.Column(db.String(50))
    tokens_used = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    conversation = db.relationship('AIConversation', backref='messages')

class AIUsage(db.Model):
    __tablename__ = 'ai_usage'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    date = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date())
    count = db.Column(db.Integer, default=0)
    tokens = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('user_id', 'date'),)

# ============================================================
# INIT DB
# ============================================================
with app.app_context():
    try:
        db.create_all()
        print("✅ Database ready")
    except Exception as e:
        print(f"❌ DB error: {e}")

# ============================================================
# HELPERS
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated

def allowed_file(fn):
    return '.' in fn and fn.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_chat_id(a, b):
    return f"{min(a, b)}-{max(a, b)}"

def are_friends(a, b):
    return Friendship.query.filter(
        or_(and_(Friendship.user1_id == a, Friendship.user2_id == b),
            and_(Friendship.user1_id == b, Friendship.user2_id == a))
    ).first() is not None

def get_time_ago(dt):
    if not dt: return 'Never'
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    s = (datetime.now(timezone.utc) - dt).total_seconds()
    if s < 60: return 'Just now'
    if s < 3600: return f'{int(s/60)}m ago'
    if s < 86400: return f'{int(s/3600)}h ago'
    return f'{int(s/86400)}d ago'

def is_user_online(user_id):
    if user_id in online_users:
        last_seen = online_users[user_id].get('last_seen')
        if last_seen and (datetime.now(timezone.utc) - last_seen).seconds < 30:
            return True
    return False

def is_blocked(user_id, other_user_id):
    return BlockedUser.query.filter(
        or_(
            and_(BlockedUser.blocker_id == user_id, BlockedUser.blocked_id == other_user_id),
            and_(BlockedUser.blocker_id == other_user_id, BlockedUser.blocked_id == user_id)
        )
    ).first() is not None

def format_message(msg, user_id):
    reactions = MessageReaction.query.filter_by(message_id=msg.id).all()
    reads = MessageRead.query.filter_by(message_id=msg.id).all()
    
    reaction_counts = {}
    user_reactions = []
    for r in reactions:
        reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1
        if r.user_id == user_id:
            user_reactions.append(r.emoji)
    
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
def not_found(e): return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return jsonify({'success': False, 'error': 'Server error'}), 500

# ============================================================
# PAGE ROUTES
# ============================================================
@app.route('/')
def index():
    if 'user_id' in session: return redirect('/chat')
    return render_template('login.html')

@app.route('/register')
def register_page():
    if 'user_id' in session: return redirect('/chat')
    return render_template('register.html')

@app.route('/chat')
def chat():
    try:
        uid = session.get('user_id')
        if not uid: return redirect('/')
        user = User.query.get(uid)
        if not user:
            session.clear()
            return redirect('/')
        return render_template('chat.html', user=user, user_id=user.id)
    except Exception as e:
        print(f"❌ Chat error: {e}")
        session.clear()
        return redirect('/')

@app.route('/logo')
def serve_logo():
    templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    return send_from_directory(templates_dir, 'hepozy_logo.jpg')

# ============================================================
# AUTH ROUTES
# ============================================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        if not username or not password:
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username min 3 chars'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password min 6 chars'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username taken'}), 400
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session.modified = True
        print(f"✅ Registered: {username} (ID:{user.id})")
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Register error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')
        if not identifier or not password:
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        user = User.query.filter_by(username=identifier).first()
        if not user or not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session.modified = True
        print(f"✅ Login: {user.username} (ID:{user.id})")
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    if uid and uid in online_users:
        del online_users[uid]
    session.clear()
    return jsonify({'success': True})

# ============================================================
# SEARCH ROUTES
# ============================================================
@app.route('/api/users/search')
@login_required
def search_users():
    try:
        query = request.args.get('q', '').strip()
        uid = session['user_id']
        if not query:
            return jsonify({'success': True, 'results': [], 'count': 0})
        users = User.query.filter(
            User.id != uid,
            User.username.ilike(f'%{query}%')
        ).limit(20).all()
        results = []
        for u in users:
            is_friend = are_friends(uid, u.id)
            req_sent = FriendRequest.query.filter_by(from_user_id=uid, to_user_id=u.id, status='pending').first() is not None
            req_recv = FriendRequest.query.filter_by(from_user_id=u.id, to_user_id=uid, status='pending').first() is not None
            if is_friend: rel = 'friend'
            elif req_sent: rel = 'request_sent'
            elif req_recv: rel = 'request_received'
            else: rel = 'none'
            results.append({
                'id': u.id, 'username': u.username,
                'avatar': u.avatar_url or f"https://ui-avatars.com/api/?name={u.username}&background=6c63ff&color=fff&size=128",
                'status': u.status or 'Available',
                'is_online': is_user_online(u.id),
                'is_friend': is_friend, 'relationship': rel,
                'request_sent': req_sent, 'request_received': req_recv
            })
        return jsonify({'success': True, 'results': results, 'count': len(results)})
    except Exception as e:
        print(f"❌ Search error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# PROFILE ROUTES
# ============================================================
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    try:
        user = User.query.get(session['user_id'])
        if not user: return jsonify({'success': False, 'error': 'Not found'}), 404
        return jsonify({'success': True, 'profile': user.to_dict()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    try:
        data = request.get_json()
        user = User.query.get(session['user_id'])
        if 'username' in data and data['username'] != user.username:
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'success': False, 'error': 'Username taken'}), 400
            user.username = data['username']
            session['username'] = data['username']
            session.modified = True
        if 'bio' in data: user.bio = data['bio'][:500]
        if 'status' in data: user.status = data['status'][:100]
        if 'relationship_status' in data:
            if data['relationship_status'] in ['Single', 'Married', 'Prefer not to say']:
                user.relationship_status = data['relationship_status']
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    try:
        if 'avatar' not in request.files:
            return jsonify({'success': False, 'error': 'No file'}), 400
        file = request.files['avatar']
        if not file or not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file'}), 400
        ext = file.filename.rsplit('.', 1)[1].lower()
        fn = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(UPLOAD_FOLDER, 'avatars')
        os.makedirs(path, exist_ok=True)
        file.save(os.path.join(path, fn))
        url = f"/static/uploads/avatars/{fn}"
        user = User.query.get(session['user_id'])
        user.avatar_url = url
        db.session.commit()
        return jsonify({'success': True, 'url': url})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile/relationship', methods=['PUT'])
@login_required
def update_relationship_status():
    try:
        data = request.get_json()
        status = data.get('relationship_status')
        if status not in ['Single', 'Married', 'Prefer not to say']:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
        user = User.query.get(session['user_id'])
        user.relationship_status = status
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# STORIES ROUTES
# ============================================================
@app.route('/api/stories/create', methods=['POST'])
@login_required
def create_story():
    try:
        data = request.get_json()
        uid = session['user_id']
        content = data.get('content', '').strip()
        media_url = data.get('media_url', '')
        media_type = data.get('media_type', 'image')
        privacy = data.get('privacy', 'friends')
        custom_users = data.get('custom_users', [])
        
        if not content and not media_url:
            return jsonify({'success': False, 'error': 'Content or media required'}), 400
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        story = Story(
            user_id=uid,
            content=content,
            media_url=media_url,
            media_type=media_type,
            privacy=privacy,
            expires_at=expires_at
        )
        db.session.add(story)
        db.session.commit()
        
        if privacy == 'custom' and custom_users:
            for user_id in custom_users:
                db.session.add(StoryPrivacy(story_id=story.id, allowed_user_id=user_id))
            db.session.commit()
        
        return jsonify({'success': True, 'story_id': story.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stories/friends')
@login_required
def get_friends_stories():
    try:
        uid = session['user_id']
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == uid, Friendship.user2_id == uid)
        ).all()
        friend_ids = [f.user2_id if f.user1_id == uid else f.user1_id for f in friendships]
        friend_ids.append(uid)
        
        stories = []
        for fid in friend_ids:
            if is_blocked(uid, fid) and fid != uid:
                continue
            
            user_stories = Story.query.filter(
                Story.user_id == fid,
                Story.created_at >= cutoff,
                Story.expires_at > datetime.now(timezone.utc)
            ).order_by(Story.created_at.desc()).all()
            
            for story in user_stories:
                if story.privacy == 'public':
                    allowed = True
                elif story.privacy == 'friends':
                    allowed = fid == uid or fid in friend_ids
                elif story.privacy == 'custom':
                    allowed = fid == uid or StoryPrivacy.query.filter_by(
                        story_id=story.id, allowed_user_id=uid
                    ).first() is not None
                else:
                    allowed = False
                
                if allowed:
                    viewed = StoryView.query.filter_by(story_id=story.id, viewer_id=uid).first() is not None
                    stories.append({
                        'id': story.id,
                        'user_id': story.user_id,
                        'username': story.user.username,
                        'avatar': story.user.avatar_url or f"https://ui-avatars.com/api/?name={story.user.username}&background=6c63ff&color=fff",
                        'content': story.content,
                        'media_url': story.media_url,
                        'media_type': story.media_type,
                        'created_at': story.created_at.isoformat(),
                        'expires_at': story.expires_at.isoformat(),
                        'viewed': viewed,
                        'is_own': story.user_id == uid
                    })
        
        user_stories = {}
        for story in stories:
            if story['user_id'] not in user_stories:
                user_stories[story['user_id']] = {
                    'user_id': story['user_id'],
                    'username': story['username'],
                    'avatar': story['avatar'],
                    'stories': [],
                    'has_unviewed': False
                }
            user_stories[story['user_id']]['stories'].append(story)
            if not story['viewed']:
                user_stories[story['user_id']]['has_unviewed'] = True
        
        return jsonify({'success': True, 'stories': list(user_stories.values())})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stories/<int:story_id>/view', methods=['POST'])
@login_required
def view_story(story_id):
    try:
        uid = session['user_id']
        story = Story.query.get(story_id)
        if not story:
            return jsonify({'success': False, 'error': 'Story not found'}), 404
        
        existing = StoryView.query.filter_by(story_id=story_id, viewer_id=uid).first()
        if not existing:
            db.session.add(StoryView(story_id=story_id, viewer_id=uid))
            db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stories/<int:story_id>/viewers')
@login_required
def get_story_viewers(story_id):
    try:
        uid = session['user_id']
        story = Story.query.get(story_id)
        if not story or story.user_id != uid:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        views = StoryView.query.filter_by(story_id=story_id).order_by(StoryView.viewed_at.desc()).all()
        viewers = []
        for view in views:
            viewer = User.query.get(view.viewer_id)
            if viewer:
                viewers.append({
                    'user_id': viewer.id,
                    'username': viewer.username,
                    'avatar': viewer.avatar_url or f"https://ui-avatars.com/api/?name={viewer.username}&background=6c63ff&color=fff",
                    'viewed_at': view.viewed_at.isoformat()
                })
        
        return jsonify({'success': True, 'viewers': viewers, 'count': len(viewers)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stories/<int:story_id>/delete', methods=['DELETE'])
@login_required
def delete_story(story_id):
    try:
        uid = session['user_id']
        story = Story.query.get(story_id)
        if not story or story.user_id != uid:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        StoryView.query.filter_by(story_id=story_id).delete()
        StoryPrivacy.query.filter_by(story_id=story_id).delete()
        db.session.delete(story)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# BLOCKLIST ROUTES
# ============================================================
@app.route('/api/blocklist')
@login_required
def get_blocklist():
    try:
        uid = session['user_id']
        blocked = BlockedUser.query.filter_by(blocker_id=uid).all()
        blocked_users = []
        for b in blocked:
            user = User.query.get(b.blocked_id)
            if user:
                blocked_users.append({
                    'id': user.id,
                    'username': user.username,
                    'avatar': user.avatar_url or f"https://ui-avatars.com/api/?name={user.username}&background=6c63ff&color=fff",
                    'blocked_at': b.created_at.isoformat()
                })
        return jsonify({'success': True, 'blocked_users': blocked_users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blocklist/add', methods=['POST'])
@login_required
def block_user():
    try:
        data = request.get_json()
        uid = session['user_id']
        blocked_id = data.get('user_id')
        
        if not blocked_id or uid == blocked_id:
            return jsonify({'success': False, 'error': 'Invalid user'}), 400
        
        existing = BlockedUser.query.filter_by(blocker_id=uid, blocked_id=blocked_id).first()
        if existing:
            return jsonify({'success': False, 'error': 'User already blocked'}), 400
        
        db.session.add(BlockedUser(blocker_id=uid, blocked_id=blocked_id))
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blocklist/remove', methods=['POST'])
@login_required
def unblock_user():
    try:
        data = request.get_json()
        uid = session['user_id']
        blocked_id = data.get('user_id')
        
        blocked = BlockedUser.query.filter_by(blocker_id=uid, blocked_id=blocked_id).first()
        if not blocked:
            return jsonify({'success': False, 'error': 'User not blocked'}), 400
        
        db.session.delete(blocked)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# FRIENDS ROUTES
# ============================================================
@app.route('/api/friends')
@login_required
def get_friends():
    try:
        uid = session['user_id']
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == uid, Friendship.user2_id == uid)
        ).all()
        friends = []
        for f in friendships:
            fid = f.user2_id if f.user1_id == uid else f.user1_id
            friend = User.query.get(fid)
            if not friend: continue
            cid = get_chat_id(uid, fid)
            last = Message.query.filter_by(chat_id=cid, is_deleted=False).order_by(Message.created_at.desc()).first()
            
            unread_count = Message.query.filter(
                Message.chat_id == cid,
                Message.sender_id == fid,
                Message.is_deleted == False,
                ~Message.id.in_(
                    db.session.query(MessageRead.message_id).filter_by(user_id=uid)
                )
            ).count()
            
            av = friend.avatar_url or f"https://ui-avatars.com/api/?name={friend.username}&background=6c63ff&color=fff&size=96"
            friends.append({
                'id': friend.id, 'username': friend.username,
                'avatar': av, 'avatar_url': av,
                'status': friend.status or 'Available',
                'bio': friend.bio or '',
                'is_online': is_user_online(fid),
                'chat_id': cid,
                'last_message': last.content[:40] if last else None,
                'last_message_time': last.created_at.isoformat() if last else None,
                'unread_count': unread_count
            })
        return jsonify({'success': True, 'friends': friends})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    try:
        uid = session['user_id']
        received = FriendRequest.query.filter_by(to_user_id=uid, status='pending').order_by(FriendRequest.created_at.desc()).all()
        sent = FriendRequest.query.filter_by(from_user_id=uid, status='pending').all()
        def fmt(req, tid):
            u = User.query.get(tid)
            av = u.avatar_url or f"https://ui-avatars.com/api/?name={u.username}&background=6c63ff&color=fff"
            return {'request_id': req.id, 'user_id': u.id, 'username': u.username,
                    'avatar': av, 'time_ago': get_time_ago(req.created_at)}
        return jsonify({
            'success': True,
            'received': [fmt(r, r.from_user_id) for r in received],
            'sent': [fmt(r, r.to_user_id) for r in sent]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    try:
        data = request.get_json()
        uid = session['user_id']
        to_id = data.get('to_user_id')
        if not to_id or uid == to_id:
            return jsonify({'success': False, 'error': 'Invalid user'}), 400
        if are_friends(uid, to_id):
            return jsonify({'success': False, 'error': 'Already friends'}), 400
        if FriendRequest.query.filter_by(from_user_id=uid, to_user_id=to_id, status='pending').first():
            return jsonify({'success': False, 'error': 'Request already sent'}), 400
        db.session.add(FriendRequest(from_user_id=uid, to_user_id=to_id))
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    try:
        req = FriendRequest.query.get(request.get_json().get('request_id'))
        if not req or req.to_user_id != session['user_id']:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        db.session.add(Friendship(
            user1_id=min(req.from_user_id, req.to_user_id),
            user2_id=max(req.from_user_id, req.to_user_id)
        ))
        db.session.delete(req)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend_request():
    try:
        req = FriendRequest.query.get(request.get_json().get('request_id'))
        if not req or req.to_user_id != session['user_id']:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        db.session.delete(req)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# MESSAGES ROUTES
# ============================================================
@app.route('/api/messages/<chat_id>')
@login_required
def get_messages(chat_id):
    try:
        uid = session['user_id']
        if chat_id != 'global' and str(uid) not in chat_id.split('-'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        msgs = Message.query.filter_by(chat_id=chat_id)\
                            .order_by(Message.created_at.desc())\
                            .limit(50).all()
        msgs.reverse()
        
        for msg in msgs:
            if msg.sender_id != uid and not msg.is_deleted:
                existing_read = MessageRead.query.filter_by(message_id=msg.id, user_id=uid).first()
                if not existing_read:
                    db.session.add(MessageRead(message_id=msg.id, user_id=uid))
        db.session.commit()
        
        return jsonify({
            'success': True,
            'messages': [format_message(m, uid) for m in msgs]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/search/<chat_id>')
@login_required
def search_messages(chat_id):
    try:
        uid = session['user_id']
        query = request.args.get('q', '').strip()
        if not query:
            return jsonify({'success': True, 'messages': []})
        if chat_id != 'global' and str(uid) not in chat_id.split('-'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        msgs = Message.query.filter(
            Message.chat_id == chat_id,
            Message.is_deleted == False,
            Message.content.ilike(f'%{query}%')
        ).order_by(Message.created_at.desc()).limit(20).all()
        return jsonify({
            'success': True,
            'messages': [format_message(m, uid) for m in msgs]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/pinned/<chat_id>')
@login_required
def get_pinned_messages(chat_id):
    try:
        uid = session['user_id']
        if chat_id != 'global' and str(uid) not in chat_id.split('-'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        msgs = Message.query.filter_by(chat_id=chat_id, is_pinned=True, is_deleted=False)\
                            .order_by(Message.created_at.desc()).all()
        return jsonify({
            'success': True,
            'messages': [format_message(m, uid) for m in msgs]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/edit', methods=['PUT'])
@login_required
def edit_message(msg_id):
    try:
        uid = session['user_id']
        msg = Message.query.get(msg_id)
        if not msg or msg.sender_id != uid:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        if msg.is_deleted:
            return jsonify({'success': False, 'error': 'Cannot edit deleted message'}), 400
        
        data = request.get_json()
        new_content = data.get('content', '').strip()
        if not new_content:
            return jsonify({'success': False, 'error': 'Content required'}), 400
        
        msg.content = new_content
        msg.is_edited = True
        msg.edited_at = datetime.now(timezone.utc)
        db.session.commit()
        
        socketio.emit('message_edited', format_message(msg, uid), room=msg.chat_id)
        return jsonify({'success': True, 'message': format_message(msg, uid)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/delete', methods=['DELETE'])
@login_required
def delete_message(msg_id):
    try:
        uid = session['user_id']
        msg = Message.query.get(msg_id)
        if not msg or msg.sender_id != uid:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        msg.is_deleted = True
        msg.content = '[Message deleted]'
        db.session.commit()
        
        socketio.emit('message_deleted', {'id': msg_id, 'chat_id': msg.chat_id}, room=msg.chat_id)
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/pin', methods=['POST'])
@login_required
def toggle_pin_message(msg_id):
    try:
        uid = session['user_id']
        msg = Message.query.get(msg_id)
        if not msg:
            return jsonify({'success': False, 'error': 'Message not found'}), 404
        if str(uid) not in msg.chat_id.split('-'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        msg.is_pinned = not msg.is_pinned
        db.session.commit()
        
        socketio.emit('message_pinned', {
            'id': msg_id,
            'chat_id': msg.chat_id,
            'is_pinned': msg.is_pinned
        }, room=msg.chat_id)
        return jsonify({'success': True, 'is_pinned': msg.is_pinned})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/react', methods=['POST'])
@login_required
def react_to_message(msg_id):
    try:
        uid = session['user_id']
        data = request.get_json()
        emoji = data.get('emoji', '').strip()
        if not emoji:
            return jsonify({'success': False, 'error': 'Emoji required'}), 400
        
        msg = Message.query.get(msg_id)
        if not msg:
            return jsonify({'success': False, 'error': 'Message not found'}), 404
        
        existing = MessageReaction.query.filter_by(
            message_id=msg_id,
            user_id=uid,
            emoji=emoji
        ).first()
        
        if existing:
            db.session.delete(existing)
            action = 'removed'
        else:
            db.session.add(MessageReaction(message_id=msg_id, user_id=uid, emoji=emoji))
            action = 'added'
        
        db.session.commit()
        
        socketio.emit('message_reaction', {
            'message_id': msg_id,
            'chat_id': msg.chat_id,
            'user_id': uid,
            'emoji': emoji,
            'action': action,
            'message': format_message(msg, uid)
        }, room=msg.chat_id)
        
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# IMAGE UPLOAD
# ============================================================
@app.route('/api/upload/image', methods=['POST'])
@login_required
def upload_image():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image'}), 400
        
        file = request.files['image']
        if not file or not file.filename:
            return jsonify({'success': False, 'error': 'No image'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file type'}), 400
        
        ext = file.filename.rsplit('.', 1)[1].lower()
        fn = f"{uuid.uuid4().hex}.{ext}"
        
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filepath = os.path.join(UPLOAD_FOLDER, fn)
        file.save(filepath)
        
        url = f"/static/uploads/{fn}"
        return jsonify({'success': True, 'url': url})
    except Exception as e:
        print(f"❌ Upload error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# SOCKET.IO
# ============================================================
@socketio.on('connect')
def handle_connect():
    uid = session.get('user_id')
    uname = session.get('username')
    if not uid: return False
    
    online_users[uid] = {
        'sid': request.sid,
        'last_seen': datetime.now(timezone.utc)
    }
    
    user = User.query.get(uid)
    if user:
        user.last_seen = datetime.now(timezone.utc)
        db.session.commit()
    
    join_room(f'user_{uid}')
    join_room('global')
    
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == uid, Friendship.user2_id == uid)
    ).all()
    for f in friendships:
        fid = f.user2_id if f.user1_id == uid else f.user1_id
        socketio.emit('user_online', {'user_id': uid, 'online': True}, room=f'user_{fid}')
    
    return True

@socketio.on('join_chat')
def handle_join_chat(data):
    cid = data.get('chat_id')
    uid = session.get('user_id')
    if cid and uid: join_room(cid)

@socketio.on('send_message')
def handle_send_message(data):
    uid = session.get('user_id')
    uname = session.get('username')
    if not uid:
        emit('error', {'message': 'Not authenticated'})
        return
    cid = data.get('chat_id') or data.get('chatId', 'global')
    content = data.get('content', '').strip()
    mtype = data.get('message_type') or data.get('type', 'text')
    reply_to_id = data.get('reply_to_id')
    
    if not content: return
    if cid != 'global' and str(uid) not in cid.split('-'):
        emit('error', {'message': 'Unauthorized'})
        return
    try:
        msg = Message(
            chat_id=cid,
            sender_id=uid,
            content=content,
            message_type=mtype,
            reply_to_id=reply_to_id
        )
        db.session.add(msg)
        db.session.commit()
        db.session.refresh(msg)
        
        socketio.emit('new_message', format_message(msg, uid), room=cid)
    except Exception as e:
        db.session.rollback()
        print(f"❌ Message error: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    uid = session.get('user_id')
    if uid and uid in online_users:
        del online_users[uid]
        
        user = User.query.get(uid)
        if user:
            user.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == uid, Friendship.user2_id == uid)
        ).all()
        for f in friendships:
            fid = f.user2_id if f.user1_id == uid else f.user1_id
            socketio.emit('user_online', {'user_id': uid, 'online': False}, room=f'user_{fid}')

@socketio.on('typing_start')
def handle_typing_start(data):
    uid = session.get('user_id')
    uname = session.get('username')
    cid = data.get('chatId') or data.get('chat_id')
    if uid and cid:
        emit('typing_start', {'username': uname}, room=cid, include_self=False)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    uid = session.get('user_id')
    cid = data.get('chatId') or data.get('chat_id')
    if uid and cid:
        emit('typing_stop', {}, room=cid, include_self=False)

# ============================================================
# AI ROUTES
# ============================================================
@app.route('/api/ai/status')
@login_required
def ai_status():
    try:
        uid = session['user_id']
        user = User.query.get(uid)
        
        today = datetime.now(timezone.utc).date()
        usage = AIUsage.query.filter_by(user_id=uid, date=today).first()
        
        conversations = AIConversation.query.filter_by(user_id=uid)\
            .order_by(AIConversation.updated_at.desc())\
            .limit(5).all()
        
        return jsonify({
            'success': True,
            'ai_enabled': user.ai_enabled,
            'daily_used': usage.count if usage else 0,
            'daily_limit': AI_DAILY_LIMIT,
            'recent_conversations': [{
                'id': c.id,
                'title': c.title,
                'updated_at': c.updated_at.isoformat()
            } for c in conversations]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/conversations', methods=['GET'])
@login_required
def get_ai_conversations():
    try:
        uid = session['user_id']
        conversations = AIConversation.query.filter_by(user_id=uid)\
            .order_by(AIConversation.updated_at.desc()).all()
        
        return jsonify({
            'success': True,
            'conversations': [{
                'id': c.id,
                'title': c.title,
                'created_at': c.created_at.isoformat(),
                'updated_at': c.updated_at.isoformat(),
                'message_count': len(c.messages)
            } for c in conversations]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/conversation/<int:conv_id>', methods=['GET'])
@login_required
def get_ai_conversation(conv_id):
    try:
        uid = session['user_id']
        conv = AIConversation.query.filter_by(id=conv_id, user_id=uid).first()
        if not conv:
            return jsonify({'success': False, 'error': 'Conversation not found'}), 404
        
        messages = AIMessage.query.filter_by(conversation_id=conv_id)\
            .order_by(AIMessage.created_at.asc()).all()
        
        return jsonify({
            'success': True,
            'conversation': {
                'id': conv.id,
                'title': conv.title,
                'created_at': conv.created_at.isoformat(),
                'updated_at': conv.updated_at.isoformat(),
                'messages': [{
                    'id': m.id,
                    'role': m.role,
                    'content': m.content,
                    'model_used': m.model_used,
                    'created_at': m.created_at.isoformat()
                } for m in messages]
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/conversation/new', methods=['POST'])
@login_required
def create_ai_conversation():
    try:
        uid = session['user_id']
        data = request.get_json()
        title = data.get('title', 'New Conversation')
        
        conv = AIConversation(user_id=uid, title=title)
        db.session.add(conv)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'conversation_id': conv.id,
            'title': conv.title
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/conversation/<int:conv_id>/delete', methods=['DELETE'])
@login_required
def delete_ai_conversation(conv_id):
    try:
        uid = session['user_id']
        conv = AIConversation.query.filter_by(id=conv_id, user_id=uid).first()
        if not conv:
            return jsonify({'success': False, 'error': 'Conversation not found'}), 404
        
        AIMessage.query.filter_by(conversation_id=conv_id).delete()
        db.session.delete(conv)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/ask', methods=['POST'])
@login_required
def ai_ask():
    try:
        uid = session['user_id']
        user = User.query.get(uid)
        
        if not user.ai_enabled:
            return jsonify({
                'success': False, 
                'error': 'AI assistant not enabled. Enable it in settings.'
            }), 403
        
        data = request.get_json()
        question = data.get('question', '').strip()
        conversation_id = data.get('conversation_id')
        model = data.get('model', DEFAULT_AI_MODEL)
        
        if not question:
            return jsonify({'success': False, 'error': 'Question is required'}), 400
        
        today = datetime.now(timezone.utc).date()
        usage = AIUsage.query.filter_by(user_id=uid, date=today).first()
        if usage and usage.count >= AI_DAILY_LIMIT:
            return jsonify({
                'success': False,
                'error': f'Daily limit reached ({AI_DAILY_LIMIT} questions)'
            }), 429
        
        if conversation_id:
            conv = AIConversation.query.filter_by(id=conversation_id, user_id=uid).first()
            if not conv:
                return jsonify({'success': False, 'error': 'Conversation not found'}), 404
        else:
            title = question[:50] + ('...' if len(question) > 50 else '')
            conv = AIConversation(user_id=uid, title=title)
            db.session.add(conv)
            db.session.commit()
            conversation_id = conv.id
        
        user_msg = AIMessage(
            conversation_id=conversation_id,
            role='user',
            content=question,
            model_used=model
        )
        db.session.add(user_msg)
        
        history = AIMessage.query.filter_by(conversation_id=conversation_id)\
            .order_by(AIMessage.created_at.desc())\
            .limit(10).all()
        history.reverse()
        
        messages = [
            {"role": "system", "content": "You are a helpful AI assistant. Provide clear, accurate, and concise answers."}
        ]
        
        for msg in history:
            messages.append({
                "role": msg.role,
                "content": msg.content
            })
        
        if AI_PROVIDER == 'openai':
            if not OPENAI_API_KEY:
                return jsonify({'success': False, 'error': 'OpenAI API key not configured'}), 500
            
            openai.api_key = OPENAI_API_KEY
            response = openai.ChatCompletion.create(
                model=model,
                messages=messages,
                max_tokens=1000,
                temperature=0.7
            )
            
            answer = response.choices[0].message.content
            tokens_used = response.usage.total_tokens
            
        else:
            return jsonify({'success': False, 'error': 'Invalid AI provider'}), 500
        
        ai_msg = AIMessage(
            conversation_id=conversation_id,
            role='assistant',
            content=answer,
            model_used=model,
            tokens_used=tokens_used
        )
        db.session.add(ai_msg)
        
        conv.updated_at = datetime.now(timezone.utc)
        
        if usage:
            usage.count += 1
            usage.tokens += tokens_used
        else:
            usage = AIUsage(user_id=uid, date=today, count=1, tokens=tokens_used)
            db.session.add(usage)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'answer': answer,
            'conversation_id': conversation_id,
            'message_id': ai_msg.id,
            'tokens_used': tokens_used,
            'model': model,
            'daily_remaining': AI_DAILY_LIMIT - (usage.count if usage else 0)
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ AI Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/settings', methods=['POST'])
@login_required
def save_ai_settings():
    try:
        uid = session['user_id']
        data = request.get_json()
        
        user = User.query.get(uid)
        user.ai_enabled = data.get('ai_enabled', False)
        user.ai_model_preference = data.get('ai_model', DEFAULT_AI_MODEL)
        
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/history')
@login_required
def ai_history():
    try:
        uid = session['user_id']
        
        messages = AIMessage.query\
            .join(AIConversation, AIConversation.id == AIMessage.conversation_id)\
            .filter(AIConversation.user_id == uid)\
            .order_by(AIMessage.created_at.desc())\
            .limit(50).all()
        
        history = []
        for msg in messages:
            history.append({
                'id': msg.id,
                'conversation_id': msg.conversation_id,
                'role': msg.role,
                'content': msg.content[:100] + ('...' if len(msg.content) > 100 else ''),
                'created_at': msg.created_at.isoformat(),
                'model': msg.model_used
            })
        
        return jsonify({
            'success': True,
            'history': history
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/search')
@login_required
def ai_search():
    try:
        uid = session['user_id']
        query = request.args.get('q', '').strip()
        
        if not query:
            return jsonify({'success': True, 'results': []})
        
        results = AIMessage.query\
            .join(AIConversation, AIConversation.id == AIMessage.conversation_id)\
            .filter(AIConversation.user_id == uid)\
            .filter(AIMessage.content.ilike(f'%{query}%'))\
            .order_by(AIMessage.created_at.desc())\
            .limit(20).all()
        
        return jsonify({
            'success': True,
            'results': [{
                'id': r.id,
                'conversation_id': r.conversation_id,
                'role': r.role,
                'content': r.content[:150] + ('...' if len(r.content) > 150 else ''),
                'created_at': r.created_at.isoformat()
            } for r in results]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/stats')
@login_required
def ai_stats():
    try:
        uid = session['user_id']
        
        thirty_days_ago = datetime.now(timezone.utc).date() - timedelta(days=30)
        daily_stats = AIUsage.query.filter(
            AIUsage.user_id == uid,
            AIUsage.date >= thirty_days_ago
        ).order_by(AIUsage.date.desc()).all()
        
        total_queries = db.session.query(db.func.sum(AIUsage.count)).filter_by(user_id=uid).scalar() or 0
        total_tokens = db.session.query(db.func.sum(AIUsage.tokens)).filter_by(user_id=uid).scalar() or 0
        
        return jsonify({
            'success': True,
            'stats': {
                'total_queries': total_queries,
                'total_tokens': total_tokens,
                'daily': [{
                    'date': s.date.isoformat(),
                    'count': s.count,
                    'tokens': s.tokens
                } for s in daily_stats]
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# HEALTH / DEBUG
# ============================================================
@app.route('/health')
def health():
    try:
        return jsonify({
            'status': 'ok',
            'users': User.query.count(),
            'messages': Message.query.count(),
            'online_users': len(online_users)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/debug/users')
def debug_users():
    try:
        return jsonify({'success': True, 'users': [u.to_dict() for u in User.query.all()]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.teardown_appcontext
def shutdown_session(exception=None): 
    db.session.remove()

# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 HPZ Messenger on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
