import os
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, send_from_directory, make_response
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
# ── Stable SECRET_KEY: use env var, or generate once and persist to a file ──
# os.urandom(32) on every restart invalidates all sessions — never use it in prod
def _get_secret_key():
    # 1. Always prefer the environment variable (set this in Render dashboard)
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    # 2. Try to persist a key to disk (works locally, fails gracefully on read-only hosts)
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        key_file = os.path.join(base, '.secret_key')
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                k = f.read().strip()
                if len(k) >= 32:
                    return k
        import secrets
        k = secrets.token_hex(32)
        with open(key_file, 'w') as f:
            f.write(k)
        return k
    except Exception:
        pass
    # 3. Stable fallback — set SECRET_KEY env var in Render for real security
    return 'hpz-fallback-key-set-SECRET_KEY-env-var-in-render-dashboard'

app.config['SECRET_KEY'] = _get_secret_key()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30  # 30 days
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = 'hpz_session'
app.config['SESSION_COOKIE_SECURE'] = bool(os.environ.get('RENDER'))
app.config['SESSION_COOKIE_PATH'] = '/'
# Never share session across subdomains
app.config['SESSION_COOKIE_DOMAIN'] = None
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
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)
# Online users tracking: {user_id: {'sid': socket_id, 'last_seen': datetime}}
online_users = {}
# ============================================================
# DATABASE MODELS
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

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    is_edited = db.Column(db.Boolean, default=False)
    caption = db.Column(db.String(500), nullable=True)
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
    media_type = db.Column(db.String(20), default='text')
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

class PinnedChat(db.Model):
    __tablename__ = 'pinned_chats'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    chat_id = db.Column(db.String(100), nullable=False)
    pinned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('user_id', 'chat_id'),)

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
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            # API routes get JSON, page routes get redirect
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Login required'}), 401
            return redirect('/')
        # Validate user still exists in DB
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Session expired'}), 401
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_chat_id(user1_id, user2_id):
    return f"{min(user1_id, user2_id)}-{max(user1_id, user2_id)}"

def are_friends(user1_id, user2_id):
    return Friendship.query.filter(
        or_(
            and_(Friendship.user1_id == user1_id, Friendship.user2_id == user2_id),
            and_(Friendship.user1_id == user2_id, Friendship.user2_id == user1_id)
        )
    ).first() is not None

def is_blocked(user_id, other_user_id):
    return BlockedUser.query.filter(
        or_(
            and_(BlockedUser.blocker_id == user_id, BlockedUser.blocked_id == other_user_id),
            and_(BlockedUser.blocker_id == other_user_id, BlockedUser.blocked_id == user_id)
        )
    ).first() is not None

def is_user_online(user_id):
    if user_id in online_users:
        last_seen = online_users[user_id].get('last_seen')
        if last_seen and (datetime.now(timezone.utc) - last_seen).seconds < 30:
            return True
    return False

def get_time_ago(dt):
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
        'reply_to': reply_msg,
        'caption': msg.caption or ''
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
def _no_cache(response):
    """Prevent browser from caching authenticated pages."""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return _no_cache(redirect('/chat'))
        session.clear()
    return _no_cache(make_response(render_template('login.html')))

@app.route('/register')
def register_page():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return _no_cache(redirect('/chat'))
        session.clear()
    return _no_cache(make_response(render_template('register.html')))

@app.route('/chat')
@login_required
def chat():
    user = User.query.get(session['user_id'])
    if not user:
        return redirect('/')
    resp = make_response(render_template('chat.html', user=user, user_id=user.id))
    return _no_cache(resp)

@app.route('/logo')
def serve_logo():
    templates_dir = os.path.join(BASE_DIR, 'templates')
    static_dir = os.path.join(BASE_DIR, 'static')
    for d, fname in [(templates_dir, 'hepozy_logo.jpg'), (templates_dir, 'hepozy_logo.png'),
                     (static_dir, 'hepozy_logo.jpg'), (static_dir, 'logo.png'), (static_dir, 'logo.jpg')]:
        if os.path.exists(os.path.join(d, fname)):
            return send_from_directory(d, fname)
    return '', 404

# ============================================================
# AUTHENTICATION API
# ============================================================
@app.route('/api/auth/register', methods=['POST'])
def register():
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
        return jsonify({'success': True, 'message': 'Registration successful', 'user': user.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
    session['user_id'] = user.id
    session.permanent = True
    return jsonify({'success': True, 'message': 'Login successful', 'user': user.to_dict()})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id and user_id in online_users:
        del online_users[user_id]
    session.clear()
    response = jsonify({'success': True, 'message': 'Logged out'})
    # Delete cookie with all possible path/domain combos to ensure it's gone
    response.delete_cookie('hpz_session', path='/')
    response.delete_cookie('session', path='/')
    response.delete_cookie('hpz_session')
    response.delete_cookie('session')
    # Explicitly expire it
    response.set_cookie('hpz_session', '', expires=0, max_age=0, path='/')
    return _no_cache(response)

# ============================================================
# USER & PROFILE API
# ============================================================
@app.route('/api/users/search')
@login_required
def search_users():
    query = request.args.get('q', '').strip()
    user_id = session['user_id']
    if not query:
        return jsonify({'success': False, 'error': 'Search query required'}), 400
    users = User.query.filter(
        User.username.ilike(f'%{query}%'),
        User.id != user_id
    ).limit(10).all()
    results = []
    for u in users:
        if is_blocked(user_id, u.id):
            continue
        relationship = 'none'
        if are_friends(user_id, u.id):
            relationship = 'friend'
        else:
            req_sent = FriendRequest.query.filter_by(from_user_id=user_id, to_user_id=u.id, status='pending').first()
            req_received = FriendRequest.query.filter_by(from_user_id=u.id, to_user_id=user_id, status='pending').first()
            if req_sent:
                relationship = 'request_sent'
            elif req_received:
                relationship = 'request_received'
        results.append({**u.to_dict(), 'relationship': relationship, 'is_online': is_user_online(u.id)})
    return jsonify({'success': True, 'results': results})

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    return jsonify({'success': True, 'user': user.to_dict()})

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    data = request.get_json()
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
        # Notify online friends of profile update so their friend list refreshes
        uid = session['user_id']
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == uid, Friendship.user2_id == uid)
        ).all()
        for f in friendships:
            fid = f.user2_id if f.user1_id == uid else f.user1_id
            sid = get_sid(fid)
            if sid:
                socketio.emit('profile_updated', {
                    'user_id': uid,
                    'username': user.username,
                    'avatar_url': user.avatar_url or '',
                    'status': user.status or ''
                }, room=sid)
        return jsonify({'success': True, 'user': user.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    file = request.files['avatar']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file'}), 400
    try:
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"avatar_{session['user_id']}_{uuid.uuid4().hex[:8]}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        user = User.query.get(session['user_id'])
        user.avatar_url = f'/static/uploads/{filename}'
        db.session.commit()
        # Notify friends of avatar change
        uid = session['user_id']
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == uid, Friendship.user2_id == uid)
        ).all()
        for f in friendships:
            fid = f.user2_id if f.user1_id == uid else f.user1_id
            sid = get_sid(fid)
            if sid:
                socketio.emit('profile_updated', {
                    'user_id': uid,
                    'username': user.username,
                    'avatar_url': user.avatar_url or '',
                    'status': user.status or ''
                }, room=sid)
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
    user_id = session['user_id']
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    friends = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.get(friend_id)
        if not friend:
            continue
        chat_id = get_chat_id(user_id, friend_id)
        last_msg = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at.desc()).first()
        unread = 0
        if last_msg:
            unread = Message.query.filter(
                Message.chat_id == chat_id,
                Message.sender_id == friend_id,
                ~Message.id.in_(db.session.query(MessageRead.message_id).filter_by(user_id=user_id))
            ).count()
        friends.append({
            **friend.to_dict(),
            'chat_id': chat_id,
            'is_online': is_user_online(friend_id),
            'last_message': last_msg.content[:50] if last_msg else None,
            'last_message_time': last_msg.created_at.isoformat() if last_msg else None,
            'unread_count': unread
        })
    friends.sort(key=lambda x: x['last_message_time'] or '', reverse=True)
    return jsonify({'success': True, 'friends': friends})

@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    user_id = session['user_id']
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
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    from_user_id = session['user_id']
    if from_user_id == to_user_id:
        return jsonify({'success': False, 'error': 'Cannot add yourself'}), 400
    if are_friends(from_user_id, to_user_id):
        return jsonify({'success': False, 'error': 'Already friends'}), 400
    existing = FriendRequest.query.filter_by(from_user_id=from_user_id, to_user_id=to_user_id, status='pending').first()
    if existing:
        return jsonify({'success': False, 'error': 'Request already sent'}), 400
    try:
        req = FriendRequest(from_user_id=from_user_id, to_user_id=to_user_id)
        db.session.add(req)
        db.session.commit()
        # Notify recipient instantly via socket
        sender = User.query.get(from_user_id)
        recipient_sid = get_sid(to_user_id)
        if recipient_sid and sender:
            socketio.emit('friend_request_received', {
                'request_id': req.id,
                'from_user_id': from_user_id,
                'username': sender.username,
                'avatar_url': sender.avatar_url or ''
            }, room=recipient_sid)
        return jsonify({'success': True, 'message': 'Friend request sent'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    data = request.get_json()
    request_id = data.get('request_id')
    user_id = session['user_id']
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != user_id:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    try:
        friendship = Friendship(user1_id=req.from_user_id, user2_id=req.to_user_id)
        db.session.add(friendship)
        req.status = 'accepted'
        db.session.commit()
        # Notify the sender that their request was accepted
        acceptor = User.query.get(user_id)
        sender_sid = get_sid(req.from_user_id)
        if sender_sid and acceptor:
            socketio.emit('friend_request_accepted', {
                'user_id': user_id,
                'username': acceptor.username
            }, room=sender_sid)
        return jsonify({'success': True, 'message': 'Friend request accepted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend_request():
    data = request.get_json()
    request_id = data.get('request_id')
    user_id = session['user_id']
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != user_id:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    try:
        req.status = 'rejected'
        db.session.commit()
        # Notify sender their request was rejected
        rejecter = User.query.get(user_id)
        sender_sid = get_sid(req.from_user_id)
        if sender_sid and rejecter:
            socketio.emit('friend_request_rejected', {
                'user_id': user_id,
                'username': rejecter.username
            }, room=sender_sid)
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
    user_id = session['user_id']
    parts = chat_id.split('-')
    if len(parts) != 2:
        return jsonify({'success': False, 'error': 'Invalid chat ID'}), 400
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at).all()
    return jsonify({'success': True, 'messages': [format_message(m, user_id) for m in messages]})

@app.route('/api/messages/search/<chat_id>')
@login_required
def search_messages(chat_id):
    query = request.args.get('q', '').strip()
    user_id = session['user_id']
    if not query:
        return jsonify({'success': False, 'error': 'Search query required'}), 400
    parts = chat_id.split('-')
    if len(parts) != 2:
        return jsonify({'success': False, 'error': 'Invalid chat ID'}), 400
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    messages = Message.query.filter(
        Message.chat_id == chat_id,
        Message.content.ilike(f'%{query}%'),
        Message.is_deleted == False
    ).order_by(Message.created_at.desc()).limit(50).all()
    return jsonify({'success': True, 'messages': [format_message(m, user_id) for m in messages]})

@app.route('/api/messages/pinned/<chat_id>')
@login_required
def get_pinned_messages(chat_id):
    user_id = session['user_id']
    parts = chat_id.split('-')
    if len(parts) != 2:
        return jsonify({'success': False, 'error': 'Invalid chat ID'}), 400
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    messages = Message.query.filter_by(chat_id=chat_id, is_pinned=True).all()
    return jsonify({'success': True, 'messages': [format_message(m, user_id) for m in messages]})

@app.route('/api/messages/<int:msg_id>/edit', methods=['PUT'])
@login_required
def edit_message(msg_id):
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
        socketio.emit('message_edited', format_message(msg, user_id), room=msg.chat_id)
        return jsonify({'success': True, 'message': format_message(msg, user_id)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/delete', methods=['DELETE'])
@login_required
def delete_message(msg_id):
    user_id = session['user_id']
    msg = Message.query.get(msg_id)
    if not msg or msg.sender_id != user_id:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    try:
        msg.is_deleted = True
        msg.content = '[Message deleted]'
        db.session.commit()
        socketio.emit('message_deleted', {'id': msg.id, 'chat_id': msg.chat_id}, room=msg.chat_id)
        return jsonify({'success': True, 'message': 'Message deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/pin', methods=['POST'])
@login_required
def toggle_pin_message(msg_id):
    user_id = session['user_id']
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    parts = msg.chat_id.split('-')
    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    try:
        msg.is_pinned = not msg.is_pinned
        db.session.commit()
        socketio.emit('message_pinned', {'id': msg.id, 'chat_id': msg.chat_id, 'is_pinned': msg.is_pinned}, room=msg.chat_id)
        return jsonify({'success': True, 'is_pinned': msg.is_pinned, 'message': format_message(msg, user_id)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/react', methods=['POST'])
@login_required
def react_to_message(msg_id):
    user_id = session['user_id']
    data = request.get_json()
    emoji = data.get('emoji', '').strip()
    if not emoji:
        return jsonify({'success': False, 'error': 'Emoji required'}), 400
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    try:
        existing = MessageReaction.query.filter_by(message_id=msg_id, user_id=user_id, emoji=emoji).first()
        if existing:
            db.session.delete(existing)
        else:
            reaction = MessageReaction(message_id=msg_id, user_id=user_id, emoji=emoji)
            db.session.add(reaction)
        db.session.commit()
        socketio.emit('message_reaction', {'message': format_message(msg, user_id), 'chat_id': msg.chat_id}, room=msg.chat_id)
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
    user_id = session['user_id']
    blocked = BlockedUser.query.filter_by(blocker_id=user_id).all()
    blocked_users = []
    for b in blocked:
        user = User.query.get(b.blocked_id)
        if user:
            blocked_users.append({'id': user.id, 'username': user.username, 'avatar_url': user.avatar_url, 'blocked_at': b.created_at.isoformat()})
    return jsonify({'success': True, 'blocked_users': blocked_users})

@app.route('/api/blocklist/add', methods=['POST'])
@login_required
def block_user():
    user_id = session['user_id']
    data = request.get_json()
    blocked_id = data.get('user_id')
    if user_id == blocked_id:
        return jsonify({'success': False, 'error': 'Cannot block yourself'}), 400
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
        story = Story(
            user_id=user_id, content=content, media_url=media_url,
            media_type=media_type, privacy=privacy,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.session.add(story)
        db.session.flush()
        if privacy == 'custom' and custom_users:
            for allowed_user_id in custom_users:
                db.session.add(StoryPrivacy(story_id=story.id, allowed_user_id=allowed_user_id))
        db.session.commit()
        # Notify online friends instantly via socket
        poster = User.query.get(user_id)
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
        ).all()
        notify_ids = [f.user2_id if f.user1_id == user_id else f.user1_id for f in friendships]
        if privacy == 'custom':
            notify_ids = [uid for uid in notify_ids if uid in [int(u) for u in custom_users]]
        for fid in notify_ids:
            sid = get_sid(fid)
            if sid:
                socketio.emit('new_story', {
                    'user_id': user_id,
                    'username': poster.username if poster else '',
                    'story_id': story.id,
                    'media_type': media_type,
                    'content': content[:80] if content else ''
                }, room=sid)
        return jsonify({'success': True, 'story_id': story.id, 'message': 'Story created'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stories/friends')
@login_required
def get_friends_stories():
    user_id = session['user_id']
    now = datetime.now(timezone.utc)
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    friend_ids = [f.user2_id if f.user1_id == user_id else f.user1_id for f in friendships]
    friend_ids.append(user_id)
    stories_by_user = {}
    for friend_id in friend_ids:
        user_stories = Story.query.filter(Story.user_id == friend_id, Story.expires_at > now).order_by(Story.created_at.desc()).all()
        visible_stories = []
        for story in user_stories:
            if story.user_id == user_id:
                visible_stories.append(story)
                continue
            if story.privacy in ('public', 'friends'):
                visible_stories.append(story)
            elif story.privacy == 'custom':
                if StoryPrivacy.query.filter_by(story_id=story.id, allowed_user_id=user_id).first():
                    visible_stories.append(story)
        if visible_stories:
            user = User.query.get(friend_id)
            unviewed = any(not StoryView.query.filter_by(story_id=s.id, viewer_id=user_id).first() for s in visible_stories)
            stories_by_user[friend_id] = {
                'user_id': friend_id, 'username': user.username, 'avatar_url': user.avatar_url,
                'has_unviewed': unviewed,
                'stories': [{'id': s.id, 'content': s.content, 'media_url': s.media_url, 'media_type': s.media_type, 'created_at': s.created_at.isoformat(), 'expires_at': s.expires_at.isoformat(), 'is_own': s.user_id == user_id, 'username': user.username} for s in visible_stories]
            }
    return jsonify({'success': True, 'stories': list(stories_by_user.values())})

@app.route('/api/stories/<int:story_id>/view', methods=['POST'])
@login_required
def view_story(story_id):
    user_id = session['user_id']
    story = Story.query.get(story_id)
    if not story:
        return jsonify({'success': False, 'error': 'Story not found'}), 404
    if story.user_id == user_id:
        return jsonify({'success': True, 'message': 'Own story'})
    if StoryView.query.filter_by(story_id=story_id, viewer_id=user_id).first():
        return jsonify({'success': True, 'message': 'Already viewed'})
    try:
        db.session.add(StoryView(story_id=story_id, viewer_id=user_id))
        db.session.commit()
        # Notify story owner instantly via socket
        owner_sid = get_sid(story.user_id)
        if owner_sid:
            viewer = User.query.get(user_id)
            # Get updated view count
            view_count = StoryView.query.filter_by(story_id=story_id).count()
            socketio.emit('story_viewed', {
                'story_id': story_id,
                'viewer_id': user_id,
                'viewer_username': viewer.username if viewer else '',
                'view_count': view_count
            }, room=owner_sid)
        return jsonify({'success': True, 'message': 'Story viewed'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stories/<int:story_id>/viewers')
@login_required
def get_story_viewers(story_id):
    user_id = session['user_id']
    story = Story.query.get(story_id)
    if not story or story.user_id != user_id:
        return jsonify({'success': False, 'error': 'Story not found'}), 404
    views = StoryView.query.filter_by(story_id=story_id).all()
    viewers = []
    for view in views:
        user = User.query.get(view.viewer_id)
        if user:
            viewers.append({'user_id': user.id, 'username': user.username, 'avatar_url': user.avatar_url, 'viewed_at': view.viewed_at.isoformat()})
    return jsonify({'success': True, 'count': len(viewers), 'viewers': viewers})

@app.route('/api/stories/<int:story_id>/delete', methods=['DELETE'])
@login_required
def delete_story(story_id):
    user_id = session['user_id']
    story = Story.query.get(story_id)
    if not story or story.user_id != user_id:
        return jsonify({'success': False, 'error': 'Story not found'}), 404
    try:
        poster_id = story.user_id
        StoryView.query.filter_by(story_id=story_id).delete()
        StoryPrivacy.query.filter_by(story_id=story_id).delete()
        db.session.delete(story)
        db.session.commit()
        # Notify online friends story was removed so they refresh story bar
        friendships = Friendship.query.filter(
            or_(Friendship.user1_id == poster_id, Friendship.user2_id == poster_id)
        ).all()
        for f in friendships:
            fid = f.user2_id if f.user1_id == poster_id else f.user1_id
            sid = get_sid(fid)
            if sid:
                socketio.emit('story_deleted', {'user_id': poster_id}, room=sid)
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
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    file = request.files['image']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file'}), 400
    try:
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"img_{uuid.uuid4().hex}.{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'success': True, 'url': f'/static/uploads/{filename}', 'filename': filename})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

AUDIO_EXTENSIONS = {'webm', 'ogg', 'mp3', 'wav', 'm4a', 'aac', 'opus'}

@app.route('/api/upload/audio', methods=['POST'])
@login_required
def upload_audio():
    if 'audio' not in request.files:
        return jsonify({'success': False, 'error': 'No audio file'}), 400
    file = request.files['audio']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'Empty file'}), 400
    ext = 'webm'
    if '.' in (file.filename or ''):
        candidate = file.filename.rsplit('.', 1)[1].lower()
        if candidate in AUDIO_EXTENSIONS:
            ext = candidate
    filename = f"audio_{session['user_id']}_{uuid.uuid4().hex[:10]}.{ext}"
    try:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'success': True, 'url': f'/static/uploads/{filename}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/<int:msg_id>/forward', methods=['POST'])
@login_required
def forward_message(msg_id):
    user_id = int(session['user_id'])
    data = request.get_json() or {}
    target_chat_ids = data.get('chat_ids', [])
    if not target_chat_ids:
        return jsonify({'success': False, 'error': 'No target chats'}), 400
    original = Message.query.get(msg_id)
    if not original:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    sender = User.query.get(user_id)
    forwarded = []
    for chat_id in target_chat_ids:
        parts = chat_id.split('-')
        if len(parts) != 2:
            continue
        try:
            u1, u2 = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if user_id not in (u1, u2):
            continue
        msg = Message(
            chat_id=chat_id, sender_id=user_id,
            content=original.content, message_type=original.message_type,
            caption=original.caption,
        )
        db.session.add(msg)
        db.session.flush()
        msg_data = {
            'id': msg.id, 'chat_id': chat_id,
            'sender_id': user_id, 'sender_username': sender.username,
            'content': msg.content, 'message_type': msg.message_type,
            'caption': msg.caption, 'is_forwarded': True,
            'created_at': msg.created_at.isoformat(),
            'reply_to': None, 'is_edited': False,
            'is_deleted': False, 'is_pinned': False,
            'read_by': 0, 'reactions': {}, 'user_reactions': []
        }
        socketio.emit('new_message', msg_data, room=chat_id)
        forwarded.append(chat_id)
    try:
        db.session.commit()
        return jsonify({'success': True, 'forwarded_to': forwarded})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages/search/global', methods=['GET'])
@login_required
def global_search():
    user_id = int(session['user_id'])
    q = request.args.get('q', '').strip()
    if not q or len(q) < 2:
        return jsonify({'success': False, 'error': 'Query too short'}), 400
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    chat_ids = [get_chat_id(f.user1_id, f.user2_id) for f in friendships]
    if not chat_ids:
        return jsonify({'success': True, 'results': []})
    msgs = Message.query.filter(
        Message.chat_id.in_(chat_ids),
        Message.content.ilike(f'%{q}%'),
        Message.is_deleted == False,
        Message.message_type == 'text'
    ).order_by(Message.created_at.desc()).limit(50).all()
    results = []
    for m in msgs:
        s = User.query.get(m.sender_id)
        parts = m.chat_id.split('-')
        other_id = int(parts[1]) if int(parts[0]) == user_id else int(parts[0])
        other = User.query.get(other_id)
        results.append({
            'id': m.id, 'chat_id': m.chat_id,
            'content': m.content,
            'sender_username': s.username if s else '?',
            'other_username': other.username if other else '?',
            'other_id': other_id,
            'created_at': m.created_at.isoformat(),
        })
    return jsonify({'success': True, 'results': results})

@app.route('/api/chats/pin', methods=['POST'])
@login_required
def pin_chat():
    user_id = int(session['user_id'])
    data = request.get_json() or {}
    chat_id = data.get('chat_id', '')
    if not chat_id:
        return jsonify({'success': False, 'error': 'No chat_id'}), 400
    existing = PinnedChat.query.filter_by(user_id=user_id, chat_id=chat_id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({'success': True, 'pinned': False})
    pin = PinnedChat(user_id=user_id, chat_id=chat_id)
    db.session.add(pin)
    try:
        db.session.commit()
        return jsonify({'success': True, 'pinned': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/chats/pinned', methods=['GET'])
@login_required
def get_pinned_chats():
    user_id = int(session['user_id'])
    pins = PinnedChat.query.filter_by(user_id=user_id).all()
    return jsonify({'success': True, 'pinned': [p.chat_id for p in pins]})

# ============================================================
# SOCKET.IO EVENTS
# ============================================================
@socketio.on('connect')
def handle_connect():
    """On connect: track user, notify friends, and auto-join all friend chat rooms"""
    if 'user_id' not in session:
        return False

    user_id = session['user_id']
    online_users[user_id] = {
        'sid': request.sid,
        'last_seen': datetime.now(timezone.utc)
    }

    # ── KEY FIX: auto-join every friend's chat room so messages arrive instantly ──
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()

    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        chat_id = get_chat_id(user_id, friend_id)
        join_room(chat_id)  # join all chat rooms on connect

        # Notify online friends that this user came online
        if friend_id in online_users:
            emit('user_online', {'user_id': user_id, 'online': True},
                 room=online_users[friend_id]['sid'])

    print(f"✅ User {user_id} connected and joined {len(friendships)} chat rooms")

@socketio.on('disconnect')
def handle_disconnect():
    """On disconnect: notify friends and clean up"""
    if 'user_id' not in session:
        return

    user_id = session['user_id']

    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()

    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        if friend_id in online_users:
            emit('user_online', {'user_id': user_id, 'online': False},
                 room=online_users[friend_id]['sid'])

    if user_id in online_users:
        del online_users[user_id]

    print(f"❌ User {user_id} disconnected")

@socketio.on('join_chat')
def handle_join_chat(data):
    """Explicitly join a chat room (called when user opens a chat)"""
    chat_id = data.get('chat_id')
    if chat_id:
        join_room(chat_id)
        print(f"User joined chat: {chat_id}")

@socketio.on('send_message')
def handle_send_message(data):
    """Save message and broadcast to ALL users in the chat room instantly"""
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    chat_id = data.get('chat_id')
    content = data.get('content', '').strip()
    message_type = data.get('message_type', 'text')
    reply_to_id = data.get('reply_to_id')
    caption = data.get('caption', '').strip() if message_type == 'image' else None

    if not content or not chat_id:
        return

    parts = chat_id.split('-')
    if len(parts) != 2:
        return

    user1_id, user2_id = int(parts[0]), int(parts[1])
    if user_id not in [user1_id, user2_id]:
        return

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
            reply_to_id=reply_to_id,
            caption=caption
        )
        db.session.add(msg)
        db.session.commit()

        msg_data = format_message(msg, user_id)

        # Broadcast to room — both users auto-joined on connect
        emit('new_message', msg_data, room=chat_id)

    except Exception as e:
        db.session.rollback()
        print(f"Error sending message: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
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
    chat_id = data.get('chatId')
    if chat_id:
        emit('typing_stop', {}, room=chat_id, include_self=False)

# ============================================================
# UTILITY ROUTES
# ============================================================
@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()})

# ============================================================
# ADMIN DASHBOARD — /admin?pw=YOUR_PASSWORD
# ============================================================
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'hepozy2024')

@app.route('/admin')
def admin_dashboard():
    pw = request.args.get('pw', '')
    if pw != ADMIN_PASSWORD:
        return (
            '<!DOCTYPE html><html><head><title>Admin Login</title>'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<style>'
            '*{box-sizing:border-box;margin:0;padding:0;}'
            'body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;'
            'background:#0d0f1a;color:#fff;display:flex;align-items:center;'
            'justify-content:center;min-height:100vh;}'
            '.box{background:#161926;border:1px solid #2a2d3e;border-radius:16px;'
            'padding:36px 32px;width:320px;text-align:center;}'
            'h2{font-size:22px;margin-bottom:6px;}'
            'p{color:#888;font-size:13px;margin-bottom:24px;}'
            'input{width:100%;padding:11px 14px;border-radius:9px;border:1px solid #2a2d3e;'
            'background:#0d0f1a;color:#fff;font-size:14px;margin-bottom:14px;}'
            'button{width:100%;padding:11px;border-radius:9px;border:none;'
            'background:#7c6aff;color:#fff;font-size:14px;font-weight:700;cursor:pointer;}'
            '</style></head><body>'
            '<div class="box">'
            '<h2>🔐 Admin Login</h2>'
            '<p>Hepozy site management</p>'
            '<form method="get">'
            '<input type="password" name="pw" placeholder="Admin password" autofocus>'
            '<button type="submit">Enter</button>'
            '</form></div></body></html>',
            401
        )

    now = datetime.now(timezone.utc)
    total_users    = User.query.count()
    online_now     = len(online_users)
    today_start    = now.replace(hour=0, minute=0, second=0, microsecond=0)
    new_today      = User.query.filter(User.created_at >= today_start).count()
    new_this_week  = User.query.filter(User.created_at >= now - timedelta(days=7)).count()
    new_this_month = User.query.filter(User.created_at >= now - timedelta(days=30)).count()
    total_messages = Message.query.count()
    msgs_today     = Message.query.filter(Message.created_at >= today_start).count()
    total_stories  = Story.query.filter(Story.expires_at > now).count()
    total_friends  = Friendship.query.count()
    pending_reqs   = FriendRequest.query.filter_by(status='pending').count()

    # Growth: new users per day last 14 days
    growth_labels = []
    growth_data = []
    for i in range(13, -1, -1):
        day = now - timedelta(days=i)
        ds = day.replace(hour=0, minute=0, second=0, microsecond=0)
        de = ds + timedelta(days=1)
        cnt = User.query.filter(User.created_at >= ds, User.created_at < de).count()
        growth_labels.append(ds.strftime('%b %d'))
        growth_data.append(cnt)

    # Recent 20 users
    recent_users = User.query.order_by(User.created_at.desc()).limit(20).all()
    rows = ''
    for u in recent_users:
        badge = '<span style="color:#22c55e;">●</span>' if u.id in online_users else '<span style="color:#444;">●</span>'
        joined = u.created_at.strftime('%Y-%m-%d %H:%M') if u.created_at else '—'
        rows += f'<tr><td>{u.id}</td><td>{u.username}</td><td>{badge}</td><td>{joined}</td></tr>'

    html = f'''<!DOCTYPE html>
<html><head>
<title>Hepozy Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d0f1a;color:#e8eaf0;padding:20px 16px;min-height:100vh;}}
h1{{font-size:22px;font-weight:800;margin-bottom:2px;}}
.sub{{color:#666;font-size:13px;margin-bottom:24px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:24px;}}
.card{{background:#161926;border:1px solid #2a2d3e;border-radius:14px;padding:16px 14px;}}
.val{{font-size:30px;font-weight:800;line-height:1;}}
.lbl{{font-size:11px;color:#666;margin-top:5px;text-transform:uppercase;letter-spacing:.4px;}}
.c1{{color:#7c6aff;}}.c2{{color:#22c55e;}}.c3{{color:#f97316;}}.c4{{color:#38bdf8;}}
.box{{background:#161926;border:1px solid #2a2d3e;border-radius:14px;padding:18px;margin-bottom:24px;}}
.box h3{{font-size:12px;font-weight:700;color:#666;text-transform:uppercase;letter-spacing:.5px;margin-bottom:16px;}}
table{{width:100%;border-collapse:collapse;font-size:13px;}}
th{{text-align:left;padding:9px 12px;color:#666;border-bottom:1px solid #2a2d3e;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;}}
td{{padding:9px 12px;border-bottom:1px solid #1a1d27;color:#bbb;}}
tr:last-child td{{border-bottom:none;}}
tr:hover td{{background:#1a1d27;}}
a.btn{{display:inline-flex;align-items:center;gap:6px;background:#7c6aff;color:#fff;border-radius:9px;padding:8px 16px;font-size:13px;font-weight:700;text-decoration:none;margin-bottom:20px;}}
</style>
</head><body>
<h1>📊 Hepozy Admin</h1>
<div class="sub">Real-time site stats &nbsp;·&nbsp; <a href="/admin?pw={pw}" style="color:#7c6aff;">🔄 Refresh</a></div>

<div class="grid">
  <div class="card"><div class="val c1">{total_users}</div><div class="lbl">Total Users</div></div>
  <div class="card"><div class="val c2">{online_now}</div><div class="lbl">Online Now</div></div>
  <div class="card"><div class="val">{new_today}</div><div class="lbl">Joined Today</div></div>
  <div class="card"><div class="val">{new_this_week}</div><div class="lbl">This Week</div></div>
  <div class="card"><div class="val">{new_this_month}</div><div class="lbl">This Month</div></div>
  <div class="card"><div class="val c3">{total_messages}</div><div class="lbl">Total Messages</div></div>
  <div class="card"><div class="val c4">{msgs_today}</div><div class="lbl">Messages Today</div></div>
  <div class="card"><div class="val">{total_stories}</div><div class="lbl">Live Stories</div></div>
  <div class="card"><div class="val">{total_friends}</div><div class="lbl">Friendships</div></div>
  <div class="card"><div class="val">{pending_reqs}</div><div class="lbl">Pending Reqs</div></div>
</div>

<div class="box">
  <h3>📈 New Users — Last 14 Days</h3>
  <canvas id="chart" height="80"></canvas>
</div>

<div class="box">
  <h3>👥 Most Recent Signups</h3>
  <table>
    <thead><tr><th>ID</th><th>Username</th><th>Online</th><th>Joined</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<script>
new Chart(document.getElementById('chart'),{{
  type:'bar',
  data:{{
    labels:{growth_labels},
    datasets:[{{
      label:'New Users',
      data:{growth_data},
      backgroundColor:'rgba(124,106,255,0.75)',
      borderColor:'#7c6aff',
      borderWidth:1,
      borderRadius:5
    }}]
  }},
  options:{{
    plugins:{{legend:{{display:false}}}},
    scales:{{
      x:{{grid:{{color:'#2a2d3e'}},ticks:{{color:'#666',font:{{size:10}}}}}},
      y:{{grid:{{color:'#2a2d3e'}},ticks:{{color:'#666',stepSize:1}},beginAtZero:true}}
    }}
  }}
}});
</script>
</body></html>'''
    return html


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# ============================================================
# WEBRTC SIGNALING EVENTS
# ============================================================

def get_sid(user_id):
    """Get socket ID for a user if they are online. Always uses int key."""
    uid = int(user_id)
    if uid in online_users:
        return online_users[uid]['sid']
    return None

@socketio.on('call_offer')
def handle_call_offer(data):
    """Caller sends SDP offer to receiver."""
    if 'user_id' not in session:
        return
    caller_id = session['user_id']  # always int from session
    try:
        callee_id = int(data.get('callee_id', 0))
    except (ValueError, TypeError):
        emit('call_error', {'message': 'Invalid user'})
        return

    if not callee_id:
        emit('call_error', {'message': 'Invalid user'})
        return

    caller = User.query.get(caller_id)
    if not caller:
        return

    if not are_friends(caller_id, callee_id):
        emit('call_error', {'message': 'Not friends'})
        return

    sid = get_sid(callee_id)
    if sid:
        socketio.emit('incoming_call', {
            'caller_id': caller_id,
            'caller_name': caller.username,
            'caller_avatar': caller.avatar_url or '',
            'offer': data.get('offer'),
            'call_type': data.get('call_type', 'voice')
        }, room=sid)
    else:
        emit('call_error', {'message': 'User is offline'})

@socketio.on('call_answer')
def handle_call_answer(data):
    """Receiver accepts or rejects the call."""
    if 'user_id' not in session:
        return
    callee_id = session['user_id']
    try:
        caller_id = int(data.get('caller_id', 0))
    except (ValueError, TypeError):
        return

    callee = User.query.get(callee_id)
    if not callee:
        return

    accepted = data.get('accepted', False)
    busy = data.get('busy', False)
    sid = get_sid(caller_id)
    if not sid:
        return

    if accepted:
        socketio.emit('call_accepted', {
            'callee_id': callee_id,
            'callee_name': callee.username,
            'answer': data.get('answer')
        }, room=sid)
    else:
        socketio.emit('call_rejected', {
            'callee_id': callee_id,
            'callee_name': callee.username,
            'busy': busy
        }, room=sid)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    """Relay ICE candidate from one peer to the other."""
    if 'user_id' not in session:
        return
    sender_id = session['user_id']
    try:
        target_id = int(data.get('target_id', 0))
    except (ValueError, TypeError):
        return

    sid = get_sid(target_id)
    if sid:
        socketio.emit('ice_candidate', {
            'sender_id': sender_id,
            'candidate': data.get('candidate')
        }, room=sid)

@socketio.on('call_end')
def handle_call_end(data):
    """Notify the other party that the call has ended."""
    if 'user_id' not in session:
        return
    user_id = session['user_id']
    try:
        target_id = int(data.get('target_id', 0))
    except (ValueError, TypeError):
        return
    was_missed = data.get('was_missed', False)

    caller = User.query.get(user_id)
    sid = get_sid(target_id)
    if sid:
        if was_missed:
            # Caller hung up before receiver answered — send missed call notification
            socketio.emit('missed_call_notify', {
                'caller_id': user_id,
                'caller_name': caller.username if caller else 'Someone'
            }, room=sid)
        else:
            socketio.emit('call_ended', {'by_user_id': user_id}, room=sid)

# ============================================================
# READ RECEIPTS
# ============================================================

@socketio.on('mark_read')
def handle_mark_read(data):
    """Mark a single message as read and notify the sender."""
    if 'user_id' not in session:
        return
    reader_id = session['user_id']
    msg_id = data.get('msg_id')
    if not msg_id:
        return
    msg = Message.query.get(msg_id)
    if not msg or msg.sender_id == reader_id:
        return
    # Avoid duplicate read records
    existing = MessageRead.query.filter_by(message_id=msg_id, user_id=reader_id).first()
    if not existing:
        read = MessageRead(message_id=msg_id, user_id=reader_id)
        db.session.add(read)
        db.session.commit()
    # Count reads
    read_count = MessageRead.query.filter_by(message_id=msg_id).count()
    # Notify sender so their dot turns orange
    sender_sid = get_sid(msg.sender_id)
    if sender_sid:
        socketio.emit('receipt_update', {
            'msg_id': msg_id,
            'read_by': read_count
        }, room=sender_sid)

@socketio.on('mark_all_read')
def handle_mark_all_read(data):
    """Mark all unread messages in a chat as read when user opens the chat."""
    if 'user_id' not in session:
        return
    reader_id = session['user_id']
    chat_id = data.get('chat_id')
    if not chat_id:
        return
    # Get all messages in this chat not sent by this user and not yet read
    already_read = db.session.query(MessageRead.message_id).filter_by(user_id=reader_id).subquery()
    unread = Message.query.filter(
        Message.chat_id == chat_id,
        Message.sender_id != reader_id,
        ~Message.id.in_(already_read)
    ).all()
    if not unread:
        return
    sender_ids = set()
    for msg in unread:
        read = MessageRead(message_id=msg.id, user_id=reader_id)
        db.session.add(read)
        sender_ids.add(msg.sender_id)
    db.session.commit()
    # Notify each sender that their messages were seen
    for sid_user in sender_ids:
        sender_sid = get_sid(sid_user)
        if sender_sid:
            # Send update for each message
            for msg in unread:
                if msg.sender_id == sid_user:
                    read_count = MessageRead.query.filter_by(message_id=msg.id).count()
                    socketio.emit('receipt_update', {
                        'msg_id': msg.id,
                        'read_by': read_count
                    }, room=sender_sid)

# ============================================================
# RUN SERVER
# ============================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
