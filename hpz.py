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

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'hpz-secret-2025')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = bool(os.environ.get('RENDER'))
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

database_url = os.environ.get('DATABASE_URL', '')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 300}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# Online users: {user_id(int): {'sid': str, 'last_seen': datetime}}
online_users = {}


# ── Models ─────────────────────────────────────────────
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

    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)
    def to_dict(self):
        return {'id':self.id,'username':self.username,'avatar_url':self.avatar_url,
                'bio':self.bio,'status':self.status,'relationship_status':self.relationship_status}

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


with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created")
    except Exception as e:
        print(f"❌ DB error: {e}")


# ── Helpers ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_chat_id(a, b):
    return f"{min(a,b)}-{max(a,b)}"

def are_friends(a, b):
    return Friendship.query.filter(
        or_(and_(Friendship.user1_id==a, Friendship.user2_id==b),
            and_(Friendship.user1_id==b, Friendship.user2_id==a))
    ).first() is not None

def is_blocked(a, b):
    return BlockedUser.query.filter(
        or_(and_(BlockedUser.blocker_id==a, BlockedUser.blocked_id==b),
            and_(BlockedUser.blocker_id==b, BlockedUser.blocked_id==a))
    ).first() is not None

def is_online(user_id):
    uid = int(user_id)
    if uid in online_users:
        ls = online_users[uid].get('last_seen')
        if ls and (datetime.now(timezone.utc)-ls).seconds < 30:
            return True
    return False

def get_sid(user_id):
    """Get socket SID for a user. Always coerces to int."""
    uid = int(user_id)
    return online_users[uid]['sid'] if uid in online_users else None

def get_time_ago(dt):
    if not dt: return 'Never'
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    s = (datetime.now(timezone.utc)-dt).total_seconds()
    if s < 60: return 'Just now'
    if s < 3600: return f'{int(s/60)}m ago'
    if s < 86400: return f'{int(s/3600)}h ago'
    return f'{int(s/86400)}d ago'

def format_message(msg, user_id):
    reactions = MessageReaction.query.filter_by(message_id=msg.id).all()
    reads = MessageRead.query.filter_by(message_id=msg.id).all()
    rc = {}
    ur = []
    for r in reactions:
        rc[r.emoji] = rc.get(r.emoji, 0) + 1
        if r.user_id == user_id: ur.append(r.emoji)
    reply_msg = None
    if msg.reply_to_id:
        rep = db.session.get(Message, msg.reply_to_id)
        if rep and not rep.is_deleted:
            reply_msg = {
                'id': rep.id,
                'sender_username': rep.sender.username if rep.sender else 'Unknown',
                'content': rep.content[:50] + ('...' if len(rep.content)>50 else '')
            }
    return {
        'id': msg.id, 'chat_id': msg.chat_id,
        'sender_id': msg.sender_id,
        'sender_username': msg.sender.username if msg.sender else 'Unknown',
        'content': msg.content if not msg.is_deleted else '[Message deleted]',
        'message_type': msg.message_type,
        'is_edited': msg.is_edited, 'is_deleted': msg.is_deleted, 'is_pinned': msg.is_pinned,
        'created_at': msg.created_at.isoformat(),
        'edited_at': msg.edited_at.isoformat() if msg.edited_at else None,
        'reactions': rc, 'user_reactions': ur,
        'read_by': len(reads), 'reply_to': reply_msg,
        'caption': msg.caption or ''
    }


# ── Error handlers ──────────────────────────────────────
@app.errorhandler(404)
def not_found(e): return jsonify({'success':False,'error':'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return jsonify({'success':False,'error':'Server error'}), 500


# ── Page routes ─────────────────────────────────────────
@app.route('/')
def index(): return render_template('login.html')

@app.route('/register')
def register_page(): return render_template('register.html')

@app.route('/chat')
@login_required
def chat():
    user = db.session.get(User, session['user_id'])
    if not user: return redirect('/')
    return render_template('chat.html', user=user, user_id=user.id)

@app.route('/logo')
def serve_logo():
    p = os.path.join(BASE_DIR, 'static', 'logo.png')
    if os.path.exists(p): return send_from_directory(os.path.join(BASE_DIR,'static'), 'logo.png')
    return '', 404


# ── Auth ────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username','').strip()
    password = data.get('password','').strip()
    if not username or not password:
        return jsonify({'success':False,'error':'Username and password required'}), 400
    if len(username) < 3:
        return jsonify({'success':False,'error':'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'success':False,'error':'Password must be at least 6 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'success':False,'error':'Username already taken'}), 409
    try:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        session.permanent = True
        return jsonify({'success':True,'user':user.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username','').strip()).first()
    if not user or not user.check_password(data.get('password','').strip()):
        return jsonify({'success':False,'error':'Invalid username or password'}), 401
    session['user_id'] = user.id
    session.permanent = True
    return jsonify({'success':True,'user':user.to_dict()})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    if uid and int(uid) in online_users:
        del online_users[int(uid)]
    session.clear()
    return jsonify({'success':True})


# ── Users ───────────────────────────────────────────────
@app.route('/api/users/search')
@login_required
def search_users():
    q = request.args.get('q','').strip()
    uid = session['user_id']
    if not q: return jsonify({'success':False,'error':'Query required'}), 400
    users = User.query.filter(User.username.ilike(f'%{q}%'), User.id!=uid).limit(10).all()
    results = []
    for u in users:
        if is_blocked(uid, u.id): continue
        rel = 'none'
        if are_friends(uid, u.id): rel = 'friend'
        elif FriendRequest.query.filter_by(from_user_id=uid, to_user_id=u.id, status='pending').first(): rel = 'request_sent'
        elif FriendRequest.query.filter_by(from_user_id=u.id, to_user_id=uid, status='pending').first(): rel = 'request_received'
        results.append({**u.to_dict(), 'relationship':rel, 'is_online':is_online(u.id)})
    return jsonify({'success':True,'results':results})

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    user = db.session.get(User, session['user_id'])
    if not user: return jsonify({'success':False,'error':'Not found'}), 404
    return jsonify({'success':True,'user':user.to_dict()})

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    user = db.session.get(User, session['user_id'])
    if not user: return jsonify({'success':False,'error':'Not found'}), 404
    data = request.get_json()
    if 'username' in data and data['username'].strip():
        nu = data['username'].strip()
        if nu != user.username:
            if User.query.filter_by(username=nu).first():
                return jsonify({'success':False,'error':'Username taken'}), 409
            user.username = nu
    if 'status' in data: user.status = data['status'][:100]
    if 'bio' in data: user.bio = data['bio'][:500]
    if 'relationship_status' in data: user.relationship_status = data['relationship_status']
    try:
        db.session.commit()
        return jsonify({'success':True,'user':user.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files: return jsonify({'success':False,'error':'No file'}), 400
    file = request.files['avatar']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success':False,'error':'Invalid file'}), 400
    try:
        ext = file.filename.rsplit('.',1)[1].lower()
        fn = f"avatar_{session['user_id']}_{uuid.uuid4().hex[:8]}.{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
        user = db.session.get(User, session['user_id'])
        user.avatar_url = f'/static/uploads/{fn}'
        db.session.commit()
        return jsonify({'success':True,'avatar_url':user.avatar_url})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500


# ── Friends ─────────────────────────────────────────────
@app.route('/api/friends')
@login_required
def get_friends():
    uid = session['user_id']
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id==uid, Friendship.user2_id==uid)
    ).all()
    friends = []
    for f in friendships:
        fid = f.user2_id if f.user1_id==uid else f.user1_id
        friend = db.session.get(User, fid)
        if not friend: continue
        cid = get_chat_id(uid, fid)
        last_msg = Message.query.filter_by(chat_id=cid).order_by(Message.created_at.desc()).first()
        unread = 0
        if last_msg:
            unread = Message.query.filter(
                Message.chat_id==cid, Message.sender_id==fid,
                ~Message.id.in_(db.session.query(MessageRead.message_id).filter_by(user_id=uid))
            ).count()
        friends.append({
            **friend.to_dict(), 'chat_id':cid, 'is_online':is_online(fid),
            'last_message': ('📷 Photo' if last_msg and last_msg.message_type=='image' else (last_msg.content[:50] if last_msg else None)),
            'last_message_time':last_msg.created_at.isoformat() if last_msg else None,
            'unread_count':unread
        })
    friends.sort(key=lambda x: x['last_message_time'] or '', reverse=True)
    return jsonify({'success':True,'friends':friends})

@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    uid = session['user_id']
    received = FriendRequest.query.filter_by(to_user_id=uid, status='pending').all()
    lst = []
    for req in received:
        user = db.session.get(User, req.from_user_id)
        if user:
            lst.append({'request_id':req.id,'user_id':user.id,'username':user.username,
                        'avatar_url':user.avatar_url,'time_ago':get_time_ago(req.created_at)})
    return jsonify({'success':True,'received':lst})

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    data = request.get_json()
    from_id = session['user_id']
    to_id = data.get('to_user_id')
    if from_id == to_id: return jsonify({'success':False,'error':'Cannot add yourself'}), 400
    if are_friends(from_id, to_id): return jsonify({'success':False,'error':'Already friends'}), 400
    if FriendRequest.query.filter_by(from_user_id=from_id, to_user_id=to_id, status='pending').first():
        return jsonify({'success':False,'error':'Request already sent'}), 400
    try:
        db.session.add(FriendRequest(from_user_id=from_id, to_user_id=to_id))
        db.session.commit()
        # Notify target in real time if online
        sender = db.session.get(User, from_id)
        sid = get_sid(to_id)
        if sid and sender:
            socketio.emit('new_friend_request', {
                'from_user_id': from_id,
                'username': sender.username,
                'avatar_url': sender.avatar_url or ''
            }, room=sid)
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    data = request.get_json()
    uid = session['user_id']
    req = db.session.get(FriendRequest, data.get('request_id'))
    if not req or req.to_user_id != uid: return jsonify({'success':False,'error':'Not found'}), 404
    try:
        db.session.add(Friendship(user1_id=req.from_user_id, user2_id=req.to_user_id))
        req.status = 'accepted'
        db.session.commit()
        # Notify requester in real time so their friend list updates instantly
        accepter = db.session.get(User, uid)
        requester_sid = get_sid(req.from_user_id)
        if requester_sid and accepter:
            socketio.emit('friend_request_accepted', {
                'user_id': uid,
                'username': accepter.username,
                'avatar_url': accepter.avatar_url or ''
            }, room=requester_sid)
        # Both users join the shared chat room so messages arrive without refresh
        chat_id = get_chat_id(uid, req.from_user_id)
        my_sid = get_sid(uid)
        if my_sid:
            socketio.server.enter_room(my_sid, chat_id)
        if requester_sid:
            socketio.server.enter_room(requester_sid, chat_id)
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend_request():
    data = request.get_json()
    uid = session['user_id']
    req = db.session.get(FriendRequest, data.get('request_id'))
    if not req or req.to_user_id != uid: return jsonify({'success':False,'error':'Not found'}), 404
    try:
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500


# ── Messages ────────────────────────────────────────────
@app.route('/api/messages/<chat_id>')
@login_required
def get_messages(chat_id):
    uid = session['user_id']
    parts = chat_id.split('-')
    if len(parts) != 2: return jsonify({'success':False,'error':'Invalid chat ID'}), 400
    u1, u2 = int(parts[0]), int(parts[1])
    if uid not in [u1, u2]: return jsonify({'success':False,'error':'Unauthorized'}), 403
    msgs = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at).all()
    return jsonify({'success':True,'messages':[format_message(m, uid) for m in msgs]})

@app.route('/api/messages/search/<chat_id>')
@login_required
def search_messages(chat_id):
    q = request.args.get('q','').strip()
    uid = session['user_id']
    if not q: return jsonify({'success':False,'error':'Query required'}), 400
    parts = chat_id.split('-')
    if len(parts) != 2: return jsonify({'success':False,'error':'Invalid chat ID'}), 400
    u1, u2 = int(parts[0]), int(parts[1])
    if uid not in [u1, u2]: return jsonify({'success':False,'error':'Unauthorized'}), 403
    msgs = Message.query.filter(
        Message.chat_id==chat_id, Message.content.ilike(f'%{q}%'), Message.is_deleted==False
    ).order_by(Message.created_at.desc()).limit(50).all()
    return jsonify({'success':True,'messages':[format_message(m, uid) for m in msgs]})

@app.route('/api/messages/pinned/<chat_id>')
@login_required
def get_pinned(chat_id):
    uid = session['user_id']
    parts = chat_id.split('-')
    if len(parts) != 2: return jsonify({'success':False,'error':'Invalid chat ID'}), 400
    u1, u2 = int(parts[0]), int(parts[1])
    if uid not in [u1, u2]: return jsonify({'success':False,'error':'Unauthorized'}), 403
    msgs = Message.query.filter_by(chat_id=chat_id, is_pinned=True).all()
    return jsonify({'success':True,'messages':[format_message(m, uid) for m in msgs]})

@app.route('/api/messages/<int:mid>/edit', methods=['PUT'])
@login_required
def edit_message(mid):
    uid = session['user_id']
    data = request.get_json()
    content = data.get('content','').strip()
    if not content: return jsonify({'success':False,'error':'Content required'}), 400
    msg = db.session.get(Message, mid)
    if not msg or msg.sender_id != uid: return jsonify({'success':False,'error':'Not found'}), 404
    if msg.is_deleted: return jsonify({'success':False,'error':'Cannot edit deleted'}), 400
    try:
        msg.content = content; msg.is_edited = True; msg.edited_at = datetime.now(timezone.utc)
        db.session.commit()
        socketio.emit('message_edited', format_message(msg, uid), room=msg.chat_id)
        return jsonify({'success':True,'message':format_message(msg, uid)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/messages/<int:mid>/delete', methods=['DELETE'])
@login_required
def delete_message(mid):
    uid = session['user_id']
    msg = db.session.get(Message, mid)
    if not msg or msg.sender_id != uid: return jsonify({'success':False,'error':'Not found'}), 404
    try:
        msg.is_deleted = True; msg.content = '[Message deleted]'
        db.session.commit()
        socketio.emit('message_deleted', {'id':msg.id,'chat_id':msg.chat_id}, room=msg.chat_id)
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/messages/<int:mid>/pin', methods=['POST'])
@login_required
def pin_message(mid):
    uid = session['user_id']
    msg = db.session.get(Message, mid)
    if not msg: return jsonify({'success':False,'error':'Not found'}), 404
    parts = msg.chat_id.split('-')
    if uid not in [int(parts[0]), int(parts[1])]: return jsonify({'success':False,'error':'Unauthorized'}), 403
    try:
        msg.is_pinned = not msg.is_pinned
        db.session.commit()
        socketio.emit('message_pinned', {'id':msg.id,'chat_id':msg.chat_id,'is_pinned':msg.is_pinned}, room=msg.chat_id)
        return jsonify({'success':True,'is_pinned':msg.is_pinned,'message':format_message(msg, uid)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/messages/<int:mid>/react', methods=['POST'])
@login_required
def react(mid):
    uid = session['user_id']
    emoji = request.get_json().get('emoji','').strip()
    if not emoji: return jsonify({'success':False,'error':'Emoji required'}), 400
    msg = db.session.get(Message, mid)
    if not msg: return jsonify({'success':False,'error':'Not found'}), 404
    try:
        ex = MessageReaction.query.filter_by(message_id=mid, user_id=uid, emoji=emoji).first()
        if ex: db.session.delete(ex)
        else: db.session.add(MessageReaction(message_id=mid, user_id=uid, emoji=emoji))
        db.session.commit()
        socketio.emit('message_reaction', {'message':format_message(msg, uid),'chat_id':msg.chat_id}, room=msg.chat_id)
        return jsonify({'success':True,'message':format_message(msg, uid)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500


# ── Blocklist ───────────────────────────────────────────
@app.route('/api/blocklist')
@login_required
def get_blocklist():
    uid = session['user_id']
    blocked = BlockedUser.query.filter_by(blocker_id=uid).all()
    lst = []
    for b in blocked:
        u = db.session.get(User, b.blocked_id)
        if u: lst.append({'id':u.id,'username':u.username,'avatar_url':u.avatar_url,'blocked_at':b.created_at.isoformat()})
    return jsonify({'success':True,'blocked_users':lst})

@app.route('/api/blocklist/add', methods=['POST'])
@login_required
def block_user():
    uid = session['user_id']
    bid = request.get_json().get('user_id')
    if uid == bid: return jsonify({'success':False,'error':'Cannot block yourself'}), 400
    if BlockedUser.query.filter_by(blocker_id=uid, blocked_id=bid).first():
        return jsonify({'success':False,'error':'Already blocked'}), 400
    try:
        db.session.add(BlockedUser(blocker_id=uid, blocked_id=bid))
        # Also remove the friendship so they disappear from friend lists on both sides
        friendship = Friendship.query.filter(
            or_(and_(Friendship.user1_id==uid, Friendship.user2_id==bid),
                and_(Friendship.user1_id==bid, Friendship.user2_id==uid))
        ).first()
        if friendship:
            db.session.delete(friendship)
        db.session.commit()
        # Notify the blocked user's socket to reload (they lose friend too)
        their_sid = get_sid(bid)
        if their_sid:
            socketio.emit('friend_removed', {'user_id': uid}, room=their_sid)
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/blocklist/remove', methods=['POST'])
@login_required
def unblock_user():
    uid = session['user_id']
    bid = request.get_json().get('user_id')
    b = BlockedUser.query.filter_by(blocker_id=uid, blocked_id=bid).first()
    if not b: return jsonify({'success':False,'error':'Not blocked'}), 404
    try:
        db.session.delete(b); db.session.commit()
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500


# ── Stories ─────────────────────────────────────────────
@app.route('/api/stories/create', methods=['POST'])
@login_required
def create_story():
    uid = session['user_id']
    data = request.get_json()
    content = data.get('content','')
    media_url = data.get('media_url','')
    if not content and not media_url:
        return jsonify({'success':False,'error':'Content or media required'}), 400
    try:
        story = Story(user_id=uid, content=content, media_url=media_url,
                      media_type=data.get('media_type','text'), privacy=data.get('privacy','friends'),
                      expires_at=datetime.now(timezone.utc)+timedelta(hours=24))
        db.session.add(story); db.session.flush()
        if data.get('privacy')=='custom':
            for auid in data.get('custom_users',[]):
                db.session.add(StoryPrivacy(story_id=story.id, allowed_user_id=auid))
        db.session.commit()
        return jsonify({'success':True,'story_id':story.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/stories/friends')
@login_required
def get_friends_stories():
    uid = session['user_id']
    now = datetime.now(timezone.utc)
    # Clean up expired stories (older than 24h)
    try:
        expired = Story.query.filter(Story.expires_at < now).all()
        for s in expired:
            StoryView.query.filter_by(story_id=s.id).delete()
            StoryPrivacy.query.filter_by(story_id=s.id).delete()
            db.session.delete(s)
        if expired:
            db.session.commit()
    except Exception:
        db.session.rollback()
    fs = Friendship.query.filter(or_(Friendship.user1_id==uid, Friendship.user2_id==uid)).all()
    fids = [f.user2_id if f.user1_id==uid else f.user1_id for f in fs]
    fids.append(uid)
    result = {}
    for fid in fids:
        stories = Story.query.filter(Story.user_id==fid, Story.expires_at>now).order_by(Story.created_at.desc()).all()
        visible = []
        for s in stories:
            if s.user_id==uid: visible.append(s); continue
            if s.privacy in ('public','friends'): visible.append(s)
            elif s.privacy=='custom' and StoryPrivacy.query.filter_by(story_id=s.id, allowed_user_id=uid).first():
                visible.append(s)
        if visible:
            user = db.session.get(User, fid)
            unviewed = any(not StoryView.query.filter_by(story_id=s.id, viewer_id=uid).first() for s in visible)
            result[fid] = {
                'user_id':fid,'username':user.username,'avatar_url':user.avatar_url,'has_unviewed':unviewed,
                'stories':[{'id':s.id,'content':s.content,'media_url':s.media_url,'media_type':s.media_type,
                            'created_at':s.created_at.isoformat(),'expires_at':s.expires_at.isoformat(),
                            'is_own':s.user_id==uid,'username':user.username} for s in visible]
            }
    return jsonify({'success':True,'stories':list(result.values())})

@app.route('/api/stories/<int:sid>/view', methods=['POST'])
@login_required
def view_story(sid):
    uid = session['user_id']
    story = db.session.get(Story, sid)
    if not story: return jsonify({'success':False,'error':'Not found'}), 404
    if story.user_id == uid: return jsonify({'success':True})
    if StoryView.query.filter_by(story_id=sid, viewer_id=uid).first(): return jsonify({'success':True})
    try:
        db.session.add(StoryView(story_id=sid, viewer_id=uid)); db.session.commit()
        return jsonify({'success':True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/stories/<int:sid>/viewers')
@login_required
def story_viewers(sid):
    uid = session['user_id']
    story = db.session.get(Story, sid)
    if not story or story.user_id!=uid: return jsonify({'success':False,'error':'Not found'}), 404
    views = StoryView.query.filter_by(story_id=sid).all()
    viewers = []
    for v in views:
        u = db.session.get(User, v.viewer_id)
        if u: viewers.append({'user_id':u.id,'username':u.username,'viewed_at':v.viewed_at.isoformat()})
    return jsonify({'success':True,'count':len(viewers),'viewers':viewers})


# ── File upload ─────────────────────────────────────────
@app.route('/api/upload/image', methods=['POST'])
@login_required
def upload_image():
    if 'image' not in request.files: return jsonify({'success':False,'error':'No file'}), 400
    file = request.files['image']
    if file.filename == '': file.filename = 'photo.jpg'
    # Determine extension — blobs from canvas.toBlob() may come as 'photo.jpg' or have no ext
    fname = file.filename or 'photo.jpg'
    ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else 'jpg'
    if ext not in ALLOWED_EXTENSIONS: ext = 'jpg'
    try:
        fn = f"img_{uuid.uuid4().hex}.{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
        return jsonify({'success':True,'url':f'/static/uploads/{fn}'})
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500


# ── Socket.IO events ────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session: return False
    uid = int(session['user_id'])
    online_users[uid] = {'sid': request.sid, 'last_seen': datetime.now(timezone.utc)}

    # Auto-join all friend chat rooms and broadcast online status
    try:
        fs = Friendship.query.filter(or_(Friendship.user1_id==uid, Friendship.user2_id==uid)).all()
        online_friend_ids = []
        for f in fs:
            fid = f.user2_id if f.user1_id==uid else f.user1_id
            join_room(get_chat_id(uid, fid))
            # Tell each online friend that this user is now online
            if fid in online_users:
                socketio.emit('user_online', {'user_id':uid,'online':True}, room=online_users[fid]['sid'])
                online_friend_ids.append(fid)
        # Tell this user which of their friends are currently online
        for fid in online_friend_ids:
            emit('user_online', {'user_id':fid,'online':True})
    except Exception:
        pass

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' not in session: return
    uid = int(session['user_id'])
    try:
        fs = Friendship.query.filter(or_(Friendship.user1_id==uid, Friendship.user2_id==uid)).all()
        for f in fs:
            fid = f.user2_id if f.user1_id==uid else f.user1_id
            if fid in online_users:
                socketio.emit('user_online', {'user_id':uid,'online':False}, room=online_users[fid]['sid'])
    except Exception: pass
    finally:
        online_users.pop(uid, None)

@socketio.on('join_chat')
def handle_join_chat(data):
    cid = data.get('chat_id')
    if cid: join_room(cid)

@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session: return
    uid = int(session['user_id'])
    cid = data.get('chat_id')
    content = data.get('content','').strip()
    mtype = data.get('message_type','text')
    if not content or not cid: return
    parts = cid.split('-')
    if len(parts) != 2: return
    u1, u2 = int(parts[0]), int(parts[1])
    if uid not in [u1, u2]: return
    other = u2 if uid==u1 else u1
    if is_blocked(uid, other):
        emit('error', {'message':'Cannot message blocked user'}); return
    try:
        msg = Message(chat_id=cid, sender_id=uid, content=content, message_type=mtype,
                      reply_to_id=data.get('reply_to_id'),
                      caption=data.get('caption','').strip() if mtype=='image' else None)
        db.session.add(msg); db.session.commit()
        emit('new_message', format_message(msg, uid), room=cid)
    except Exception as e:
        db.session.rollback()

@socketio.on('typing_start')
def on_typing_start(data):
    if 'user_id' not in session: return
    user = db.session.get(User, session['user_id'])
    cid = data.get('chatId')
    if cid and user: emit('typing_start', {'username':user.username}, room=cid, include_self=False)

@socketio.on('typing_stop')
def on_typing_stop(data):
    cid = data.get('chatId')
    if cid: emit('typing_stop', {}, room=cid, include_self=False)


# ── Read receipts ───────────────────────────────────────
@socketio.on('mark_read')
def on_mark_read(data):
    if 'user_id' not in session: return
    uid = int(session['user_id'])
    mid = data.get('msg_id')
    if not mid: return
    msg = db.session.get(Message, mid)
    if not msg or msg.sender_id == uid: return
    if not MessageRead.query.filter_by(message_id=mid, user_id=uid).first():
        db.session.add(MessageRead(message_id=mid, user_id=uid))
        db.session.commit()
    rc = MessageRead.query.filter_by(message_id=mid).count()
    sid = get_sid(msg.sender_id)
    if sid: socketio.emit('receipt_update', {'msg_id':mid,'read_by':rc}, room=sid)

@socketio.on('mark_all_read')
def on_mark_all_read(data):
    if 'user_id' not in session: return
    uid = int(session['user_id'])
    cid = data.get('chat_id')
    if not cid: return
    try:
        already = db.session.query(MessageRead.message_id).filter_by(user_id=uid).subquery()
        unread = Message.query.filter(
            Message.chat_id==cid, Message.sender_id!=uid, ~Message.id.in_(already)
        ).all()
        if not unread: return
        sids_to_notify = set()
        for msg in unread:
            try:
                db.session.add(MessageRead(message_id=msg.id, user_id=uid))
                sids_to_notify.add(msg.sender_id)
            except Exception: pass
        db.session.commit()
        for sender_id in sids_to_notify:
            ssid = get_sid(sender_id)
            if ssid:
                for msg in unread:
                    if msg.sender_id == sender_id:
                        rc = MessageRead.query.filter_by(message_id=msg.id).count()
                        socketio.emit('receipt_update', {'msg_id':msg.id,'read_by':rc}, room=ssid)
    except Exception as e:
        db.session.rollback()


# ── WebRTC signaling ─────────────────────────────────────
@socketio.on('call_offer')
def on_call_offer(data):
    """Caller → Callee: send SDP offer."""
    if 'user_id' not in session: return
    caller_id = int(session['user_id'])
    callee_id = int(data.get('callee_id', 0))
    if not callee_id: return

    caller = db.session.get(User, caller_id)
    if not caller: return
    if not are_friends(caller_id, callee_id):
        emit('call_error', {'message': 'Not friends'}); return

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
def on_call_answer(data):
    """
    Callee → Caller: accept or reject.
    Payload: { caller_id, accepted, answer?, busy?, busy_name? }
    """
    if 'user_id' not in session: return
    callee_id = int(session['user_id'])
    caller_id = int(data.get('caller_id', 0))
    if not caller_id: return

    callee = db.session.get(User, callee_id)
    if not callee: return

    sid = get_sid(caller_id)
    if not sid: return

    if data.get('accepted'):
        socketio.emit('call_accepted', {
            'callee_id': callee_id,
            'callee_name': callee.username,
            'answer': data.get('answer')
        }, room=sid)
    else:
        # Pass callee name so the caller sees e.g. "Alice declined the call"
        # or "Alice is in another call"
        socketio.emit('call_rejected', {
            'callee_id': callee_id,
            'callee_name': callee.username,
            'busy': bool(data.get('busy', False)),
            'busy_name': callee.username   # frontend uses this for the "X is in another call" message
        }, room=sid)


@socketio.on('ice_candidate')
def on_ice_candidate(data):
    """Relay ICE candidate between peers."""
    if 'user_id' not in session: return
    sender_id = int(session['user_id'])
    target_id = int(data.get('target_id', 0))
    sid = get_sid(target_id)
    if sid:
        socketio.emit('ice_candidate', {
            'sender_id': sender_id,
            'candidate': data.get('candidate')
        }, room=sid)


@socketio.on('call_end')
def on_call_end(data):
    """Notify the other party that the call is over."""
    if 'user_id' not in session: return
    uid = int(session['user_id'])
    target_id = int(data.get('target_id', 0))
    sid = get_sid(target_id)
    if sid:
        socketio.emit('call_ended', {'by_user_id': uid}, room=sid)
    # If the call was never answered, send a missed call notification
    if data.get('was_missed') and sid:
        caller = db.session.get(User, uid)
        socketio.emit('missed_call_notify', {
            'caller_id': uid,
            'caller_name': caller.username if caller else 'Someone',
            'call_type': data.get('call_type', 'voice')
        }, room=sid)


# ── Health ──────────────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({'status':'healthy','timestamp':datetime.now(timezone.utc).isoformat()})

@app.teardown_appcontext
def shutdown_session(exc=None):
    db.session.remove()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
