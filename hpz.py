import os
import uuid
from flask import Flask, render_template, request, jsonify, session, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
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
# UPLOADS
# ============================================================
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ============================================================
# EXTENSIONS
# ============================================================
db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# logger=False prevents Render startup timeout
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=False,
    engineio_logger=False
)

# ============================================================
# MODELS
# ============================================================
class User(db.Model):
    __tablename__ = 'users'
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    password_hash= db.Column(db.String(200), nullable=False)
    avatar_url   = db.Column(db.String(500))
    bio          = db.Column(db.String(500), default='')
    status       = db.Column(db.String(100), default='Available')
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, p):   self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)
    def to_dict(self):
        return {'id': self.id, 'username': self.username,
                'avatar_url': self.avatar_url, 'bio': self.bio, 'status': self.status}


class Message(db.Model):
    __tablename__ = 'messages'
    id           = db.Column(db.Integer, primary_key=True)
    chat_id      = db.Column(db.String(100), nullable=False, index=True)
    sender_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content      = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender       = db.relationship('User', foreign_keys=[sender_id])


class Friendship(db.Model):
    __tablename__ = 'friendships'
    id       = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id'),)


class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id           = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    to_user_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    status       = db.Column(db.String(20), default='pending')
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


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
    if s < 60:    return 'Just now'
    if s < 3600:  return f'{int(s/60)}m ago'
    if s < 86400: return f'{int(s/3600)}h ago'
    return f'{int(s/86400)}d ago'

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

# ============================================================
# AUTH
# ============================================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data     = request.get_json()
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
        session['user_id']  = user.id
        session['username'] = user.username
        session.modified    = True

        print(f"✅ Registered: {username} (ID:{user.id})")
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Register error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data       = request.get_json()
        identifier = data.get('identifier', '').strip()
        password   = data.get('password', '')

        if not identifier or not password:
            return jsonify({'success': False, 'error': 'All fields required'}), 400

        user = User.query.filter_by(username=identifier).first()
        if not user or not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        session.permanent = True
        session['user_id']  = user.id
        session['username'] = user.username
        session.modified    = True

        print(f"✅ Login: {user.username} (ID:{user.id})")
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# ============================================================
# SEARCH
# ============================================================
@app.route('/api/users/search')
@login_required
def search_users():
    try:
        query = request.args.get('q', '').strip()
        uid   = session['user_id']

        if not query:
            return jsonify({'success': True, 'results': [], 'count': 0})

        users = User.query.filter(
            User.id != uid,
            User.username.ilike(f'%{query}%')
        ).limit(20).all()

        results = []
        for u in users:
            is_friend = are_friends(uid, u.id)
            req_sent  = FriendRequest.query.filter_by(from_user_id=uid, to_user_id=u.id, status='pending').first() is not None
            req_recv  = FriendRequest.query.filter_by(from_user_id=u.id, to_user_id=uid, status='pending').first() is not None

            if is_friend:   rel = 'friend'
            elif req_sent:  rel = 'request_sent'
            elif req_recv:  rel = 'request_received'
            else:           rel = 'none'

            results.append({
                'id': u.id, 'username': u.username,
                'avatar': u.avatar_url or f"https://ui-avatars.com/api/?name={u.username}&background=6c63ff&color=fff&size=128",
                'status': u.status or 'Available',
                'is_friend': is_friend, 'relationship': rel,
                'request_sent': req_sent, 'request_received': req_recv
            })

        return jsonify({'success': True, 'results': results, 'count': len(results)})
    except Exception as e:
        print(f"❌ Search error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# PROFILE
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

        if 'bio'    in data: user.bio    = data['bio'][:500]
        if 'status' in data: user.status = data['status'][:100]

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
        fn  = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(UPLOAD_FOLDER, 'avatars')
        os.makedirs(path, exist_ok=True)
        file.save(os.path.join(path, fn))

        url  = f"/static/uploads/avatars/{fn}"
        user = User.query.get(session['user_id'])
        user.avatar_url = url
        db.session.commit()
        return jsonify({'success': True, 'url': url})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# FRIENDS
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
            fid    = f.user2_id if f.user1_id == uid else f.user1_id
            friend = User.query.get(fid)
            if not friend: continue

            cid  = get_chat_id(uid, fid)
            last = Message.query.filter_by(chat_id=cid).order_by(Message.created_at.desc()).first()
            av   = friend.avatar_url or f"https://ui-avatars.com/api/?name={friend.username}&background=6c63ff&color=fff&size=96"

            friends.append({
                'id': friend.id, 'username': friend.username,
                'avatar': av, 'avatar_url': av,
                'status': friend.status or 'Available',
                'chat_id': cid,
                'last_message': last.content[:40] if last else None,
                'last_message_time': last.created_at.isoformat() if last else None
            })

        return jsonify({'success': True, 'friends': friends})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    try:
        uid      = session['user_id']
        received = FriendRequest.query.filter_by(to_user_id=uid,   status='pending').order_by(FriendRequest.created_at.desc()).all()
        sent     = FriendRequest.query.filter_by(from_user_id=uid, status='pending').all()

        def fmt(req, tid):
            u  = User.query.get(tid)
            av = u.avatar_url or f"https://ui-avatars.com/api/?name={u.username}&background=6c63ff&color=fff"
            return {'request_id': req.id, 'user_id': u.id, 'username': u.username,
                    'avatar': av, 'time_ago': get_time_ago(req.created_at)}

        return jsonify({
            'success': True,
            'received': [fmt(r, r.from_user_id) for r in received],
            'sent':     [fmt(r, r.to_user_id)   for r in sent]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    try:
        data  = request.get_json()
        uid   = session['user_id']
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
# MESSAGES
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

        return jsonify({'success': True, 'messages': [{
            'id': m.id, 'chat_id': m.chat_id, 'sender_id': m.sender_id,
            'sender_username': m.sender.username if m.sender else 'Unknown',
            'content': m.content, 'message_type': m.message_type,
            'created_at': m.created_at.isoformat()
        } for m in msgs]})
    except Exception as e:
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
        if not file or not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file'}), 400

        ext = file.filename.rsplit('.', 1)[1].lower()
        fn  = f"{uuid.uuid4().hex}.{ext}"
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        file.save(os.path.join(UPLOAD_FOLDER, fn))
        return jsonify({'success': True, 'url': f"/static/uploads/{fn}"})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# SOCKET.IO
# ============================================================
@socketio.on('connect')
def handle_connect():
    uid   = session.get('user_id')
    uname = session.get('username')
    print(f"🔌 {uname} (ID:{uid}) SID:{request.sid}")
    if not uid: return False
    join_room(f'user_{uid}')
    join_room('global')
    return True


@socketio.on('join_chat')
def handle_join_chat(data):
    cid = data.get('chat_id')
    uid = session.get('user_id')
    if cid and uid: join_room(cid)


@socketio.on('send_message')
def handle_send_message(data):
    uid   = session.get('user_id')
    uname = session.get('username')

    if not uid:
        emit('error', {'message': 'Not authenticated'})
        return

    # Accept both key formats from frontend
    cid     = data.get('chat_id') or data.get('chatId', 'global')
    content = data.get('content', '').strip()
    mtype   = data.get('message_type') or data.get('type', 'text')

    if not content: return

    if cid != 'global' and str(uid) not in cid.split('-'):
        emit('error', {'message': 'Unauthorized'})
        return

    try:
        msg = Message(chat_id=cid, sender_id=uid, content=content, message_type=mtype)
        db.session.add(msg)
        db.session.commit()
        db.session.refresh(msg)

        payload = {
            'id': msg.id, 'chat_id': cid,
            'sender_id': uid, 'sender_username': uname,
            'content': content, 'message_type': mtype,
            'created_at': msg.created_at.isoformat()
        }

        # ✅ ONE emit only — no duplicates
        socketio.emit('new_message', payload, room=cid)
        print(f"✅ Msg#{msg.id} → {cid}")
    except Exception as e:
        db.session.rollback()
        print(f"❌ Message error: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    print(f"❌ DISCONNECT: {session.get('username', 'Unknown')}")

# ============================================================
# HEALTH / DEBUG
# ============================================================
@app.route('/health')
def health():
    try:
        return jsonify({'status': 'ok', 'users': User.query.count(), 'messages': Message.query.count()})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/debug/users')
def debug_users():
    try:
        return jsonify({'success': True, 'users': [u.to_dict() for u in User.query.all()]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.teardown_appcontext
def shutdown_session(exception=None): db.session.remove()

# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 HPZ Messenger on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
