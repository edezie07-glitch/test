import os
import uuid
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from sqlalchemy import or_, and_
from functools import wraps

# ========== FLASK APP ==========
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30  # 30 days
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# ========== DATABASE ==========
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# ========== UPLOAD FOLDER ==========
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# ========== SOCKET.IO ==========
# FIX #1: logger=False to prevent Render timeout
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=False,          # ✅ FIXED: was True, caused timeout
    engineio_logger=False  # ✅ FIXED: was True, caused timeout
)

print("✅ Using async_mode='gevent' with full features")

# ========== MODELS ==========
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar_url = db.Column(db.String(500))
    bio = db.Column(db.String(500), default='')
    status = db.Column(db.String(100), default='Available')
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
            'status': self.status
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    sender = db.relationship('User', foreign_keys=[sender_id])

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

# ========== INIT DB ==========
with app.app_context():
    try:
        db.create_all()
        print("✅ Database initialized with all tables")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")

# ========== HELPERS ==========
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
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

def get_time_ago(dt):
    """FIX #3: Added missing function"""
    if not dt:
        return 'Never'
    # FIX: handle both naive and aware datetimes
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    seconds = (now - dt).total_seconds()
    if seconds < 60:
        return 'Just now'
    elif seconds < 3600:
        return f'{int(seconds / 60)}m ago'
    elif seconds < 86400:
        return f'{int(seconds / 3600)}h ago'
    return f'{int(seconds / 86400)}d ago'

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return jsonify({'success': False, 'error': 'Server error'}), 500

# ========== PAGE ROUTES ==========
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/chat')
    return render_template('login.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect('/chat')
    return render_template('register.html')

@app.route('/chat')
def chat():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return redirect('/')
        user = User.query.get(user_id)
        if not user:
            session.clear()
            return redirect('/')
        return render_template('chat.html', user=user, user_id=user.id)
    except Exception as e:
        print(f"❌ Chat route error: {e}")
        import traceback; traceback.print_exc()
        session.clear()
        return redirect('/')

# ========== AUTH ==========
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username too short (min 3)'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password too short (min 6)'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username taken'}), 400

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # FIX #5: session.modified = True ensures session is saved
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session.modified = True

        print(f"✅ Registered: {username} (ID: {user.id})")
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Register error: {e}")
        import traceback; traceback.print_exc()
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
            or_(User.username == identifier)
        ).first()

        if not user or not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        # FIX #5: session.modified = True ensures session is saved
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session.modified = True

        print(f"✅ Login: {user.username} (ID: {user.id})")
        return jsonify({'success': True, 'redirect': '/chat'})
    except Exception as e:
        print(f"❌ Login error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# ========== SEARCH ==========
@app.route('/api/users/search')
@login_required
def search_users():
    try:
        query = request.args.get('q', '').strip()
        user_id = session['user_id']

        if not query:
            return jsonify({'success': True, 'results': [], 'count': 0})

        users = User.query.filter(
            User.id != user_id,
            User.username.ilike(f'%{query}%')
        ).limit(20).all()

        results = []
        for user in users:
            is_friend = are_friends(user_id, user.id)

            req_sent = FriendRequest.query.filter_by(
                from_user_id=user_id,
                to_user_id=user.id,
                status='pending'
            ).first() is not None

            req_received = FriendRequest.query.filter_by(
                from_user_id=user.id,
                to_user_id=user_id,
                status='pending'
            ).first() is not None

            # FIX #2: Added 'relationship' field frontend needs
            if is_friend:
                relationship = 'friend'
            elif req_sent:
                relationship = 'request_sent'
            elif req_received:
                relationship = 'request_received'
            else:
                relationship = 'none'

            results.append({
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar_url or f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff&size=128",
                'status': user.status or 'Available',
                'bio': user.bio or '',
                'is_friend': is_friend,
                'is_online': False,
                'last_seen': 'Offline',
                'relationship': relationship,          # ✅ FIXED: was missing
                'request_sent': req_sent,
                'request_received': req_received
            })

        print(f"🔍 Search '{query}' found {len(results)} users")
        return jsonify({'success': True, 'results': results, 'count': len(results)})
    except Exception as e:
        print(f"❌ Search error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== PROFILE ==========
# FIX #4: Added missing profile endpoints

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'profile': {
                'bio': user.bio,
                'status': user.status,
                'avatar_url': user.avatar_url
            }
        })
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

        if 'bio' in data:
            user.bio = data['bio'][:500]
        if 'status' in data:
            user.status = data['status'][:100]

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
        filename = f"{uuid.uuid4().hex}.{ext}"
        upload_path = os.path.join(UPLOAD_FOLDER, 'avatars')
        os.makedirs(upload_path, exist_ok=True)
        file.save(os.path.join(upload_path, filename))

        url = f"/static/uploads/avatars/{filename}"
        user = User.query.get(session['user_id'])
        user.avatar_url = url
        db.session.commit()

        return jsonify({'success': True, 'url': url})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== FRIENDS ==========
@app.route('/api/friends')
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
            friend = User.query.get(friend_id)
            if friend:
                chat_id = get_chat_id(user_id, friend_id)
                last_msg = Message.query.filter_by(chat_id=chat_id).order_by(
                    Message.created_at.desc()
                ).first()

                avatar = friend.avatar_url or f"https://ui-avatars.com/api/?name={friend.username}&background=0088cc&color=fff&size=96"

                friends.append({
                    'id': friend.id,
                    'username': friend.username,
                    'avatar': avatar,
                    'avatar_url': avatar,
                    'avatarUrl': avatar,
                    'status': friend.status or 'Available',
                    'is_online': False,
                    'chat_id': chat_id,
                    'last_message': last_msg.content[:50] if last_msg else None,
                    'last_message_time': last_msg.created_at.isoformat() if last_msg else None
                })

        return jsonify({'success': True, 'friends': friends, 'contacts': friends})
    except Exception as e:
        print(f"❌ Get friends error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/requests')
@login_required
def get_friend_requests():
    try:
        user_id = session['user_id']

        received = FriendRequest.query.filter_by(
            to_user_id=user_id, status='pending'
        ).order_by(FriendRequest.created_at.desc()).all()

        sent = FriendRequest.query.filter_by(
            from_user_id=user_id, status='pending'
        ).all()

        received_list = []
        for req in received:
            user = User.query.get(req.from_user_id)
            if user:
                received_list.append({
                    'request_id': req.id,
                    'user_id': user.id,
                    'username': user.username,
                    'avatar': user.avatar_url or f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff",
                    'avatar_url': user.avatar_url or f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff",
                    'time_ago': get_time_ago(req.created_at)  # ✅ FIXED: uses get_time_ago
                })

        sent_list = []
        for req in sent:
            user = User.query.get(req.to_user_id)
            if user:
                sent_list.append({
                    'id': req.id,
                    'user_id': user.id,
                    'username': user.username
                })

        return jsonify({'success': True, 'received': received_list, 'sent': sent_list})
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
        if are_friends(user_id, to_user_id):
            return jsonify({'success': False, 'error': 'Already friends'}), 400
        if FriendRequest.query.filter_by(from_user_id=user_id, to_user_id=to_user_id, status='pending').first():
            return jsonify({'success': False, 'error': 'Request already sent'}), 400

        db.session.add(FriendRequest(from_user_id=user_id, to_user_id=to_user_id))
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    try:
        data = request.get_json()
        req = FriendRequest.query.get(data.get('request_id'))
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
        data = request.get_json()
        req = FriendRequest.query.get(data.get('request_id'))
        if not req or req.to_user_id != session['user_id']:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        db.session.delete(req)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== MESSAGES ==========
@app.route('/api/messages/<chat_id>')
@login_required
def get_messages(chat_id):
    try:
        user_id = session['user_id']
        if chat_id != 'global':
            user_ids = chat_id.split('-')
            if str(user_id) not in user_ids:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        messages = Message.query.filter_by(chat_id=chat_id).order_by(
            Message.created_at.desc()
        ).limit(50).all()
        messages.reverse()

        result = [{
            'id': m.id,
            'chat_id': m.chat_id,
            'sender_id': m.sender_id,
            'sender_username': m.sender.username if m.sender else 'Unknown',
            'content': m.content,
            'message_type': m.message_type,
            'created_at': m.created_at.isoformat()
        } for m in messages]

        return jsonify({'success': True, 'messages': result})
    except Exception as e:
        print(f"❌ Get messages error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== IMAGE UPLOAD ==========
@app.route('/api/upload/image', methods=['POST'])
@login_required
def upload_image():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image provided'}), 400

        file = request.files['image']
        if not file or file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            return jsonify({'success': True, 'url': f"/static/uploads/{filename}", 'filename': filename})

        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== SOCKET.IO ==========
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')

    print(f"🔌 CONNECT: {username} (ID: {user_id}) SID: {request.sid}")

    if not user_id:
        print("❌ No user_id in session - rejecting connection")
        return False

    join_room('global')
    join_room(f'user_{user_id}')
    print(f"✅ Joined 'global' and 'user_{user_id}' rooms")
    return True

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    user_id = session.get('user_id')
    if chat_id and user_id:
        join_room(chat_id)
        print(f"👥 User {user_id} joined chat: {chat_id}")

# Also support 'join' event used by frontend
@socketio.on('join')
def handle_join(data):
    chat_id = data.get('chatId') or data.get('chat_id')
    user_id = session.get('user_id')
    if chat_id and user_id:
        join_room(chat_id)
        print(f"👥 User {user_id} joined: {chat_id}")

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    username = session.get('username')

    # Support both chat_id and chatId from frontend
    chat_id = data.get('chat_id') or data.get('chatId', 'global')
    content = data.get('content', '').strip()
    message_type = data.get('message_type') or data.get('type', 'text')

    print(f"📥 MESSAGE: {username} → {chat_id}: {content[:40]}")

    if not user_id:
        emit('error', {'message': 'Not authenticated'})
        return

    if not content:
        return

    if chat_id != 'global':
        user_ids = chat_id.split('-')
        if str(user_id) not in user_ids:
            emit('error', {'message': 'Unauthorized'})
            return

    try:
        msg = Message(
            chat_id=chat_id,
            sender_id=user_id,
            content=content,
            message_type=message_type
        )
        db.session.add(msg)
        db.session.commit()
        db.session.refresh(msg)

        message_data = {
            'id': msg.id,
            'chat_id': chat_id,
            'sender_id': user_id,
            'sender_username': username,
            'content': content,
            'message_type': message_type,
            'created_at': msg.created_at.isoformat()
        }

        # Broadcast to room
        socketio.emit('new_message', message_data, room=chat_id)

        # Also notify individual users for private chats
        if chat_id != 'global' and '-' in chat_id:
            for uid in chat_id.split('-'):
                socketio.emit('new_message', message_data, room=f'user_{uid}')

        print(f"✅ Message #{msg.id} broadcast to '{chat_id}'")
    except Exception as e:
        db.session.rollback()
        print(f"❌ Message error: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    username = session.get('username')
    chat_id = data.get('chatId') or data.get('chat_id')
    if username and chat_id:
        socketio.emit('typing_start', {'username': username, 'chatId': chat_id},
                      room=chat_id, include_self=False)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    username = session.get('username')
    chat_id = data.get('chatId') or data.get('chat_id')
    if username and chat_id:
        socketio.emit('typing_stop', {'username': username, 'chatId': chat_id},
                      room=chat_id, include_self=False)

@socketio.on('disconnect')
def handle_disconnect():
    print(f"❌ DISCONNECT: {session.get('username', 'Unknown')}")

# ========== DEBUG ==========
@app.route('/health')
def health():
    try:
        return jsonify({
            'status': 'ok',
            'users': User.query.count(),
            'messages': Message.query.count(),
            'friendships': Friendship.query.count()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/debug/users')
def debug_users():
    try:
        return jsonify({
            'success': True,
            'users': [u.to_dict() for u in User.query.all()]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== TEARDOWN ==========
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# ========== RUN ==========
if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    port = int(os.environ.get('PORT', 5000))
    print(f"\n{'='*50}")
    print(f"🚀 HPZ MESSENGER STARTING")
    print(f"   Port: {port}")
    print(f"   Features: ✅ Friends ✅ Search ✅ Messages ✅ Images ✅ Profile")
    print(f"{'='*50}\n")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
