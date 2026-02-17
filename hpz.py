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

# ========== FLASK APP ==========
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# ========== DATABASE ==========
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///hpz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ========== UPLOAD FOLDER ==========
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# ========== SOCKET.IO ==========
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    cors_credentials=True,
    async_mode='gevent',
    logger=True,
    engineio_logger=True
)

print("✅ Using async_mode='gevent' with full features")

# ========== MODELS ==========
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)  # 'global' or 'user1-user2'
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')  # 'text' or 'image'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    sender = db.relationship('User', foreign_keys=[sender_id])

class Friendship(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id'),)

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ========== INIT DB ==========
with app.app_context():
    try:
        db.create_all()
        print("✅ Database initialized with all tables")
        
        # List tables
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"📊 Tables: {tables}")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        import traceback
        traceback.print_exc()

# ========== HELPER FUNCTIONS ==========
def allowed_file(filename):
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

# ========== ROUTES ==========
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
        if 'user_id' not in session:
            return redirect('/')
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect('/')
        return render_template('chat.html', user=user, user_id=user.id)
    except Exception as e:
        print(f"❌ Error in /chat route: {e}")
        import traceback
        traceback.print_exc()
        return f"Error loading chat: {str(e)}", 500

# ========== AUTH API ==========
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'Username taken'}), 400
    
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'success': True, 'redirect': '/chat'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')
    
    user = User.query.filter_by(username=identifier).first()
    if not user or not user.check_password(password):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'success': True, 'redirect': '/chat'})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# ========== USER SEARCH API ==========
@app.route('/api/users/search')
def search_users():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    query = request.args.get('q', '').strip()
    user_id = session['user_id']
    
    if not query:
        return jsonify({'success': True, 'results': []})
    
    users = User.query.filter(
        User.id != user_id,
        User.username.ilike(f'%{query}%')
    ).limit(20).all()
    
    results = []
    for user in users:
        is_friend = are_friends(user_id, user.id)
        
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
        
        results.append({
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar_url or f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff",
            'is_friend': is_friend,
            'request_sent': request_sent,
            'request_received': request_received
        })
    
    return jsonify({'success': True, 'results': results})

# ========== FRIENDS API ==========
@app.route('/api/friends')
def get_friends():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    user_id = session['user_id']
    
    friendships = Friendship.query.filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    
    friends = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.get(friend_id)
        
        if friend:
            # Get last message
            chat_id = get_chat_id(user_id, friend_id)
            last_msg = Message.query.filter_by(chat_id=chat_id).order_by(
                Message.created_at.desc()
            ).first()
            
            friends.append({
                'id': friend.id,
                'username': friend.username,
                'avatar': friend.avatar_url or f"https://ui-avatars.com/api/?name={friend.username}&background=0088cc&color=fff",
                'chat_id': chat_id,
                'last_message': last_msg.content if last_msg else None,
                'last_message_time': last_msg.created_at.isoformat() if last_msg else None
            })
    
    return jsonify({'success': True, 'friends': friends})

@app.route('/api/friends/requests')
def get_friend_requests():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    user_id = session['user_id']
    
    # Received requests
    received = FriendRequest.query.filter_by(
        to_user_id=user_id,
        status='pending'
    ).all()
    
    received_list = []
    for req in received:
        user = User.query.get(req.from_user_id)
        if user:
            received_list.append({
                'request_id': req.id,
                'user_id': user.id,
                'username': user.username,
                'avatar': user.avatar_url or f"https://ui-avatars.com/api/?name={user.username}&background=0088cc&color=fff"
            })
    
    return jsonify({'success': True, 'received': received_list})

@app.route('/api/friends/request', methods=['POST'])
def send_friend_request():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    data = request.get_json()
    user_id = session['user_id']
    to_user_id = data.get('to_user_id')
    
    if user_id == to_user_id:
        return jsonify({'success': False, 'error': 'Cannot add yourself'}), 400
    
    # Check if already friends
    if are_friends(user_id, to_user_id):
        return jsonify({'success': False, 'error': 'Already friends'}), 400
    
    # Check if request already exists
    existing = FriendRequest.query.filter_by(
        from_user_id=user_id,
        to_user_id=to_user_id,
        status='pending'
    ).first()
    
    if existing:
        return jsonify({'success': False, 'error': 'Request already sent'}), 400
    
    req = FriendRequest(from_user_id=user_id, to_user_id=to_user_id)
    db.session.add(req)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/friends/accept', methods=['POST'])
def accept_friend_request():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    data = request.get_json()
    request_id = data.get('request_id')
    
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != session['user_id']:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    
    # Create friendship
    friendship = Friendship(
        user1_id=min(req.from_user_id, req.to_user_id),
        user2_id=max(req.from_user_id, req.to_user_id)
    )
    db.session.add(friendship)
    
    # Update request status
    req.status = 'accepted'
    db.session.delete(req)
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/friends/reject', methods=['POST'])
def reject_friend_request():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    data = request.get_json()
    request_id = data.get('request_id')
    
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user_id != session['user_id']:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    
    db.session.delete(req)
    db.session.commit()
    
    return jsonify({'success': True})

# ========== MESSAGES API ==========
@app.route('/api/messages/<chat_id>')
def get_messages(chat_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    
    # Verify user has access to this chat
    user_id = session['user_id']
    if chat_id != 'global':
        # Private chat - check if users are friends
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
        'sender_username': m.sender.username,
        'content': m.content,
        'message_type': m.message_type,
        'created_at': m.created_at.isoformat()
    } for m in messages]
    
    return jsonify({'success': True, 'messages': result})

# ========== IMAGE UPLOAD API ==========
@app.route('/api/upload/image', methods=['POST'])
def upload_image():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image provided'}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        # Generate unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        
        # Ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Return URL
        url = f"/static/uploads/{filename}"
        
        return jsonify({
            'success': True,
            'url': url,
            'filename': filename
        })
    
    return jsonify({'success': False, 'error': 'Invalid file type'}), 400

# ========== SOCKET.IO EVENTS ==========
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"\n{'='*50}")
    print(f"🔌 CONNECT: {username} (ID: {user_id})")
    print(f"   Socket SID: {request.sid}")
    
    if user_id:
        # Join global room
        join_room('global')
        
        # Join personal room for notifications
        join_room(f'user_{user_id}')
        
        print(f"✅ Joined 'global' and 'user_{user_id}' rooms")
    else:
        print(f"❌ No user_id in session!")
    
    print(f"{'='*50}\n")
    return True

@socketio.on('join_chat')
def handle_join_chat(data):
    """Join a specific chat room (private or global)"""
    chat_id = data.get('chat_id')
    user_id = session.get('user_id')
    
    if chat_id and user_id:
        join_room(chat_id)
        print(f"👥 User {user_id} joined chat: {chat_id}")

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    username = session.get('username')
    chat_id = data.get('chat_id', 'global')
    content = data.get('content', '').strip()
    message_type = data.get('message_type', 'text')
    
    print(f"\n{'='*50}")
    print(f"📥 MESSAGE FROM: {username} (ID: {user_id})")
    print(f"   Chat: {chat_id}")
    print(f"   Type: {message_type}")
    print(f"   Content: {content[:50]}...")
    print(f"   Socket SID: {request.sid}")
    
    if not user_id:
        print(f"❌ ERROR: No user_id!")
        emit('error', {'message': 'Not authenticated'})
        return
    
    if not content:
        print(f"❌ ERROR: Empty content!")
        return
    
    # Verify access for private chats
    if chat_id != 'global':
        user_ids = chat_id.split('-')
        if str(user_id) not in user_ids:
            print(f"❌ ERROR: Unauthorized access to chat {chat_id}")
            emit('error', {'message': 'Unauthorized'})
            return
    
    # Save to database
    msg = Message(
        chat_id=chat_id,
        sender_id=user_id,
        content=content,
        message_type=message_type
    )
    db.session.add(msg)
    db.session.commit()
    db.session.refresh(msg)
    
    # Create response
    message_data = {
        'id': msg.id,
        'chat_id': chat_id,
        'sender_id': user_id,
        'sender_username': username,
        'content': content,
        'message_type': message_type,
        'created_at': msg.created_at.isoformat()
    }
    
    print(f"💾 Saved to database: Message #{msg.id}")
    print(f"📤 Broadcasting to '{chat_id}' room...")
    
    # Send to everyone in the room INCLUDING sender
    socketio.emit('new_message', message_data, room=chat_id)
    print(f"   ✓ Broadcast to room '{chat_id}'")
    
    print(f"✅ Message broadcast complete!")
    print(f"{'='*50}\n")

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username', 'Unknown')
    print(f"❌ DISCONNECT: {username}\n")

# ========== DEBUG ==========
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'users': User.query.count(),
        'messages': Message.query.count(),
        'friendships': Friendship.query.count()
    })

# ========== RUN ==========
if __name__ == '__main__':
    # Create upload folder
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    print(f"\n{'='*50}")
    print(f"🚀 ENHANCED MESSENGER STARTING")
    print(f"   Port: {port}")
    print(f"   Features: Private Chats ✅ Friends ✅ Images ✅")
    print(f"{'='*50}\n")
    socketio.run(app, host='0.0.0.0', port=port)
