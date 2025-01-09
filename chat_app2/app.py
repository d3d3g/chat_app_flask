
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Mess
from sqlalchemy.orm import sessionmaker 
Session = sessionmaker() 
session = Session() 
import hashlib
sha256_hash = hashlib.new('sha256')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    mess_from_db = Mess.query.filter_by()
    return render_template('index.html', username=current_user.username, allmes=mess_from_db)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        # sha256_hash.update(password.encode())
        # sha256_hex = sha256_hash.hexdigest()
        hashed_password = password
        if user and user.password == hashed_password:
            login_user(user)
            return redirect(url_for('index'))
        flash('Wrong password.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # sha256_hash.update(password.encode())
        # sha256_hex = sha256_hash.hexdigest()
        hashed_password = password
        q = User.query.filter_by(username = username).first()
        if q != None:
            flash('User already exist.')
            return redirect(url_for('register'))
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@socketio.on('message')
def handle_message(msg):
    new_msg = Mess(author=current_user.username, mess=msg)
    db.session.add(new_msg)
    db.session.commit()
    print(f'Received message from {current_user.username}: {msg}')
    emit('message', f'{current_user.username}: {msg}', broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создание базы данных
    socketio.run(app) #http://127.0.0.1:5000/    
