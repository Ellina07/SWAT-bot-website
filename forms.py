from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    reading_goal = db.Column(db.Integer, default=0)  # Новое поле для цели
    books = db.relationship('Book', backref='user', lazy=True)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    genre = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    want_to_read_books = Book.query.filter_by(user_id=current_user.id, status='хочу прочитать').all()
    in_progress_books = Book.query.filter_by(user_id=current_user.id, status='в процессе').all()
    read_books = Book.query.filter_by(user_id=current_user.id, status='прочитано').all()
    return render_template('dashboard.html', want_to_read_books=want_to_read_books, in_progress_books=in_progress_books, read_books=read_books)


@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        genre = request.form.get('genre')
        status = request.form.get('status')
        new_book = Book(title=title, author=author, genre=genre, status=status, user_id=current_user.id)
        db.session.add(new_book)
        db.session.commit()
        flash('Book added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_book.html')


@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    if request.method == 'POST':
        book.title = request.form.get('title')
        book.author = request.form.get('author')
        book.genre = request.form.get('genre')
        book.status = request.form.get('status')
        book.rating = request.form.get('rating')
        db.session.commit()
        flash('Book updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_book.html', book=book)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        goal = request.form.get('goal')
        current_user.reading_goal = goal
        db.session.commit()
        flash('Reading goal set successfully!', 'success')
        return redirect(url_for('profile'))
    read_books = Book.query.filter_by(user_id=current_user.id, status='прочитано').count()
    want_to_read_books = Book.query.filter_by(user_id=current_user.id, status='хочу прочитать').count()
    return render_template('profile.html', read_books=read_books, want_to_read_books=want_to_read_books, reading_goal=current_user.reading_goal)


@app.route('/set_goal', methods=['POST'])
@login_required
def set_goal():
    goal = request.form.get('goal')
    current_user.reading_goal = goal
    db.session.commit()
    flash('Reading goal set successfully!', 'success')
    return redirect(url_for('profile'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
