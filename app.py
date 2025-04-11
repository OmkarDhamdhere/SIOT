from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = '65712417738724197264956526'  # Change this to a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Prevents unnecessary warnings

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if user isn't logged in

# Database model for Users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    iot_device_id = db.Column(db.String(100), unique=True, nullable=False)
    phone_email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone_email = request.form['phone_email']
        password = request.form['password']
        user = User.query.filter_by(phone_email=phone_email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful! Redirecting to dashboard.', 'success')
            
            # Check if user was trying to access a protected page before login
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))  # ✅ Redirect to dashboard

        else:
            flash('Login failed. Check your credentials.', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        iot_device_id = request.form['iot_device_id']
        phone_email = request.form['phone_email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # Check if user already exists
        existing_user = User.query.filter_by(phone_email=phone_email).first()
        if existing_user:
            flash('User already exists! Please log in.', 'danger')
            return redirect(url_for('login'))

        # Create new user
        new_user = User(iot_device_id=iot_device_id, phone_email=phone_email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Auto-login new user after signup
        login_user(new_user)

        flash('Signup successful! Redirecting to dashboard.', 'success')
        return redirect(url_for('dashboard'))  # ✅ Redirect after signup

    return render_template('signup.html')

@app.route('/dashboard', methods=['GET'])  # ✅ Fix: Only allow GET requests
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/guide')
def guide():
    return render_template('guide.html', user=current_user)

@app.route('/history')
def history():
    return render_template('history.html', user=current_user)

@app.route('/notification')
def notification():
    return render_template('notification.html', user=current_user)

@app.route('/prediction')
def prediction():
    return render_template('prediction.html', user=current_user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure database tables are created
    app.run(debug=True)


