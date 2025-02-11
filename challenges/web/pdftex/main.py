from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from forms import RegisterForm, LoginForm, CreateForm

app = Flask(__name__)
app.secret_key = os.urandom(24)  
csrf = CSRFProtect(app)

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'your_username'
app.config['MYSQL_PASSWORD'] = 'your_password'
app.config['MYSQL_DB'] = 'your_database'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return User(user['id'], user['username']) if user else None

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        mysql.connection.commit()
        cursor.close()
        
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'])
            login_user(user_obj)
            flash("Login successful!", "success")
            return redirect(url_for('create'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html', form=form)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = CreateForm()
    if request.method == 'POST':
        title = form.title.data
        design = form.design.data
        print(title, design)
        flash("Content created successfully!", "success")
        return render_template('create.html', form=form, send="design created")
    return render_template('create.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
