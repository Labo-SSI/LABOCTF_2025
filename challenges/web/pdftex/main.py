from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess
from forms import RegisterForm, LoginForm, CreateForm
import secrets
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(128) 
csrf = CSRFProtect(app)

UPLOAD_FOLDER = "files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['MYSQL_HOST'] = 'mysql'
app.config['MYSQL_USER'] = 'your_username'
app.config['MYSQL_PASSWORD'] = 'your_password'
app.config['MYSQL_DB'] = 'your_database'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def initialize_database():
    """Creates the database and tables if they do not exist."""
    with app.app_context():
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("CREATE DATABASE IF NOT EXISTS your_database")
            cursor.execute("USE your_database")
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
            """)
            mysql.connection.commit()
            print("Database initialized successfully! 🎉")
        except Exception as e:
            print(f"Database Error: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

initialize_database()

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

blacklist = [
    "begin", "input", "include", "newread", "openin", "read", "closein", "text", "lstinputlisting", 
    "usepackage", "verbatiminput", "catcode", "lstin", "newwrite", "openout", "write", "immediate", "url", "href", 
    "pdffiledump", "write18", "renewcommand", "dagger", "outfile", "loop"
]


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
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            mysql.connection.commit()
            cursor.close()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Database error: {e}", "danger")
            print(f"Error inserting user: {e}")
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
            print(f"User {username} logged in successfully!")  
            flash("Login successful!", "success")
            return redirect(url_for('create'))
        else:
            print("Invalid login attempt")  
            flash("Invalid credentials", "danger")
    return render_template('login.html', form=form)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = CreateForm()
    if request.method == 'POST':
        title = form.title.data
        design = form.design.data
        for item in blacklist:
            if item in title.lower():
                title = "Not allowed"
            if item in design.lower():
                design = "Not allowed"
        tex_content = f"""
        \documentclass{{article}}
        \\begin{{document}}
        {title}

        \\begin{{picture}}(100,100)

        {design}

        \end{{picture}}

        \end{{document}}
        """
        
        tex_path = os.path.join(UPLOAD_FOLDER, "main.tex")
        pdf_path = os.path.join(UPLOAD_FOLDER, "main.pdf")
        
        with open(tex_path, "w") as tex_file:
            tex_file.write(tex_content)
        
        subprocess.run(
            ["pdflatex", "--shell-restricted", "--interaction=nonstopmode", "-output-directory", UPLOAD_FOLDER, tex_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        return send_file(pdf_path, as_attachment=True)
    return render_template('create.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=False, port=5000, host='0.0.0.0')
