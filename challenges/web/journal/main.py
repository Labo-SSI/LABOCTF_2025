from flask import Flask, render_template, request, redirect, url_for, flash, session, render_template_string, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os
import random
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(128)
adminpass = secrets.token_urlsafe(128)
print(adminpass)
mad_scientist_titles = [
    "The Great Brain Swapping Experiment",
    "Mutant Plant Growth Serum",
    "Tesla's Revenge: Unlimited Power",
    "Invisibility Potion Gone Wrong",
    "Robotic Minion Army Blueprint",
    "Time Travel Paradox Generator",
    "Doomsday Weather Machine",
    "Zombie Reanimation Formula",
    "Mind Control Ray Gun",
    "Alien Communication Device"
]

mad_scientist_contents = [
    "Afters month in my secret lab, I've finally perfected the {0}! The results are shocking...",
    "My latest invention, the {0}, promises to revolutionize mad science as we know it!",
    "With the {0}, I shall rule the world! Mwahahaha!",
    "The {0} experiment failed spectacularly, turning my assistant into a giant frog.",
    "Behold the power of my {0}! Now to test it on the unsuspecting villagers...",
    "The {0} is complete. Time to unleash chaos upon this miserable planet!",
    "Years of research led to the {0}. Now, who wants to be my test subject?",
    "The {0} hummed to life today. The fabric of reality will never be the same!",
    "My genius knows no bounds with the {0}! Tremble before my scientific might!",
    "The {0} is my masterpiece. Soon, all will bow before Dr. Madstein!"
]


def process_content(content):
    return app.jinja_env.from_string(content).render()

def init_db():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT DEFAULT 'USER')''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS articles 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  author_id INTEGER,
                  FOREIGN KEY (author_id) REFERENCES users (id))''')
    
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 ('admin', generate_password_hash(adminpass), 'ADMIN'))
        
        c.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_id = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM articles")
        if c.fetchone()[0] == 0:
            for _ in range(10):
                title = random.choice(mad_scientist_titles)
                content_template = random.choice(mad_scientist_contents)
                content = content_template.format(title)
                c.execute("INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)",
                         (title, content, admin_id))
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        role = c.fetchone()[0]
        conn.close()
        if role != 'ADMIN':
            flash('Admin access required.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    if 'user_id' not in session:
        return False
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
    role = c.fetchone()[0]
    conn.close()
    return role == 'ADMIN'

@app.route('/')
@login_required
def home():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute("SELECT articles.*, users.username FROM articles JOIN users ON articles.author_id = users.id ORDER BY articles.id DESC")
    articles = c.fetchall()
    conn.close()
    processed_articles = []
    for article in articles:
        article_id, title, content, author_id, username = article
        rendered_content = process_content(content)
        processed_articles.append((article_id, title, rendered_content, author_id, username))
    return render_template('home.html', articles=processed_articles, is_admin=is_admin())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                     (username, generate_password_hash(password)))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
        finally:
            conn.close()
    return render_template('register.html', is_admin=is_admin())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        flash('Invalid credentials.')
    return render_template('login.html', is_admin=is_admin())

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('home'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['password']
        
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        
        if user:
            user_id = user[0]
            c.execute("UPDATE users SET password = ? WHERE id = ?",
                      (generate_password_hash(new_password), user_id))
            conn.commit()
            flash(f"Password updated successfully for {username}!")
        else:
            flash("User not found.")
        conn.close()
        return redirect(url_for('account'))
    
    c.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
    current_username = c.fetchone()[0]
    conn.close()
    return render_template('account.html', is_admin=is_admin(), current_username=current_username)

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        c.execute("INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)",
                 (title, content, session['user_id']))
        conn.commit()
        conn.close()
        flash('Article created successfully!')
        return redirect(url_for('admin'))
    return render_template('admin.html', is_admin=is_admin())


templates = {
    'base.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Mad Scientist Blog</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
        body { background: #f0f2f5; color: #333; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        nav { background: #2c3e50; padding: 15px 20px; margin-bottom: 20px; }
        nav a { color: white; text-decoration: none; margin-right: 15px; font-weight: bold; }
        nav a:hover { color: #3498db; }
        .flash { padding: 15px; background: #e74c3c; color: white; margin-bottom: 20px; border-radius: 5px; }
        h1 { color: #2c3e50; margin-bottom: 20px; }
        button, input[type="submit"] { 
            background: #3498db; 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 16px; 
        }
        button:hover, input[type="submit"]:hover { background: #2980b9; }
    </style>
</head>
<body>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
        {% if 'user_id' not in session %}
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Register</a>
        {% else %}
            <a href="{{ url_for('account') }}">Account</a>
            <a href="{{ url_for('logout') }}">Logout</a>
            {% if is_admin %}
                <a href="{{ url_for('admin') }}">Admin</a>
            {% endif %}
        {% endif %}
    </nav>
    <div class="container">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="flash">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>''',

    'home.html': '''{% extends "base.html" %}
{% block content %}
    <h1>Mad Scientist Chronicles</h1>
    {% for article in articles %}
        <div class="article" style="
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        ">
            <h2 style="color: #2c3e50; margin-bottom: 10px;">{{ article[1] }}</h2>
            <p style="margin-bottom: 10px;">{{ article[2] | safe }}</p>
            <p style="color: #7f8c8d; font-style: italic;">By: {{ article[4] }}</p>
        </div>
    {% endfor %}
    {% if not articles %}
        <p style="color: #7f8c8d; text-align: center;">No experiments documented yet!</p>
    {% endif %}
{% endblock %}''',

    'register.html': '''{% extends "base.html" %}
{% block content %}
    <h1>Join the Mad Scientists</h1>
    <form method="POST" style="
        background: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    ">
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Username:</label>
            <input type="text" name="username" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            ">
        </div>
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Password:</label>
            <input type="password" name="password" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            ">
        </div>
        <input type="submit" value="Register">
    </form>
{% endblock %}''',

    'login.html': '''{% extends "base.html" %}
{% block content %}
    <h1>Mad Scientist Login</h1>
    <form method="POST" style="
        background: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    ">
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Username:</label>
            <input type="text" name="username" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            ">
        </div>
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Password:</label>
            <input type="password" name="password" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            ">
        </div>
        <input type="submit" value="Login">
    </form>
{% endblock %}''',

   'account.html': '''{% extends "base.html" %}
{% block content %}
    <h1>Lab Security</h1>
    <form method="POST" style="
        background: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    ">
        <input type="hidden" name="username" value="{{ current_username }}">
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">New Password:</label>
            <input type="password" name="password" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            ">
        </div>
        <input type="submit" value="Update Password">
    </form>
{% endblock %}''',

    'admin.html': '''{% extends "base.html" %}
{% block content %}
    <h1>Mad Experiment Log</h1>
    <form method="POST" style="
        background: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    ">
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Experiment Title:</label>
            <input type="text" name="title" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            ">
        </div>
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Experiment Details:</label>
            <textarea name="content" required style="
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                min-height: 150px;
                resize: vertical;
            "></textarea>
        </div>
        <input type="submit" value="Record Experiment">
    </form>
{% endblock %}'''
}

if not os.path.exists('templates'):
    os.makedirs('templates')
for name, content in templates.items():
    with open(f'templates/{name}', 'w') as f:
        f.write(content)

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0')