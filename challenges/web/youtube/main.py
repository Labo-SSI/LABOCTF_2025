from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  
db = SQLAlchemy(app)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2083), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    uuid = db.Column(db.String(128), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/submit', methods=['POST'])
def submit():
    url = request.form['url']
    try:
        if "https://www.youtube.com/watch?v=" not in url:
            raise ValueError
    except ValueError:
        flash('Invalid YouTube video.', 'error')
        return redirect(url_for('home'))
    new_url = URL(url=url, uuid=str(uuid.uuid4()))
    db.session.add(new_url)
    db.session.commit()
    flash('URL submitted successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'password':
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            flash('Invalid credentials', 'error')
    
    if 'logged_in' in session:
        urls = URL.query.order_by(URL.timestamp.desc()).all()
    else:
        urls = []
    return render_template('admin.html', urls=urls)

@app.route('/admin/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')