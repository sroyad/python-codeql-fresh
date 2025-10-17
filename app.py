from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import subprocess
import os
import pickle
import hashlib
import base64

app = Flask(__name__)
DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return "Welcome to the vulnerable Python app!"

# 1. SQL Injection
@app.route('/users')
def users():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect(DATABASE)
    # Vulnerable to SQL Injection
    cursor = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    if user:
        return f"User: {user[1]}"
    return "User not found"

# 2. Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # Vulnerable to Command Injection
    output = subprocess.getoutput(f"ping -c 1 {host}")
    return f"<pre>{output}</pre>"

# 3. Path Traversal
@app.route('/view')
def view_file():
    filename = request.args.get('file', 'app.py')
    # Vulnerable to Path Traversal
    with open(filename, 'r') as f:
        content = f.read()
    return f"<pre>{content}</pre>"

# 4. XSS Vulnerability
@app.route('/search')
def search():
    query = request.args.get('query', 'default')
    # Vulnerable to Reflected XSS
    return f"You searched for: {query}"

# 5. Hardcoded Credentials
SECRET_KEY = "hardcoded-secret-key-123" # Hardcoded credential
@app.route('/secret')
def show_secret():
    return f"The secret key is: {SECRET_KEY}"

# 6. Insecure Deserialization
@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize_data():
    if request.method == 'POST':
        data = request.form.get('data')
        if data:
            # Vulnerable to Insecure Deserialization
            deserialized_data = pickle.loads(base64.b64decode(data))
            return f"Deserialized data: {deserialized_data}"
    return '<form method="post"><input type="text" name="data"><input type="submit" value="Deserialize"></form>'

# 7. Weak Cryptography (MD5)
@app.route('/hash')
def hash_data():
    text = request.args.get('text', 'test')
    # Vulnerable: Using MD5 for hashing
    hashed_text = hashlib.md5(text.encode()).hexdigest()
    return f"MD5 hash of '{text}': {hashed_text}"

# 8. File Upload Vulnerability (basic, no proper validation)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            # Vulnerable: No proper filename sanitization or content validation
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            return f'File uploaded successfully to {filepath}'
    return '''
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    '''

if __name__ == '__main__':
    # 9. Flask app is run in debug mode (High severity)
    app.run(debug=True)
