from flask import Flask, request, render_template, jsonify, session, send_file, g
import sqlite3
import secrets
import string
import logging
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
app.config['DATABASE'] = 'hospital.db'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.cli.command('initdb')
def initdb_command():
    init_db()
    print('Initialized the database.')

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Generate a random private key
def generate_private_key(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    if role not in ['patient', 'doctor']:
        return jsonify({'success': False, 'error': 'Invalid role'}), 400

    hashed_password = generate_password_hash(password)

    try:
        query_db('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                 [username, hashed_password, role])
        get_db().commit()
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        session['user_id'] = user['id']
        session['role'] = user['role']
        logging.info(f"User registered: {username} (ID: {user['id']}, Role: {user['role']})")
        return jsonify({'success': True, 'role': user['role']})
    except sqlite3.IntegrityError:
        logging.warning(f"Registration failed: Username '{username}' already exists")
        return jsonify({'success': False, 'error': 'Username already exists'}), 409
    except Exception as e:
        logging.error(f"Database error during registration: {str(e)}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    try:
        user = query_db('SELECT id, role, password FROM users WHERE username = ? AND role = ?',
                        [username, role], one=True)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            logging.info(f"User logged in: {username} (ID: {user['id']}, Role: {user['role']})")
            return jsonify({'success': True, 'role': user['role']})
        else:
            logging.warning(f"Login failed: Invalid credentials for username '{username}' and role '{role}'")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    except Exception as e:
        logging.error(f"Database error during login: {str(e)}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    logging.info(f"User logged out: ID {session.get('user_id')}, Role: {session.get('role')}")
    session.clear()
    return jsonify({'success': True})

@app.route('/upload', methods=['POST'])
def upload_data():
    if 'user_id' not in session:
        logging.warning("Upload attempted without being logged in")
        return jsonify({'error': 'Not logged in'}), 401

    content = request.form['content']
    description = request.form['description']
    private_key = generate_private_key()

    image_filename = None
    if 'image' in request.files:
        image = request.files['image']
        if image.filename != '':
            image_filename = secure_filename(f"{private_key}_{image.filename}")
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)
            logging.info(f"Image saved: {image_path}")

    try:
        if session['role'] == 'patient':
            query_db('INSERT INTO patient_data (patient_id, content, description, image_filename, private_key) VALUES (?, ?, ?, ?, ?)',
                     [session['user_id'], content, description, image_filename, private_key])
        else:
            query_db('INSERT INTO doctor_data (doctor_id, content, description, image_filename, private_key) VALUES (?, ?, ?, ?, ?)',
                     [session['user_id'], content, description, image_filename, private_key])
        get_db().commit()
        logging.info(f"Data uploaded by {session['role']} (ID: {session['user_id']}):")
        logging.info(f"Content: {content}")
        logging.info(f"Description: {description}")
        logging.info(f"Image: {image_filename}")
        logging.info(f"Private Key: {private_key}")
        return jsonify({'success': True, 'private_key': private_key})
    except Exception as e:
        logging.error(f"Database error during upload: {str(e)}")
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/retrieve', methods=['POST'])
def retrieve_data():
    private_key = request.form.get('private_key')
    
    if not private_key:
        logging.warning("Retrieval failed: Missing private key")
        return jsonify({'success': False, 'error': 'Missing private key'}), 400

    try:
        result = query_db('SELECT content, description, image_filename FROM patient_data WHERE private_key = ?',
                          [private_key], one=True)
        if not result:
            result = query_db('SELECT content, description, image_filename FROM doctor_data WHERE private_key = ?',
                              [private_key], one=True)
        
        if result:
            logging.info(f"Data retrieved with private key: {private_key}")
            return jsonify({
                'success': True,
                'content': result['content'],
                'description': result['description'],
                'image_filename': result['image_filename']
            })
        else:
            logging.warning(f"Retrieval failed: Invalid private key '{private_key}'")
            return jsonify({'success': False, 'error': 'Invalid private key'}), 404
    except Exception as e:
        logging.error(f"Database error during retrieval: {str(e)}")
        return jsonify({'success': False, 'error': f'Database error occurred: {str(e)}'}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=True)

