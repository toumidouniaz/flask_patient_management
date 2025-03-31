from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import sqlite3
import bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Database connection function
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database (create the table)
@app.route('/init_db')
def init_db():
    conn = get_db()
    conn.execute('CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY, name TEXT, surname TEXT, age INT, illness TEXT, parameter TEXT, parameter_val REAL)')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')  # For storing users
    conn.commit()
    conn.close()
    return 'Table created successfully!'

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('x-access-token')  # Check in headers first
        if not token:
            token = request.cookies.get('x-access-token')  # Then check in cookies
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode the token to verify the user
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']  # Decode username from token
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'Invalid or expired token!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = get_db()

    if request.method == 'GET':
        return render_template('login.html')  # Show the login/registration form

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('login.html', error="Username and password are required")

    existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if existing_user:
        return render_template('login.html', error="Username already exists!")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()

    token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},app.config['SECRET_KEY'],algorithm='HS256')
    conn.close()

    # Redirect to main route with the token stored in a cookie
    response = redirect(url_for('new'))
    response.set_cookie('x-access-token', token)
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')  # Show the login form

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('login.html', error="Username and password are required")

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},app.config['SECRET_KEY'],algorithm='HS256')

        # Redirect to main route with the token stored in a cookie
        response = redirect(url_for('new'))
        response.set_cookie('x-access-token', token)
        return response
    else:
        return render_template('login.html', error="Invalid username or password")


@app.route('/', methods=['GET', 'POST'])
def new():
    token = request.cookies.get('x-access-token')  # Get the token from cookies
    current_user = None

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return redirect(url_for('login'))  # Redirect to login if token is invalid or expired

    if not current_user:
        return redirect(url_for('login'))

    conn = get_db()
    if request.method == 'POST':  # When the form is submitted
        name = request.form['n']
        surname = request.form['sn']
        age = request.form['age']
        illness = request.form['ill']
        parameter = request.form['para']
        parameter_val = request.form['value']

        conn.execute(
            'INSERT INTO patients (name, surname, age, illness, parameter, parameter_val) VALUES (?, ?, ?, ?, ?, ?)',
            (name, surname, age, illness, parameter, parameter_val)
        )
        conn.commit()

    patients = conn.execute('SELECT * FROM patients').fetchall()
    conn.close()

    return render_template('new.html', patients=patients, user=current_user)


# Update Patient Route (protected)
@app.route('/update/<int:id>', methods=['POST'])
@token_required
def update(current_user, id):
    conn = get_db()
    name = request.form['name']
    surname = request.form['surname']
    age = request.form['age']
    illness = request.form['illness']
    parameter = request.form['parameter']
    parameter_val = request.form['parameter_val']
    
    # Update the patient in the database
    conn.execute('UPDATE patients SET name = ?, surname = ?, age = ?, illness = ?, parameter = ?, parameter_val = ? WHERE id = ?',(name, surname, age, illness, parameter, parameter_val, id))
    conn.commit()
    conn.close()
    
    # Redirect back to the main page after updating
    return redirect(url_for('new'))

# Delete Patient Route (protected)
@app.route('/delete/<int:id>', methods=['POST'])
@token_required
def delete(current_user, id):
    conn = get_db()
    # Delete the patient from the database
    conn.execute('DELETE FROM patients WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('new'))

@app.route('/test-token', methods=['GET'])
@token_required
def test_token(current_user):
    return jsonify({'message': f'Token is valid for user: {current_user}'}), 200


if __name__ == '__main__':
    app.run(debug=True)
