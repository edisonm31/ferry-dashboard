from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from data_manager import load_json, save_json
from flask import Flask, render_template, request, redirect, url_for, session, flash
import flask_socketio
from flask_socketio import SocketIO, emit
from collections import defaultdict
import csv
import io
from flask import make_response






terminals = load_json('terminals.json', [])
ferries = load_json('ferries.json', [])
submissions = load_json('submissions.json', [])


app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Add this too if you haven’t

socketio = SocketIO(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password  # hashed
        self.role = role

    def get_id(self):
        return str(self.id)
    
    

raw_users = load_json('users.json', [])
print(f"Loaded raw_users: {raw_users}")

users = {
    u['username']: User(
        id=u['id'],
        username=u['username'],
        password=generate_password_hash(u['password']),
        role=u['role']
    )
    for u in raw_users
}



@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.get_id() == user_id:
            return user
    return None



@app.route('/change_password', methods=['POST'])
def change_password():
    global users, raw_users  # ✅ Add this to modify both

    username = request.form['username']
    current_pw = request.form['current_password']
    new_pw = request.form['new_password']
    confirm_pw = request.form['confirm_password']

    user = users.get(username)

    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    if not check_password_hash(user.password, current_pw):
        flash("Current password is incorrect.")
        return redirect(url_for('login'))

    if new_pw != confirm_pw:
        flash("New passwords do not match.")
        return redirect(url_for('login'))

    # ✅ Update in-memory user object
    user.password = generate_password_hash(new_pw)

    # ✅ Update raw_users list and save
    for u in raw_users:
        if u['username'] == username:
            u['password'] = new_pw  # or generate_password_hash(new_pw) if storing hashed
            break

    save_json('users.json', raw_users)

    flash("Password updated successfully.")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))  # Everyone lands here
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/home')
@login_required
def home():

    return render_template('home.html')  # Or whatever page you want

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You’ve been logged out.")
    return redirect(url_for('login'))





@app.route('/dashboard')
@login_required
def dashboard():
    selected_ferry = request.args.get('ferry_filter', '')

    # Load all submissions
    all_submissions = load_json('submissions.json', [])

    # Role-based filtering
    if current_user.role in ['crew', 'admin']:
        submissions = all_submissions
    elif current_user.role == 'ferry':
        submissions = [s for s in all_submissions if s['ferry'] == current_user.username]
    else:
        submissions = []

    # Apply ferry filter if selected
    if selected_ferry:
        submissions = [s for s in submissions if s['ferry'] == selected_ferry]
        latest = max(submissions, key=lambda x: x['timestamp']) if submissions else None
        display_submissions = [latest] if latest else []
    else:
        # Group by ferry and get latest trip per ferry
        latest_by_ferry = {}
        for s in sorted(submissions, key=lambda x: x['timestamp'], reverse=True):
            if s['ferry'] not in latest_by_ferry:
                latest_by_ferry[s['ferry']] = s
        display_submissions = list(latest_by_ferry.values())

    # Load ferry list for dropdown
    ferries = load_json('ferries.json', [])

    return render_template(
        'dashboard.html',
        submissions=display_submissions,
        ferries=ferries,
        selected_ferry=selected_ferry
    )


@app.route('/admin/add_terminal', methods=['POST'])
@login_required
def add_terminal():
    global terminals
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    name = request.form['terminal_name']
    new_id = max([t['id'] for t in terminals], default=0) + 1
    terminals.append({'id': new_id, 'name': name})
    print(f"Saving terminals: {terminals}")
    save_json('terminals.json', terminals)  # ✅ This must be here
    return redirect(url_for('admin'))


@app.route('/admin/edit_terminal', methods=['POST'])
@login_required
def edit_terminal():
    global terminals
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    tid = int(request.form['terminal_id'])
    new_name = request.form['new_name']
    for t in terminals:
        if t['id'] == tid:
            t['name'] = new_name
            break

    save_json('terminals.json', terminals)  # ✅ Add this
    flash("Terminal updated.")
    return redirect(url_for('admin'))

@app.route('/admin/delete_terminal', methods=['POST'])
@login_required
def delete_terminal():
    global terminals
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    tid = int(request.form['terminal_id'])
    terminals[:] = [t for t in terminals if t['id'] != tid]

    save_json('terminals.json', terminals)  # ✅ Add this
    flash("Terminal deleted.")
    return redirect(url_for('admin'))

@app.route('/admin/add_ferry', methods=['POST'])
@login_required
def add_ferry():
    global ferries
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    name = request.form['ferry_name']
    new_id = max([f['id'] for f in ferries], default=0) + 1
    ferries.append({'id': new_id, 'name': name})
    save_json('ferries.json', ferries)
    flash("Ferry added.")
    return redirect(url_for('admin'))

@app.route('/admin/edit_ferry', methods=['POST'])
@login_required
def edit_ferry():
    global ferries
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    fid = int(request.form['ferry_id'])
    new_name = request.form['new_name']
    for f in ferries:
        if f['id'] == fid:
            f['name'] = new_name
            break

    save_json('ferries.json', ferries)
    flash("Ferry updated.")
    return redirect(url_for('admin'))

@app.route('/admin/delete_ferry', methods=['POST'])
@login_required
def delete_ferry():
    global ferries
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    fid = int(request.form['ferry_id'])
    ferries[:] = [f for f in ferries if f['id'] != fid]

    save_json('ferries.json', ferries)
    flash("Ferry deleted.")
    return redirect(url_for('admin'))

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    global users, raw_users
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    username = request.form['username']
    role = request.form['role']

    if username in users:
        flash("Username already exists.")
        return redirect(url_for('admin'))

    new_id = max([u['id'] for u in raw_users], default=0) + 1
    raw_users.append({
        'id': new_id,
        'username': username,
        'password': 'password',  # default
        'role': role
    })

    users = {
        u['username']: User(
            id=u['id'],
            username=u['username'],
            password=generate_password_hash(u['password']),
            role=u['role']
        )
        for u in raw_users
    }

    save_json('users.json', raw_users)
    flash("User added.")
    return redirect(url_for('admin'))

@app.route('/admin/update_role', methods=['POST'])
@login_required
def update_role():
    global users, raw_users
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    username = request.form['username']
    new_role = request.form['role']

    user = users.get(username)
    if not user:
        flash("User not found.")
        return redirect(url_for('admin'))

    for u in raw_users:
        if u['username'] == username:
            u['role'] = new_role
            break

    user.role = new_role
    save_json('users.json', raw_users)
    flash("Role updated.")
    return redirect(url_for('admin'))

@app.route('/admin/delete_user', methods=['POST'])
@login_required
def delete_user():
    global users, raw_users
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    username = request.form['username']

    if username not in users:
        flash("User not found.")
        return redirect(url_for('admin'))

    raw_users[:] = [u for u in raw_users if u['username'] != username]

    users = {
        u['username']: User(
            id=u['id'],
            username=u['username'],
            password=generate_password_hash(u['password']),
            role=u['role']
        )
        for u in raw_users
    }

    save_json('users.json', raw_users)
    flash("User deleted.")
    return redirect(url_for('admin'))

@app.route('/admin/reset_password', methods=['POST'])
@login_required
def reset_password():
    global users, raw_users
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('admin'))

    username = request.form['username']
    user = users.get(username)

    if not user:
        flash("User not found.")
        return redirect(url_for('admin'))

    # Update in-memory user
    user.password = generate_password_hash('password')

    # Update raw_users
    for u in raw_users:
        if u['username'] == username:
            u['password'] = 'password'  # or hash here if storing hashed
            break

    save_json('users.json', raw_users)
    flash(f"Password for {username} has been reset to default.")
    return redirect(url_for('admin'))

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('counter'))  # Attendants go to counter

    return render_template(
        'admin.html',
        terminals=terminals,
        ferries=ferries,
        users=users.values()
    )



@app.route('/counter', methods=['GET', 'POST'])
@login_required
def counter():
    if current_user.role not in ['attendant', 'crew', 'admin']:
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        data = {
            'timestamp': datetime.now().strftime('%A, %B %d, %Y %H:%M:%S %p'),
            'terminal': request.form['terminal'],
            'destination': request.form['destination'],
            'ferry': request.form['ferry'],
            'adult': int(request.form['adult']),
            'child': int(request.form['child']),
            'accessible': int(request.form['accessible']),
            'submitted_by': current_user.username
        }
        submissions.append(data)
        flash("Submission recorded.")
        return redirect(url_for('counter'))

    terminal_names = [t['name'] for t in terminals]
    ferry_names = [f['name'] for f in ferries]

    return render_template(
        'counter.html',
        terminals=terminal_names,
        destinations=terminal_names,
        ferries=ferry_names
    )

    # You’ll pass these in from your admin config

    

@app.route('/close_gate', methods=['POST'])
@login_required
def close_gate():

        # Save dropdowns to session
    session['terminal'] = request.form.get('terminal')
    session['destination'] = request.form.get('destination')
    session['ferry'] = request.form.get('ferry')

    submission = {
        'adult': int(request.form.get('adult', 0)),
        'child': int(request.form.get('child', 0)),
        'accessible': int(request.form.get('accessible', 0)),
        'attendant': current_user.username,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'terminal': request.form.get('terminal', 'Unknown'),
        'destination': request.form.get('destination', 'Unknown'),
        'ferry': request.form.get('ferry', 'Unknown')
    }

    submissions = load_json('submissions.json', [])
    submissions.append(submission)
    save_json('submissions.json', submissions)

    flash('Gate closed. Submission saved.')
    socketio.emit('new_submission', {'ferry': submission['ferry']})
    return redirect(url_for('counter'))


@app.route('/submit_count', methods=['POST'])
@login_required
def submit_count():
    action = request.form.get('type')
    if not action:
        flash("No action specified.")
        return redirect(url_for('counter'))

    counter = session.get('counter', {
        'adult': 0,
        'child': 0,
        'accessible': 0,
        'attendant': 0
    })

    if action in counter:
        counter[action] += 1
        session['counter'] = counter
        flash(f"{action.capitalize()} count updated.")
    else:
        flash(f"Unknown counter type: {action}")

    return redirect(url_for('counter'))



@app.route('/download')
@login_required
def download():
    selected_ferry = request.args.get('ferry_filter', '')
    all_submissions = load_json('submissions.json', [])

    # Role-based filtering
    if current_user.role in ['crew', 'admin']:
        submissions = all_submissions
    elif current_user.role == 'ferry':
        submissions = [s for s in all_submissions if s['ferry'] == current_user.username]
    else:
        submissions = []

    # Apply ferry filter if selected
    if selected_ferry:
        submissions = [s for s in submissions if s['ferry'] == selected_ferry]

    # Prepare CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'timestamp', 'ferry', 'terminal', 'destination',
        'adult', 'child', 'accessible', 'attendant'
    ])
    writer.writeheader()
    writer.writerows(submissions)

    # Send response
    response = make_response(output.getvalue())
    filename = f"{selected_ferry or 'all'}_submissions.csv"
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'text/csv'
    return response


if __name__ == '__main__':
    socketio.run(app, debug=True)
