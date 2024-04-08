import os

from flask import Flask, request, render_template, flash, redirect, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix

from db import DB

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ['SECRET_KEY']
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)


@app.route("/", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username or password is missing", "error")
            return redirect(url_for('register'))

        if not isinstance(username, str) or not isinstance(password, str):
            flash("Username or password is invalid", "error")
            return redirect(url_for('register'))

        if len(password) < 8:
            flash("Password too short", "error")
            return redirect(url_for('register'))

        db = DB(request.remote_addr)
        user_id = db.register(username, password)
        if user_id:
            session_id = db.create_session(user_id)

            resp = make_response(redirect(url_for('todo')))
            resp.set_cookie('session', session_id)

            return resp

        flash("Username already exists", "error")
        return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/todo', methods=['GET', 'POST'])
def todo():
    session_id = request.cookies.get('session')

    if not session_id:
        return redirect(url_for('register'))

    db = DB(request.remote_addr)
    user = db.get_user_from_session(session_id)

    if not user:
        return redirect(url_for('register'))

    if request.method == 'POST':
        description = request.form.get('description')
        if not description or len(description) < 8:
            return redirect(url_for('todo'))

        db.add_task(description, user['id'])
        return redirect(url_for('todo'))
    else:
        tasks = db.get_tasks(user['id'])

        return render_template('todo.html', username=user['username'], tasks=tasks)


@app.route('/toggle/<task_id>', methods=['POST'])
def toggle(task_id):
    session_id = request.cookies.get('session')

    if not session_id:
        return redirect(url_for('register'))

    db = DB(request.remote_addr)
    user = db.get_user_from_session(session_id)

    if not user:
        return redirect(url_for('register'))

    db.toggle_task(task_id, user['id'])
    return redirect(url_for('todo'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
