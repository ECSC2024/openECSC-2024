from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from db import DB
from werkzeug.security import generate_password_hash, check_password_hash
import string
import random
import re
import os
import requests

app = Flask(__name__)
MAIL_HOST = os.environ.get('MAIL_HOST')
MAIL_TOKEN = os.environ['MAIL_TOKEN']
ADMIN_EMAIL = os.environ['ADMIN_EMAIL']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
HEADLESS_HOST = os.environ.get('HEADLESS_HOST')
HEADLESS_AUTH = os.environ.get('HEADLESS_AUTH')

app.secret_key = os.environ.get('SECRET_KEY',
                                ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(32)]))

mail_regex = re.compile(r'^([A-Za-z0-9]+[.\-_])*[A-Za-z0-9]+@fakemail\.olicyber\.it$')


@app.route('/api/add_email', methods=['POST'])
def add_email():
    data = request.get_json()

    if 'token' not in data:
        return jsonify({
            "error": "Token is required"
        }), 400

    if data['token'] != MAIL_TOKEN:
        return jsonify({
            "error": "Invalid token"
        }), 400

    if 'from' not in data or not isinstance(data['from'], str) or not re.fullmatch(mail_regex, data['from']):
        return jsonify({
            "error": "From is required"
        }), 400

    if 'to' not in data or not isinstance(data['to'], str) or not re.fullmatch(mail_regex, data['to']):
        return jsonify({
            "error": "To is required"
        }), 400

    if 'subject' not in data or not isinstance(data['subject'], str):
        return jsonify({
            "error": "Subject is required"
        }), 400

    if 'body' not in data or not isinstance(data['body'], str):
        return jsonify({
            "error": "Body is required"
        }), 400

    db = DB()

    to = data['to']
    user = db.get_user(to)

    if user is None:
        return jsonify({
            "error": "User does not exist"
        }), 400

    email_id = db.add_email(user['id'], data['from'], data['subject'], data['body'])

    if to == ADMIN_EMAIL:
        # Start worker
        r = requests.post(
            "http://" + HEADLESS_HOST,
            headers={
                "X-Auth": HEADLESS_AUTH,
            },
            json={
                'actions': [
                    # Go to fakemail
                    {
                        "type": "request",
                        "url": f"http://{MAIL_HOST}/",
                        "timeout": 5,
                    },

                    # Login to fake mail
                    {
                        "type": "type",
                        "element": "#email",
                        "value": ADMIN_EMAIL
                    },
                    {
                        "type": "type",
                        "element": "#password",
                        "value": ADMIN_PASSWORD
                    },
                    {
                        "type": "click",
                        "element": "#submit"
                    },
                    {
                        "type": "sleep",
                        "time": 1
                    },

                    # Visit the email
                    {
                        "type": "request",
                        "url": f"http://{MAIL_HOST}/email/{email_id}",
                    },
                    {
                        "type": "sleep",
                        "time": 1
                    },

                    # Click on the link
                    {
                        "type": "click",
                        "element": "#body > a",
                    },
                    {
                        "type": "sleep",
                        "time": 1
                    },
                ]
            }
        )
        r.raise_for_status()

    return jsonify({
        "success": True
    }), 201


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not isinstance(email, str) or not re.fullmatch(mail_regex, email):
            flash("Email non valida, deve finire per @fakemail.olicyber.it", "error")
            return redirect(url_for('register'))

        if not isinstance(password, str) or len(password) < 8:
            flash("La password deve essere lunga almeno 8 caratter", "error")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Le password non corrispondono", "error")
            return redirect(url_for('register'))

        db = DB()
        user = db.get_user(email)

        if user:
            flash("L'utente esiste già", "error")
            return redirect(url_for('register'))

        db.add_user(email, generate_password_hash(password))

        return redirect(url_for('login'))

    return render_template("register.html")


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        db = DB()
        user = db.get_user(email)

        if not user:
            flash("User does not exist", "error")
            return redirect(url_for('login'))

        if not check_password_hash(user['password'], password):
            flash("Invalid password", "error")
            return redirect(url_for('login'))

        session['user_id'] = user['id']

        return redirect(url_for('inbox'))

    return render_template("login.html")


@app.route('/inbox')
def inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = DB()
    emails = db.get_emails(session['user_id'])

    return render_template("inbox.html", emails=emails[::-1])


@app.route('/email/<int:email_id>')
def email(email_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = DB()
    email = db.get_email(session['user_id'], email_id)

    if not email:
        return redirect(url_for('inbox'))

    db.set_seen(email['id'])

    return render_template("email.html", email=email)


@app.route('/email/<int:email_id>/delete', methods=['POST'])
def delete_email(email_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = DB()
    email = db.get_email(session['user_id'], email_id)

    if not email:
        return redirect(url_for('inbox'))

    if email['user_id'] != session['user_id']:
        return redirect(url_for('inbox'))

    db.delete_mail(email['id'])

    return redirect(url_for('inbox'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
