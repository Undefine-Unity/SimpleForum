from flask import *

import datetime
import json
import random
import requests
import string
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = '4kr/:/S>tEayrQu2(5waOW{A>]H56='

database = sqlite3.connect('database.db', check_same_thread=False)

active_tokens = {}

recaptcha_secret = ''

def generate_random_token():
    token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    while token in active_tokens.keys():
        token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))

    return token

def login(username: str, password: str) -> Response:
    accountTuple = database.execute('select * from accounts where upper(username)=upper(?)', [username]).fetchone()
    if accountTuple is None:
        return redirect(url_for('login', error='Account not found'))

    id, username, password, email = accountTuple

    if password != password:
        return redirect(url_for('login', error='Invalid password'))
        
    if id in active_tokens.values():
        return redirect(url_for('login', error='User already logged in'))
        
    token = generate_random_token()
    active_tokens[token] = id
    
    resp = make_response(redirect('/'))
    resp.set_cookie('token', token)
    return resp

def logout(token: str) -> Response:
    if token in active_tokens.keys():
        active_tokens.pop(token)
    resp = make_response(redirect('/'))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/')
def main():
    # Check if token is still valid
    if 'token' in request.cookies.keys() and not request.cookies['token'] in active_tokens:
        return logout(request.cookies['token'])
    
    posts = database.execute('select * from posts').fetchall()
    
    username = ''
    if 'token' in request.cookies.keys():
        username = database.execute('select username from accounts where id=?', [active_tokens[request.cookies['token']]]).fetchone()[0]
        
    return render_template('main.html', posts=posts, username=username)

@app.route('/login')
def login_endpoint():
    if 'token' in request.cookies.keys():
        return redirect('/')
    return render_template('login.html', error=request.args['error'] if 'error' in request.args.keys() else '')

@app.route('/register')
def register():
    if 'token' in request.cookies.keys():
        return redirect('/')
    return render_template('register.html', error=request.args['error'] if 'error' in request.args.keys() else '',
                                            username_old=request.args['username_old'] if 'username_old' in request.args.keys() else '',
                                            email_old=request.args['email_old'] if 'email_old' in request.args.keys() else '')

@app.route('/logout')
def logout_endpoint():
    return logout(request.cookies['token'])

@app.route('/api/login', methods=['POST'])
def api_login():
    return login(request.form['username'], request.form['password'])

@app.route('/api/register', methods=['POST'])
def api_register():
    assert recaptcha_secret != ''

    # FIXME: Do these in JavaScript on the frontend
    if len(request.form['password']) < 3 or len(request.form['password']) > 16:
        return redirect(url_for('register', error='Password does not meet the requirements', username_old=request.form['username'], email_old=request.form['email']))

    if request.form['password'] != request.form['password_confirm']:
        return redirect(url_for('register', error='Passwords do not match', username_old=request.form['username'], email_old=request.form['email']))

    if len(request.form['username']) < 3 or len(request.form['username']) > 16:
        return redirect(url_for('register', error='Username does not meet the requirements', username_old=request.form['username'], email_old=request.form['email']))

    if database.execute('select * from accounts where username=?', [request.form['username'].lower()]).fetchone() is not None:
        return redirect(url_for('register', error='Username already taken', username_old=request.form['username'], email_old=request.form['email']))

    if database.execute('select * from accounts where email=?', [request.form['email'].lower()]).fetchone() is not None:
        return redirect(url_for('register', error='Email already registered', username_old=request.form['username'], email_old=request.form['email']))

    r = requests.get('https://www.google.com/recaptcha/api/siteverify', params={
        'secret': recaptcha_secret,
        'response': request.form['g-recaptcha-response']
    })
    if r.status_code != 200 or not r.json()['success']:
        return redirect(url_for('register', error='Verify you are not a robot', username_old=request.form['username'], email_old=request.form['email']))
    
    database.execute('insert into accounts (username, password, email) values (?, ?, ?)', [request.form['username'], request.form['password'], request.form['email']])
    database.commit()

    return login(request.form['username'], request.form['password'])

@app.route('/api/new_post', methods=['POST'])
def api_new_post():
    # Check if token is still valid
    if 'token' in request.cookies.keys() and not request.cookies['token'] in active_tokens:
        return logout(request.cookies['token'])
    
    author_id = active_tokens[request.cookies['token']]
    database.execute('insert into posts (author_id, title, content) values (?, ?, ?)', [author_id, request.form['title'], request.form['content']])
    database.commit()

    return redirect('/')

if __name__ == '__main__':
    with open('captcha_secret') as f:
        recaptcha_secret = f.readline()
    app.run(debug=True)