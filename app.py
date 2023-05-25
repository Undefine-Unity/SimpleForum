from flask import *
from werkzeug.utils import secure_filename

from dataclasses import dataclass
import datetime
import json
import os
import random
import requests
import string
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = '4kr/:/S>tEayrQu2(5waOW{A>]H56='

database = sqlite3.connect('database.db', check_same_thread=False)

active_tokens: dict[str, int] = {}

recaptcha_secret = ''

PROFILE_PICTURE_DIRECTORY = 'static/storage/profilePictures'

def generate_random_token():
    token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    while token in active_tokens.keys():
        token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))

    return token

def login(username_in: str, password_in: str) -> Response:
    accountTuple = database.execute('select * from accounts where upper(username)=upper(?)', [username_in]).fetchone()
    if accountTuple is None:
        return redirect(url_for('login_endpoint', error='Account not found'))

    id, username, password, email, profile_picture = accountTuple

    if password_in != password:
        return redirect(url_for('login_endpoint', error='Invalid password'))
        
    if id in active_tokens.values():
        return redirect(url_for('login_endpoint', error='User already logged in'))
        
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

@dataclass
class DisplayPostInfo:
    title: str
    content: str
    author: str
    author_profile_picture: str

@app.route('/')
def main():
    # Check if token is still valid
    if 'token' in request.cookies.keys() and not request.cookies['token'] in active_tokens:
        return logout(request.cookies['token'])
    
    posts = database.execute('select * from posts').fetchall()
    postInfos = []
    for post in posts:
        id, author_id, title, content = post
        author_username, author_profile_picture = database.execute('select username, profile_picture from accounts where id=?', [author_id]).fetchone()
        postInfos.append(DisplayPostInfo(title, content, author_username, author_profile_picture if author_profile_picture != None else 'static/img/no_profile_picture.jpg'))
    
    username = ''
    profile_picture = ''
    if 'token' in request.cookies.keys():
        username, profile_picture = database.execute('select username, profile_picture from accounts where id=?', [active_tokens[request.cookies['token']]]).fetchone()
        
    return render_template('main.html', posts=postInfos, username=username, profile_picture=profile_picture)

@app.route('/tos')
def tos():
    return 'TOS might go here'

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
                                            email_old=request.args['email_old'] if 'email_old' in request.args.keys() else '',
                                            tos_old=request.args['tos_old'] if 'tos_old' in request.args.keys() else '')

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
        return redirect(url_for('register', error='Password does not meet the requirements', username_old=request.form['username'], email_old=request.form['email'], tos_old=request.form['tos']))

    if request.form['password'] != request.form['password_confirm']:
        return redirect(url_for('register', error='Passwords do not match', username_old=request.form['username'], email_old=request.form['email'], tos_old=request.form['tos']))

    if len(request.form['username']) < 3 or len(request.form['username']) > 16:
        return redirect(url_for('register', error='Username does not meet the requirements', username_old=request.form['username'], email_old=request.form['email'], tos_old=request.form['tos']))

    if 'tos' not in request.form.keys() or request.form['tos'] == False:
        return redirect(url_for('register', error='Accept the terms of service', username_old=request.form['username'], email_old=request.form['email'], tos_old=request.form['tos']))

    if database.execute('select * from accounts where username=?', [request.form['username'].lower()]).fetchone() is not None:
        return redirect(url_for('register', error='Username already taken', username_old=request.form['username'], email_old=request.form['email'], tos_old=request.form['tos']))

    if database.execute('select * from accounts where email=?', [request.form['email'].lower()]).fetchone() is not None:
        return redirect(url_for('register', error='Email already registered', username_old=request.form['username'], email_old=request.form['email'], tos_old=request.form['tos']))

    r = requests.get('https://www.google.com/recaptcha/api/siteverify', params={
        'secret': recaptcha_secret,
        'response': request.form['g-recaptcha-response']
    })
    if r.status_code != 200 or not r.json()['success']:
        return redirect(url_for('register', error='Verify you are not a robot', username_old=request.form['username'], email_old=request.form['email']))
    
    database.execute('insert into accounts (username, password, email) values (?, ?, ?)', [request.form['username'], request.form['password'], request.form['email']])
    database.commit()

    return login(request.form['username'], request.form['password'])

@app.route('/api/change_profile_picture', methods=['POST'])
def api_change_profile_picture():
    uploadedImage = request.files['profile_picture']
    imageFilename = os.path.join(PROFILE_PICTURE_DIRECTORY, secure_filename(uploadedImage.filename))
    uploadedImage.save(imageFilename)

    database.execute('update accounts set profile_picture = ? where id=?', [imageFilename, active_tokens[request.cookies['token']]])
    database.commit()

    return redirect('/')

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