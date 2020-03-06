from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
from flask import render_template

import pprint
import os

# This code originally from https://github.com/lepture/flask-oauthlib/blob/master/example/github.py
# Edited by P. Conrad for SPIS 2016 to add getting Client Id and Secret from
# environment variables, so that this will work on Heroku.
# Edited by S. Adams for Designing Software for the Web to add comments and remove flash messaging

app = Flask(__name__)

app.debug = True #Change this to False for production

app.secret_key = os.environ['SECRET_KEY'] 
oauth = OAuth(app)

#Set up Github as the OAuth provider
github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'], 
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],
    request_token_params={'scope': 'user:email'}, #request read-only access to the user's email.  For a list of possible scopes, see developer.github.com/apps/building-oauth-apps/scopes-for-oauth-apps
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',  
    authorize_url='https://github.com/login/oauth/authorize' #URL for github's OAuth login
)


@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

userisvalidarray = []
userisnotvalidarray = []

@app.route('/')
def home():
    secretd = ''
    secretd2 = ''
    global userisvalidarray
    global userisnotvalidarray
    if 'user_data' in session and session['user_data']['public_repos'] == 17:
        user_check = True#print.pformat(session['user_data'])#format the user data nicely
        userisvalidarray.append(session['user_data']['login'])
        if session['user_data']['login'] == 'LucaCC':
            for x in userisvalidarray:
                try:
                    secretd.index(x) #checking for error
                except Exception as inst:
                    secretd += x + ' '
            for y in userisnotvalidarray:
                try:
                    secretd2.index(y)
                except Exception as inst:
                    secretd2 += y + ' '
            admin_check = 'Admin Privileges'
        else:
            secretd = ''
            secretd2 = ''
            admin_check = ''
    else:
        user_check = False
        secretd = ''
        secretd2 = ''
        admin_check = ''
        if 'user_data' in session:
            userisnotvalidarray.append(session['user_data']['login'])
    return render_template('home.html',valid_user=user_check, admin_secret_data=secretd, admin_secret_data2=secretd2, Admin=admin_check)

@app.route('/login')
def login():   
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https'))

@app.route('/logout')
def logout():
    session.clear()
    return render_template('msg.html', msg='You were logged out')

@app.route('/login/authorized')#the route should match the callback URL registered with the OAuth provider
def authorized():
    response = github.authorized_response()
    if response is None:
        session.clear()
        msg = 'Access denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'] + ' full=' + pprint.pformat(request.args)      
    else:
        try:
            #save user data and set log in message
            session['github_token'] = (response['access_token'], '')
            session['user_data'] = github.get('user').data
            msg = 'You were successfully logged in as ' + session['user_data']['login']
        except Exception as inst:
            #clear the session and give error message
            session.clear()
            print(inst)
            msg = 'Unable to login. Please Try again'
    return render_template('msg.html', msg=msg)



@github.tokengetter
def get_github_oauth_token():
    return session['github_token']


if __name__ == '__main__':
    app.run()
