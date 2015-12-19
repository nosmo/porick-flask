import bcrypt
import re
import smtplib

from email.mime.text import MIMEText

from flask import request
from sqlalchemy import or_

from models import User
from porick import db
from settings import PASSWORD_SALT, SERVER_DOMAIN, PASSWORD_RESET_REQUEST_EXPIRY, SMTP_REPLYTO, SMTP_SERVER



reset_password_text = """
Hi,

A password reset has been requested for your account on Porick.

To reset your password, please click the link below.

http://{server_domain}/reset_password?key={key}

This URL will be valid for {validity}.

If you did not initiate this password reset then you may simply disregard this email.

Cheers,
Porick

"""

def send_reset_password_email(user_email, key):
    validity = '{} hour{}'.format(PASSWORD_RESET_REQUEST_EXPIRY, '' if PASSWORD_RESET_REQUEST_EXPIRY == 1 else 's')
    msg = MIMEText(reset_password_text.format(server_domain=SERVER_DOMAIN, key=key, validity=validity))
    msg['To'] = user_email
    msg['From'] = SMTP_REPLYTO
    msg['Subject'] = 'Porick password reset request'
    s = smtplib.SMTP(SMTP_SERVER)
    s.sendmail(
        SMTP_REPLYTO, [user_email],
        msg.as_string()
    )
    s.quit()

def current_page(default=1):
    try:
        return int(request.args.get('page', default))
    except ValueError:
        return default


def hash_password(plaintext):
    return bcrypt.hashpw(plaintext.encode('utf-8'), PASSWORD_SALT)

def authenticate(username, password):
    user = User.query.filter(User.username == username).first()
    if not user:
        return False
    elif hash_password(password) == user.password:
        return user
    else:
        return False


def validate_signup(username, password, password_confirm, email):
    valid_password = validate_password(password, password_confirm)
    if not valid_password['status']:
        return valid_password

    if not (username and password and password_confirm and email):
        return {'status': False,
                'msg': 'Please fill in all the required fields.'}

    email_regex = re.compile('''[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%'''
                             '''&'*+/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*'''
                             '''[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?''')
    if not email_regex.match(email):
        return {'status': False,
                'msg': 'Please enter a valid email address.'}

    username_regex = re.compile('''^[a-zA-Z0-9_]*$''')
    if not username_regex.match(username):
        return {'status': False,
                'msg': 'Your username may consist only of'
                       ' alphanumeric characters and underscores.'}

    return {'status': True}


def validate_password(password, password_confirm):
    if not len(password) >= 8:
        return {'status': False,
                'msg': 'Your password must be at least 8 characters long.'}

    if not password == password_confirm:
        return {'status': False,
                'msg': 'Your password did not match in both fields.'}
    return {'status': True}


def create_user(username, password, email):
    conflicts = User.query.filter(or_(User.email == email,
                                      User.username == username)).first()
    if conflicts:
        if conflicts.email == email:
            raise NameError('Sorry! That email already exists in the system.')
        elif conflicts.username == username:
            raise NameError('Sorry! That username is already taken.')

    hashed_pass = bcrypt.hashpw(password.encode('utf-8'), PASSWORD_SALT)
    new_user = User()
    new_user.username = username
    new_user.password = hashed_pass
    new_user.email = email

    db.session.add(new_user)
    db.session.commit()
    return True
