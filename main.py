from flask import Flask, render_template, redirect, flash, wrappers, url_for, session, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired, Email, Length, EqualTo
import sqlite3
from passlib.hash import sha256_crypt
import random
import math
from flask_mail import Mail
from flask_mail import Message
import os
import dotenv
from werkzeug.datastructures import ImmutableOrderedMultiDict
#from requests import request
import time
import requests
import stripe



dotenv.load_dotenv()
secret_key= os.getenv('SECRET_KEY')

app= Flask(__name__)

my_email= os.getenv('EMAIL')
my_pwd= os.getenv('PASSWORD')
app.config['SECRET_KEY']= secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:''@localhost/invite+'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False
app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 465,
    MAIL_USE_TLS = False,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = my_email,
    MAIL_PASSWORD = my_pwd
))

Bootstrap(app)
db = SQLAlchemy(app)
mail= Mail(app)

stripe_keys = {
    "secret_key": os.getenv('STRIPE_SECRET_KEY'),
    "publishable_key": os.getenv('STRIPE_PUBLISHABLE_KEY'),
}
stripe.api_key = stripe_keys["secret_key"]

class users(db.Model):
    Name = db.Column(db.String(80))
    Discord_username = db.Column(db.String(100), primary_key=True, unique=True, nullable=False)
    Email = db.Column(db.String(120), unique=True, nullable=False)
    Password= db.Column(db.String(80))
    Tcoins= db.Column(db.Integer, default=0)
    Rcoins= db.Column(db.Integer, default=0)
    OTP= db.Column(db.String(10), default=None)

    def __init__(self, Name, Discord_username, Email, Password, Tcoins, Rcoins):
        self.Name= Name
        self.Discord_username= Discord_username
        self.Email= Email
        self.Password= Password
        self.Tcoins= Tcoins
        self.Rcoins= Rcoins


class payments(db.Model):
    payer_email= db.Column(db.String(120))
    unix= db.Column(db.Time)
    payment_date= db.Column(db.String(80))
    username= db.Column(db.String(100), primary_key= True)
    last_name = db.Column(db.String(100))
    payment_gross = db.Column(db.Integer)
    payment_fee = db.Column(db.Integer)
    payment_net = db.Column(db.Integer)
    payment_status = db.Column(db.String(80))


    def __init__(self, payer_email, unix, payment_date, username, last_name, payment_gross, payment_fee, payment_net, payment_status):
        self.payer_email= payer_email
        self.unix= unix
        self.payment_date= payment_date
        self.username= username
        self.last_name= last_name
        self.payment_gross= payment_gross
        self.payment_fee= payment_fee
        self.payment_net= payment_net
        self.payment_status= payment_status



@app.route('/')
def index():
    return render_template('home.html')


class signup_form(FlaskForm):
    Name= StringField('Name', validators=[InputRequired('Name is required')])
    Discord_username= StringField('Discord Username', validators=[InputRequired('Discord_username is required')])
    Email= StringField('Email', validators=[InputRequired('Email is required'), Email(message='Invalid email')])
    Password= PasswordField('Password', validators=[InputRequired('Password is required'), Length(min=5, max=80)])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form= signup_form()

    if form.validate_on_submit():
        password= sha256_crypt.encrypt(str(form.Password.data))
        New_user= users(Name=form.Name.data, Discord_username=form.Discord_username.data, Email=form.Email.data, Password=password, Tcoins=0, Rcoins=0)
        exists = db.session.query(users).filter_by(Discord_username= New_user.Discord_username,).scalar() is not None
        exists1 = db.session.query(users).filter_by(Email= New_user.Email,).scalar() is not None

        if exists or exists1:
            flash('User already exist!!!')
            return redirect(url_for('signup'))

        else:
            db.session.add(New_user)
            db.session.commit()
            flash('You have been registered. Login here')
            return redirect(url_for('login'))

    return render_template('signup.html', form=form)


class login_form(FlaskForm):
    Discord_username= StringField('Discord Username', validators=[InputRequired()])
    Password= PasswordField('Password', validators=[InputRequired(), Length(min=5,max=80)])


@app.route('/login', methods=['GET', 'POST'])
def login():
    form= login_form()
    if form.validate_on_submit():
        user= db.session.query(users).filter_by(Discord_username= form.Discord_username.data).scalar()
        if user:
            if sha256_crypt.verify(form.Password.data, user.Password):
                session['logged_in']= True
                session['Discord_username']= user.Discord_username
                return redirect(url_for('profile'))
            else:
                flash('Invalid credentials. Try again')
                return redirect(url_for('login'))
        else:
            flash('Invalid credentials. Try again')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap

@app.route('/profile')
@login_required
def profile():
    user = db.session.query(users).filter_by(Discord_username=session['Discord_username']).scalar()

    return render_template('profile.html', user= user)


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


class forgot_password_form(FlaskForm):
    Email= StringField('Email', validators=[Email(message='Invalid email'), InputRequired(message='This field is required')])
    Discord_username= StringField('Discord_username', validators=[InputRequired(message='This field is required')])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form= forgot_password_form()

    if form.validate_on_submit():
        user= db.session.query(users).filter_by(Discord_username= form.Discord_username.data).scalar()
        if user:
            user_email= db.session.query(users).filter_by(Email= form.Email.data).scalar()
            if user_email:
                r_email = [form.Email.data, ]
                string = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
                OTP1 = ""
                length = len(string)
                for i in range(6):
                    OTP1 += string[math.floor(random.random() * length)]
                user_otp= db.session.query(users).filter_by(Email= form.Email.data).scalar()
                user_otp.OTP= OTP1
                db.session.commit()
                session['logged_in'] = True
                session['Discord_username'] = form.Discord_username.data
                session['Email'] = form.Email.data
                msg = Message(OTP1, sender=app.config['MAIL_USERNAME'], recipients=r_email)
                mail.send(msg)
                return redirect('/enter_otp')
            else:
                flash('Invalid credentials. Try again')
                return redirect('/forgot_password')
        else:
            flash('No user found associated with given credentials.')
            return redirect('/forgot_password')
    return render_template('forgot_password.html', form=form)


def create_otp_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Invalid request")
            return redirect(url_for('forgot_password'))

    return wrap

class enter_otp_form(FlaskForm):
    OTP= StringField('OTP', validators=[InputRequired('You need to input the OTP!!!')])


@app.route('/enter_otp', methods=['GET', 'POST'])
@create_otp_required
def enter_otp():
    form= enter_otp_form()
    if form.validate_on_submit():
        d_username= session['Discord_username']
        user= db.session.query(users).filter_by(Discord_username= d_username).scalar()
        otp= user.OTP
        g_otp= form.OTP.data
        if g_otp==otp:
            user.OTP= None
            db.session.commit()
            flash('Reset your password')
            return redirect('/new_password')
        else:
            user.OTP= None
            db.session.commit()
            session.clear()
            flash('Invalid OTP')
            return redirect('/forgot_password')

    return render_template('enter_otp.html', form=form)


class new_password_form(FlaskForm):
    New_password= PasswordField('Enter new password', validators=[InputRequired('This field cannot be empty')])
    Confirm_password= PasswordField('Confirm new password', validators=[EqualTo('New_password', message='passwords must match'), InputRequired('This field cannot be empty!')])


@app.route('/new_password', methods=['GET', 'POST'])
@create_otp_required
def new_password():
    form= new_password_form()
    if form.validate_on_submit():
        d_username= session['Discord_username']
        user= db.session.query(users).filter_by(Discord_username= d_username).scalar()
        user.Password= sha256_crypt.encrypt(str(form.New_password.data))
        db.session.commit()
        session.clear()
        flash('Your password has been changed.')
        return redirect('/login')


    return render_template('/new_password_form.html', form=form)


@app.route('/purchase/<amount>/<price>', methods=['GET', 'POST'])
@login_required
def purchase(amount,price):
    coins_info={
        'no_of_coins': int(amount),
        'price': int(price)
    }
    return render_template('purchase.html',key=stripe_keys['publishable_key'], coin= coins_info)




@app.route('/success')
def success():
    flash('Success')
    return redirect('/')


@app.route("/cancelled")
def cancelled():
    flash('Cancelled')
    return redirect('/')


@app.route('/checkout/<coins>/<price>', methods=['POST'])
@login_required
def checkout(price,coins):
    amount= price




    customer = stripe.Customer.create(
        email=request.form.get('Email'),
        source= request.form['stripeToken'],
        name='not_needed',
        address={
            'line1': '510 Townsend St',
            'postal_code': '98140',
            'city': 'San francisco',
            'state': 'CA',
            'country': 'US',
        },
    )

    stripe.Charge.create(
        customer=customer.id,
        amount=amount,
        currency='usd',
        description='Flask Charge'
    )
    d_username = session['Discord_username']
    user = db.session.query(users).filter_by(Discord_username=d_username).scalar()
    user.Tcoins= user.Tcoins + int(coins)
    user.Rcoins= user.Rcoins + int(coins)
    db.session.commit()

    return render_template('checkout.html', amount=amount)



@app.errorhandler(500)
def internal_server_error(error):

    return render_template('500.html', error=error), 500

@app.errorhandler(stripe.error.CardError)
def stripe_card_error(e):


    #record_payment_error('stripe-card-error')
    return render_template('500.html', e=e), 200



@app.errorhandler(stripe.error.RateLimitError)
def stripe_ratelimit_error(e):

    #record_payment_error('stripe-rate-limit-error')
    return render_template('500.html', e=e), 200


@app.errorhandler(stripe.error.InvalidRequestError)
def stripe_invalid_request_error(e):

    #record_payment_error('stripe-invalid-request-error')
    return render_template('500.html', e=e), 200


@app.errorhandler(stripe.error.AuthenticationError)
def stripe_authentication_error(e):

    #record_payment_error('stripe-authentication-error')
    return render_template('500.html', e=e), 200


@app.errorhandler(stripe.error.APIConnectionError)
def stripe_api_connection_error(e):

    #record_payment_error('stripe-api-connection-error')
    return render_template('500.html', e=e), 200


@app.errorhandler(stripe.error.StripeError)
def stripe_generic_error(e):
    #record_payment_error('general-stripe-error')
    return render_template('500.html', e=e), 200

if __name__== '__main__':
    app.run(debug=True)

