from flask import Flask, render_template, url_for, flash, redirect, request, session, jsonify
#from flask_sqlalchemy import SQLAlchemy
#from flask_migrate import Migrate
from flask_mongoengine import MongoEngine
import pymongo
# from pymongo.server_api import ServerApi
# from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm, SendEthForm
# from models import db, User, Wallet
from models_mongo import User
from utils.web3_funcs import wallet_generator, wallet_generator, full_transaction, get_balance
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")  # Set a secret key for security purposes
app.config['MONGODB_HOST'] = os.getenv("MONGODB_URI")
  
# use a database named "myDatabase"
db = MongoEngine(app)

@app.route('/')
def hello_world():
    return "Hello World"

@app.route('/main')
def main_():
    return 'You are on the main page!'

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match. Please try again.', 'danger')
    if request.method == 'POST' and form.validate():
        
        # Generate the wallet and retrieve its data
        mnemonic, private_key, primary_address = wallet_generator()
        # print(mnemonic, private_key, primary_address) # debugging line

        # Hash the password
        #hashed_password = generate_password_hash(form.password.data)

        # Create a new user with wallet details
        user = User(email=form.email.data,
                    password_hash=form.password.data,
                    private_key=private_key,
                    primary_seed_phrase=mnemonic,
                    primary_address=primary_address)
        

        try:
            user.save()
        except Exception as e: 
            flash(f'Not successful registration, recheck your entry. Error log in console', 'danger') 
            print(e) 

        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
        # Use MongoEngine's syntax for querying the database
        user = User.objects(email=form.email.data).first()
        if user and user.password_hash == form.password.data:
            # Login the user by adding user info to the session or another method of your choice
            session['user_id'] = str(user.id)
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to a dashboard or home page
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
  return render_template('login.html', title='Login', form=form)

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    print("user id", user_id, " debugging line")  # debugging line
    if not user_id:
        # Redirect to login if no user is in session
        return redirect(url_for('login'))

    # Use MongoEngine's syntax to query the user by id
    # Assuming `user_id` stored in session is a string representation of ObjectId
    from bson import ObjectId
    if not ObjectId.is_valid(user_id):  # Validate it to ensure it's a valid ObjectId string
        return "Invalid user ID format", 400

    user = User.objects(id=ObjectId(user_id)).first()
    if not user:
        # Handle case where user is not found
        return "User not found", 404
    
    """
    wallets = user.wallets
    if wallets:
        latest_address = wallets[-1].address  # Assuming addresses are ordered by creation time
    else:
        latest_address = "No addresses found"
    """

    # Assuming you have a function to get balance for an address
    # total_balance = get_total_balance()
    total_balance = get_balance()
    
    address_to_display = user.primary_address

    seed_phrase = user.primary_seed_phrase

    user_email = user.email

    return render_template('dashboard.html', latest_address=address_to_display, total_balance=total_balance, seed_phrase=seed_phrase, user_email=user_email)


@app.route('/send_ethereum', methods=['POST', 'GET'])
def send_ethereum():
    form = SendEthForm()
    if form.validate_on_submit():
        user_id = session.get('user_id')
        to_address = request.form.get('to_address')
        amount_eth = request.form.get('amount_eth')
        gas_price_gwei = request.form.get('gas_price_gwei')
        
        made_transaction_hash = full_transaction(to_address, user_id, amount_eth, gas_price_gwei)

    return render_template('send.html', title='Send', form=form)

# for generation (deprecated)
"""
@app.route('/generate_new_wallet', methods=['POST', 'GET'])
def generate_new_wallet():
    user_id = session.get('user_id')
    if not user_id:
        return {'success': False}

    user = User.query.get(user_id)
    if not user:
        return {'success': False}

    # Assuming you have a function to generate a new address from the seed phrase
    mnemonic, private_key_hex, new_address = wallet_generator()
    print("New Address ", new_address, " debugging line")

    # Save the new address in the database
    # address = Wallet(address=new_address, user_id=user.id, seed_phrase=mnemonic, private_key=private_key_hex)
    # db.session.add(address)
    # db.session.commit()
    
    return {'success': True}
"""




if __name__ == '__main__':
    app.run(debug=True)
