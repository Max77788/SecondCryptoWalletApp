from flask import Flask, render_template, url_for, flash, redirect, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mongoengine import MongoEngine
import pymongo
# from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm, SendEthForm
# from models import db, User, Wallet
from models_mongo import User
from web3 import Web3
from mnemonic import Mnemonic
from eth_account import Account
from utils.web3_funcs import wallet_generator, get_total_balance, wallet_generator, full_transaction, get_balance
import os


app = Flask(__name__)
#migrate = Migrate(app, db)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")  # Set a secret key for security purposes
app.config['MONGODB_HOST'] = os.getenv("MONGODB_URI")
"""
# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///walletuser.db'  # Configure your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# for MongoDB
app.config['MONGO_HOST'] = os.getenv("MONGODB_URI")
# app.config['MONGODB_SETTINGS'] = {{'db':'testing', 'alias':'default'}}
"""
"""
try:
  client = pymongo.MongoClient(os.getenv("MONGODB_URI"))
  
# return a friendly error if a URI error is thrown 
except pymongo.errors.ConfigurationError:
  print("An Invalid URI host error was received. Is your Atlas host name correct in your connection string?")
  sys.exit(1)
"""
  
# use a database named "myDatabase"
db = MongoEngine(app)

# use a collection named "recipes"
# my_collection = db["users"]

#db.init_app(app)

#with app.app_context():
    #db.create_all()

@app.route('/')
def hello_world():
    return redirect(url_for('login'))

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

        
        # db.session.flush() # Flush to assign ID to user without committing transaction

        """
        # Create a new Address instance for the primary address
        address = Wallet(address=primary_address, user_id=user.id, private_key=private_key, seed_phrase=mnemonic)
        db.session.add(address)
        
        try:
           db.session.commit()
        except Exception as e:
            db.session.rollback()  # Roll back the session to the state before the attempt to commit
            flash(f'Not successful validation, recheck your entry. Error log: {e}', 'danger')  
        """

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

        #if made_transaction_hash:
            #print(f"Bravissimo, the transaction went thorugh. The transaction hash number is {made_transaction_hash}", "success")
        #else:   
            #flash("Something went wrong, retry later or change input", "danger")
        

    #result = send_ethereum_function(user_id, to_address, float(amount_eth), int(gas_price_gwei))
    """
    if result['success']:
        return jsonify({'status': 'success', 'tx_hash': result['tx_hash']})
    else:
        return jsonify({'status': 'error', 'message': result['message']}), 400
    """
    return render_template('send.html', title='Send', form=form)

# for generation
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
    address = Wallet(address=new_address, user_id=user.id, seed_phrase=mnemonic, private_key=private_key_hex)
    db.session.add(address)
    db.session.commit()
    
    return {'success': True}


# tests
@app.route('/test_db')
def test_db():
    try:
        user_count = User.query.count()
        return f'There are {user_count} users in the database.'
    except Exception as e:
        return f'Database connection failed: {str(e)}'





if __name__ == '__main__':
    app.run(debug=True)
