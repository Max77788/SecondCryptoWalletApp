from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm
from models import db, User, Wallet
from web3 import Web3
from mnemonic import Mnemonic
from eth_account import Account
from utils.web3_funcs import wallet_generator, get_total_balance, wallet_generator
import os


app = Flask(__name__)
migrate = Migrate(app, db)
# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///walletuser.db'  # Configure your database URI
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")  # Set a secret key for security purposes
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def hello_world():
    return 'Hello, World!'

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
        hashed_password = generate_password_hash(form.password.data)

        # Create a new user with wallet details
        user = User(email=form.email.data,
                    password_hash=hashed_password,
                    private_key=private_key,
                    primary_seed_phrase=mnemonic,
                    primary_address=primary_address)
        
        try:
            db.session.add(user)
        except Exception as e:
            db.session.rollback()  # Roll back the session to the state before the attempt to commit
            flash(f'Not successful validation, recheck your entry. Error log in console', 'danger') 
            print(e) 

        
        db.session.flush() # Flush to assign ID to user without committing transaction

        # Create a new Address instance for the primary address
        address = Wallet(address=primary_address, user_id=user.id, private_key=private_key, seed_phrase=mnemonic)
        db.session.add(address)
        
        try:
           db.session.commit()
        except Exception as e:
            db.session.rollback()  # Roll back the session to the state before the attempt to commit
            flash(f'Not successful validation, recheck your entry. Error log: {e}', 'danger')  
        

        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            # Login the user by adding user info to the session or another method of your choice
            session['user_id'] = user.id
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to a dashboard or home page
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
  return render_template('login.html', title='Login', form=form)

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    print("user id", user_id, " debugging line") # debugging line
    if not user_id:
        # Redirect to login if no user is in session
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        # Handle case where user is not found
        return "User not found", 404

    wallets = user.wallets
    if wallets:
        latest_address = wallets[-1].address  # Assuming addresses are ordered by creation time
    else:
        latest_address = "No addresses found"

    # Assuming you have a function to get balance for an address
    total_balance = get_total_balance()
    
    seed_phrase = user.primary_seed_phrase

    return render_template('dashboard.html', latest_address=latest_address, total_balance=total_balance, seed_phrase=seed_phrase)


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

@app.route('/send_transaction', methods=['POST', 'GET'])
def send_ethereum(user_id, to_address, amount_eth, gas_price_gwei):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    # Assuming the user's wallet information includes a private key
    private_key = user.private_key  # Make sure this is securely managed

    # Setup Web3
    web3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_PROJECT_URL")))
    
    # Convert amount from Ether to Wei
    amount_wei = web3.toWei(amount_eth, 'ether')
    
    # Build Transaction
    nonce = web3.eth.getTransactionCount(user.eth_address)
    gas_price = web3.toWei(gas_price_gwei, 'gwei')
    gas_limit = 21000  # Assuming a simple transfer, adjust based on transaction complexity
    
    tx = {
        'nonce': nonce,
        'to': to_address,
        'value': amount_wei,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'chainId': 1  # Mainnet, adjust for testnets
    }
    
    # Sign Transaction
    signed_tx = web3.eth.account.signTransaction(tx, private_key)
    
    # Send Transaction
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    
    return web3.toHex(tx_hash)


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
