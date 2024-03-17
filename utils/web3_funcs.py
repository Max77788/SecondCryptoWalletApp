from mnemonic import Mnemonic
from eth_account import Account
from web3 import Web3
import os
from flask import session
# from models import db, User, Wallet
from models_mongo import User
from eth_utils import to_checksum_address
import bip32utils
from flask import flash, redirect, url_for

def wallet_generator():
    # Generate a mnemonic
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=128)

    # Generate a seed from the mnemonic
    seed = mnemo.to_seed(mnemonic, passphrase="")

    # Derive the BIP44 path for Ethereum
    # m / purpose' / coin_type' / account' / change / address_index
    # For Ethereum, coin_type is 60 (see SLIP-0044), account is typically 0, change is 0, and address_index is 0 for the first address
    path = "m/44'/60'/0'/0/0"

    # Use bip32utils or another library to derive the key from the seed and path
    # This requires converting the seed to a BIP32 root key and then deriving the path
    root_key = bip32utils.BIP32Key.fromEntropy(seed)
    derived_key = root_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(
        60 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)

    # Extract the private key from the derived key
    private_key_hex = derived_key.PrivateKey().hex()

    # Create an Ethereum account from the private key
    account = Account.privateKeyToAccount(private_key_hex)
    primary_address = to_checksum_address(account.address)

    return mnemonic, private_key_hex, primary_address

def get_balance():
    user_id = session.get('user_id')  # Assuming user_id is stored in session upon login
    if not user_id:
        return "User not logged in", 403  # Or handle as appropriate

    user = User.objects(id=user_id).first()
    if not user:
        return "User not found", 404  # Or handle as appropriate

    web3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_PROJECT_URL")))  # Example provider

    # Convert the address to a checksum address
    checksum_address = to_checksum_address(user.primary_address)
    
    # Get the balance in Wei
    balance_wei = web3.eth.getBalance(checksum_address)
    
    # Convert the balance from Wei to Ether
    balance_eth = web3.fromWei(balance_wei, 'ether')
    
    return balance_eth

# Util function to get the total balance of the wallet
def get_total_balance():
    """
    Get the total balance of the wallets pertained to the account, summing up the balances of all wallets
    Args: none
    Returns: total_balance - float, the amount of eth stored in account
    """
    user_id = session.get('user_id')  # Assuming user_id is stored in session upon login
    if not user_id:
        return "User not logged in", 403  # Or handle as appropriate

    user = User.query.get(user_id)
    if not user:
        return "User not found", 404  # Or handle as appropriate

    web3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_PROJECT_URL")))  # Example provider


    total_balance = sum(web3.eth.get_balance(wallet.address) for wallet in user.wallets)
    
    # Convert balance to eth
    total_balance_eth = web3.fromWei(total_balance, 'ether')

    # Convert total balance to Ether
    return total_balance_eth


"""
def generate_new_address_for_user():
    user_id = session.get('user_id')  # Assuming the user's ID is stored in session
    if not user_id:
        return "User not logged in", 403

    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    # Use the user's seed_phrase to create a Wallet instance
    wallet = Wallet(user.seed_phrase)
    # Derive a new address
    new_address_index = len(user.addresses)  # Assuming user.addresses is a list of Address objects
    new_address = wallet.derive_account("eth", account=0, change=False)
    print("\n\n\n", new_address, "\n\n\n")
    private_key = new_address[0]
    public_key = new_address[1]

    web3 = Web3()
    

    pub_key_bytes = public_key[1:]  # Remove the prefix byte
    priv_key_bytes = private_key[1:]
    hashed_private_key_hex = keccak(priv_key_bytes).hex()
    print("Hashed private key: ", hashed_private_key_hex)
    hashed_public_key = keccak(pub_key_bytes)  # Hash the public key
    eth_address = to_checksum_address(hashed_public_key[-20:])  # Take the last 20 bytes and checksum

    # Save the new address in the database
    address = Address(address=eth_address, user_id=user_id, private_key=hashed_private_key_hex)  # Remove the prefix byte
    db.session.add(address)
    db.session.commit()

    return eth_address
"""

def full_transaction(to_address, user_id, amount_eth, gas_price_gwei):
    user = User.objects(id=user_id).first()
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('send_ethereum'))

    private_key = user.private_key  # Ensure secure management of private keys

    # Setup Web3
    web3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_PROJECT_URL")))
    
    # Convert amount from Ether to Wei and set up transaction parameters
    amount_wei = web3.toWei(amount_eth, 'ether')
    nonce = web3.eth.getTransactionCount(user.primary_address)
    gas_price = web3.toWei(gas_price_gwei, 'gwei')
    gas_limit = 21000  # Adjust based on transaction complexity

    tx = {
        'nonce': nonce,
        'to': to_address,
        'value': amount_wei,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'chainId': web3.eth.chain_id
    }
    
    # Sign and send transaction

    try:
        signed_tx = web3.eth.account.signTransaction(tx, private_key)
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if tx_receipt.status == 1:
            flash(f"Transaction successful with hash: {web3.toHex(tx_hash)}", "success")
        else:
            flash("Transaction failed.", "danger")
    except Exception as e:
        error_message = str(e)
        flash(f"Oops, an error occurred: {error_message}", "danger")
    
    return redirect(url_for('send_ethereum'))
        