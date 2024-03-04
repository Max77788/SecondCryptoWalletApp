from mnemonic import Mnemonic
import bip32utils
from eth_account import Account
from eth_utils import to_checksum_address


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
    private_key_hex = "0x" + private_key_hex

    # Create an Ethereum account from the private key
    account = Account.privateKeyToAccount(private_key_hex)
    primary_address = to_checksum_address(account.address)

    return mnemonic, private_key_hex, primary_address

mnemonic, private_key_hex, primary_address = wallet_generator()

print("\n", mnemonic,"\n", private_key_hex,"\n", primary_address)