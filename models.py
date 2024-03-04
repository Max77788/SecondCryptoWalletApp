from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    private_key = db.Column(db.String(256), nullable=False)
    primary_seed_phrase = db.Column(db.String(512), nullable=False)
    primary_address = db.Column(db.String(120), nullable=False)
    wallets = db.relationship('Wallet', backref='user')  # One-to-many relationship for storing multiple addresses

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(120), nullable=False)  # Wallet address
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to link address to user
    private_key = db.Column(db.String(120), nullable=False)  # Address's private key
    seed_phrase = db.Column(db.String(200), nullable=False)