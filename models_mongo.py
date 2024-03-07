from mongoengine import Document, StringField, ReferenceField, ListField, EmailField, CASCADE, connect, disconnect

# disconnect()
 
# connect('crypto_users', host='your_mongodb_uri', alias='server')

class User(Document):
    email = EmailField(required=True, unique=True)
    password_hash = StringField(required=True, max_length=128)
    private_key = StringField(required=True, max_length=256)
    primary_seed_phrase = StringField(required=True, max_length=512)
    primary_address = StringField(required=True, max_length=120)
    # MongoEngine does not use 'relationship'. Use ReferenceField or ListField for references.
    
    # off for now

    """
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    """