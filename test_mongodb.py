from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# Replace the placeholder with your Atlas connection string
uri = "mongodb+srv://crypto_app:1234@myfauserscluster0.ve3bgep.mongodb.net/crypto_users"

# Set the Stable API version when creating a new client
client = MongoClient(uri)
                          
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)