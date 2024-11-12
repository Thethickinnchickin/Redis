import hashlib
import os
from werkzeug.security import generate_password_hash, check_password_hash
import uuid  # For generating verification tokens

class User:
    # Assuming `mongo` is set correctly
    mongo = None  

    @classmethod
    def set_mongo(cls, mongo_instance):
        cls.mongo = mongo_instance

    def __init__(self, username, password=None, password_hash=None, salt=None, email=None, verification_token=None, is_verified=False):
        self.username = username
        self.email = email  # Add email attribute
        self.verification_token = verification_token  # Store the verification token
        self.is_verified = is_verified  # Store verification status
        
        if password:
            self.salt = os.urandom(16)  # Generate a random salt
            self.password_hash = self.generate_scrypt_hash(password)
        else:
            self.password_hash = password_hash  # Use the provided password hash
            self.salt = salt  # Use the provided salt

    def generate_scrypt_hash(self, password):
        """Generate scrypt hash for the password."""
        return hashlib.scrypt(password.encode(), salt=self.salt, n=16384, r=8, p=1).hex()

    def save_to_db(self):
        """Save the user to MongoDB. If the user already exists, update the existing record."""
        user_data = {
            "username": self.username,
            "password_hash": self.password_hash,
            "salt": self.salt.hex(),  # Store the salt in hexadecimal
            "email": self.email,
            "verification_token": self.verification_token,
            "is_verified": self.is_verified
        }
        
        # If the user exists, update their information, otherwise insert a new user
        existing_user = self.mongo.db.users.find_one({"username": self.username})
        if existing_user:
            self.mongo.db.users.update_one(
                {"username": self.username}, 
                {"$set": user_data}
            )
        else:
            self.mongo.db.users.insert_one(user_data)


    @classmethod
    def find_by_username(cls, username):
        """Find a user by username."""
        if cls.mongo is None:
            raise ValueError("Mongo instance not set. Call User.set_mongo() in app.py.")
        user_data = cls.mongo.db.users.find_one({"username": username})
        if user_data:
            salt = bytes.fromhex(user_data["salt"])  # Retrieve salt from database
            user = User(username=user_data["username"], email=user_data["email"], salt=salt, is_verified=user_data["is_verified"])
            user.password_hash = user_data["password_hash"]  # Set password_hash separately
            user.verification_token = user_data["verification_token"]  # Set verification token
            return user
        return None

    @classmethod
    def find_by_verification_token(cls, token):
        """Find a user by their verification token."""
        if cls.mongo is None:
            raise ValueError("Mongo instance not set. Call User.set_mongo() in app.py.")
        user_data = cls.mongo.db.users.find_one({"verification_token": token})
        if user_data:
            salt = bytes.fromhex(user_data["salt"])  # Retrieve salt from database
            user = User(username=user_data["username"], email=user_data["email"], salt=salt, is_verified=user_data["is_verified"])
            user.password_hash = user_data["password_hash"]  # Set password_hash separately
            user.verification_token = user_data["verification_token"]  # Set verification token
            return user
        return None

    def check_password(self, password):
        """Check the password hash matches using scrypt."""
        stored_hash = bytes.fromhex(self.password_hash)
        # Compute the scrypt hash of the entered password and compare it with the stored hash
        hashed_password = hashlib.scrypt(password.encode(), salt=self.salt, n=16384, r=8, p=1)
        return hashed_password == stored_hash

    def generate_verification_token(self):
        """Generate a unique verification token."""
        return str(uuid.uuid4())  # UUID for unique token generation
