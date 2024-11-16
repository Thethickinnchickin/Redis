from datetime import datetime, timedelta, timezone
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

    def __init__(self, username, password=None, password_hash=None, salt=None, email=None, verification_token=None, 
                 is_verified=False, reset_token=None, token_expiry=None, role='user'):
        self.username = username
        self.email = email  # Add email attribute
        self.verification_token = verification_token  # Store the verification token
        self.is_verified = is_verified  # Store verification status
        self.reset_token = reset_token
        self.token_expiry = token_expiry
        self.role = role
        
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
            "is_verified": self.is_verified,
            "reset_token": self.reset_token,
            "token_expiry": self.token_expiry,
            "role": self.role,
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

    def delete_from_db(self):
        """Delete the user from the MongoDB collection."""
        if self.mongo is None:
            raise ValueError("Mongo instance not set. Call User.set_mongo() in app.py.")
        
        # Use delete_one with the username or other unique identifier to remove the user
        result = self.mongo.db.users.delete_one({"username": self.username})
        if result.deleted_count == 0:
            raise ValueError(f"User with username {self.username} not found.")


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
            user.role = user_data["role"]
            return user
        return None
    
    @classmethod
    def find_by_email(cls, email):
        """Find a user by email."""
        if cls.mongo is None:
            raise ValueError("Mongo instance not set. Call User.set_mongo() in app.py.")
        
        user_data = cls.mongo.db.users.find_one({"email": email})
        if user_data:
            # Retrieve salt in bytes from hexadecimal
            salt = bytes.fromhex(user_data["salt"])
            # Create a User object with all necessary attributes
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                salt=salt,
                is_verified=user_data["is_verified"],
                verification_token=user_data.get("verification_token"),
                role=user_data.get("role")
            )
            user.password_hash = user_data["password_hash"]
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
            user.role = user_data["role"]
            return user
        return None
    
    @classmethod
    def find_by_role(cls, role):
        """Find users by their role."""
        if cls.mongo is None:
            raise ValueError("Mongo instance not set. Call User.set_mongo() in app.py.")
        
        # Query the MongoDB collection for users with the given role
        users_data = cls.mongo.db.users.find({"role": role})
        
        users = []
        for user_data in users_data:
            # Retrieve salt in bytes from hexadecimal
            salt = bytes.fromhex(user_data["salt"])
            # Create a User object with all necessary attributes
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                salt=salt,
                is_verified=user_data["is_verified"],
                verification_token=user_data.get("verification_token"),
                role=user_data.get("role", 'user')  # Default to 'admin' if role is not provided
            )
            user.password_hash = user_data["password_hash"]
            users.append(user)
        
        return users if users else None


    def check_password(self, password):
        """Check the password hash matches using scrypt."""
        stored_hash = bytes.fromhex(self.password_hash)
        # Compute the scrypt hash of the entered password and compare it with the stored hash
        hashed_password = hashlib.scrypt(password.encode(), salt=self.salt, n=16384, r=8, p=1)
        return hashed_password == stored_hash

    def generate_verification_token(self):
        """Generate a unique verification token."""
        return str(uuid.uuid4())  # UUID for unique token generation
    
    @classmethod
    def find_by_reset_token(cls, token):
        user_data = cls.mongo.db.users.find_one({'reset_token': token})
        if user_data:
            print(f"User data retrieved: {user_data}")  # Debug: Ensure 'role' exists
            user_data.pop('_id', None)
            return cls(
                username=user_data.get('username'),
                password_hash=user_data.get('password_hash'),
                salt=bytes.fromhex(user_data['salt']) if user_data.get('salt') else None,
                email=user_data.get('email'),
                verification_token=user_data.get('verification_token'),
                is_verified=user_data.get('is_verified', False),
                reset_token=user_data.get('reset_token'),
                token_expiry=user_data.get('token_expiry'),
                role=user_data.get('role', 'user')  # Default to 'user' if missing
            )
        return None



    def generate_reset_token(self):
        """Generate a reset token with a 1-hour expiration."""
        self.reset_token = str(uuid.uuid4())
        self.token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)

