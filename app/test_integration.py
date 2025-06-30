from . import app
import pytest
from app import mongo, User
from flask import session
import flask
from flask_pymongo import PyMongo
from pymongo.mongo_client import MongoClient



# MongoDB URI configuration
app.config['MONGO_URI'] = 'mongodb+srv://mattreileydeveloper:NewPassword@cluster0.ueh7b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'

# Initialize PyMongo
mongo = MongoClient('mongodb+srv://mattreileydeveloper:NewPassword@cluster0.ueh7b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

@pytest.fixture
def init_db():
    # Add a test user using MongoDB
    mongo.db.users.insert_one({
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123',
        'role': 'user'
    })
    
    yield mongo.db  # Yield the MongoDB database collection

    # Cleanup: Remove test user after the test
    mongo.db.users.delete_one({'username': 'testuser'})


def test_complete_registration_flow(client):
    # Step 1: Register user
    response = client.post('/register', data={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'newpassword123',
        'confirm_password': 'newpassword123'
    })
    assert response.status_code == 200
    assert b'Account created successfully' in response.data
    
    # Step 2: Check email verification (this would be handled via a mock email system in tests)
    user = mongo.db.users.find_one({'email': 'newuser@example.com'})
    assert user is not None
    assert user.get('email_verified', False) is False  # Assuming email verification logic exists

    # Step 3: Verify that user can login
    response = client.post('/login', data={
        'username': 'newuser',
        'password': 'newpassword123'
    })
    assert response.status_code == 200
    assert b'Login successful' in response.data
    assert session['username'] == 'newuser'

def test_complete_login_flow(client, init_db):
    # Step 1: Login user
    response = client.post('/login', data={'username': 'testuser', 'password': 'password123'})
    assert response.status_code == 200
    assert b'Login successful' in response.data
    
    # Step 2: Enter 2FA code (mock 2FA for testing)
    response = client.post('/two_factor', data={'code': '123456'})
    assert response.status_code == 200
    assert b'Login successful' in response.data
    assert session['username'] == 'testuser'

def test_role_based_access_flow(client, init_db):
    # Step 1: Login as regular user
    response = client.post('/login', data={'username': 'newuser', 'password': 'newpassword123'})
    assert response.status_code == 200
    assert b'Login successful' in response.data
    
    # Step 2: Try to access admin page (should be denied)
    response = client.get('/admin-dashboard', follow_redirects=True)
    assert response.status_code == 403
    assert b'Access denied' in response.data

    # Cleanup: Delete the test user from MongoDB
    mongo.db.users.delete_one({'username': 'newuser'})

    response = client.post('/login', data={'username': 'TestUser', 'password': 'password'})
    assert response.status_code == 200
    assert b'Login successful' in response.data

    # Step 4: Try to access admin page as admin (should be allowed)
    response = client.get('/admin-dashboard')
    assert response.status_code == 200
    assert b'Admin Dashboard' in response.data
