from locust import HttpUser, TaskSet, task, between
import random
import string
from bs4 import BeautifulSoup
from forms import DeleteUserForm, LoginForm, TwoFactorForm, RegisterForm, RequestPasswordResetForm, ResetPasswordForm
from wtforms import Form, StringField, PasswordField 
from . import app

def random_string(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

# Custom form without Flask context (using wtforms directly)
class LoginFormWithoutFlaskContext(Form):
    username = StringField('Username')
    password = PasswordField('Password')

class UserBehavior(HttpUser):
    wait_time = between(1, 5)
    
    @task(1)
    def logout(self):
        self.client.get("/")

    @task(2)
    def login(self):
        # Step 1: Get the login page to retrieve CSRF token
        response = self.client.get("/login")
        if response.status_code != 200:
            print("Failed to load login page")
            return

        # Step 2: Parse the HTML to extract the CSRF token
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

        # Step 3: Submit the login form with the CSRF token
        response = self.client.post("/login", data={
            "username": "TestUser",
            "password": "password",
            "csrf_token": csrf_token
        })

        # Check if redirect for 2FA is received
        if response.status_code == 302:
            self.two_factor()

    def two_factor(self):
        # Simulate entering the 2FA code
        # code = "123456"  # Replace with dynamic code if available
        # self.client.post("/two_factor", data={"code": code})
        print("Nice")

    # @task(3)
    # def register(self):
    #     username = random_string()
    #     email = f"{username}@example.com"
    #     password = "password123"
        
    #     self.client.get("/register")
    #     self.client.post("/register", data={
    #         "username": username,
    #         "email": email,
    #         "password": password,
    #         "confirm_password": password
    #     })

    @task(3)
    def logout(self):
        self.client.get("/logout")

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)  # Simulate wait time between requests
