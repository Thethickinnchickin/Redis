from app import create_app

app = create_app()

if __name__ == "__main__":
    print("Mongo instance in User model:", getattr(app, 'mongo', None))
    app.run(ssl_context='adhoc', debug=True)
